import os
import sys
import re
import csv
import io
import threading
import imaplib
import email
import email.utils
import requests
import fitz  # PyMuPDF — usado só para RENDERIZAR (desenhar) PDFs como imagem, nunca para executar nada
from PIL import Image
from datetime import datetime, timezone
from email.header import decode_header
from html.parser import HTMLParser
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import psycopg
import cofre

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ------------------------------------------------------------------
# Variáveis de ambiente (configure no painel do Render, em "Environment"):
#   EMAIL_USER            -> gatekeeper@ccat.com.br
#   EMAIL_PASS            -> a senha dessa caixa de e-mail (Locaweb)
#   WHITELIST_EMAILS      -> lista "de fábrica", separada por vírgula (opcional)
#   DATABASE_URL          -> mesma conexão Postgres/Supabase usada no outro serviço
#   DOMINIOS_INSTITUCIONAIS -> domínios protegidos contra falsificação, separados
#                              por vírgula. Ex: pf.gov.br,trt.jus.br,correios.com.br
# ------------------------------------------------------------------
IMAP_HOST = os.environ.get("IMAP_HOST", "email-ssl.com.br")
IMAP_PORT = int(os.environ.get("IMAP_PORT", "993"))
EMAIL_USER = os.environ.get("EMAIL_USER", "").strip()
EMAIL_PASS = os.environ.get("EMAIL_PASS", "").strip()
QUARANTINE_FOLDER = os.environ.get("QUARANTINE_FOLDER_NAME", "INBOX.Quarentena")

# Subpastas dentro da Quarentena, separando por nível de risco (o "joio do trigo"):
# - Geral: remetentes desconhecidos comuns (baixo risco, geralmente newsletter/contato novo)
# - Alerta Institucional: possível falsificação de banco/governo (alto risco, exige atenção)
# No formato padrão (Locaweb), subpastas usam "." como separador. Em provedores
# com outro separador (ex.: Gmail, que usa "/"), ajuste essas variáveis.
QUARENTENA_SUBPASTA_GERAL = os.environ.get(
    "QUARENTENA_SUBPASTA_GERAL", f"{QUARANTINE_FOLDER}.Geral"
)
QUARENTENA_SUBPASTA_INSTITUCIONAL = os.environ.get(
    "QUARENTENA_SUBPASTA_INSTITUCIONAL", f"{QUARANTINE_FOLDER}.Alerta-Institucional"
)

# Nome da pasta de "Enviados" — também varia por provedor, igual a Quarentena:
# Locaweb: "INBOX.enviadas" | Gmail: "[Gmail]/E-mails enviados" | Outlook: "Sent Items"
SENT_FOLDER = os.environ.get("SENT_FOLDER_NAME", "INBOX.enviadas")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

WHITELIST_FIXA = {
    e.strip().lower()
    for e in os.environ.get("WHITELIST_EMAILS", "").split(",")
    if e.strip()
}

DOMINIOS_INSTITUCIONAIS = {
    d.strip().lower()
    for d in os.environ.get(
        "DOMINIOS_INSTITUCIONAIS",
        "gov.br,jus.br,correios.com.br"
    ).split(",")
    if d.strip()
}

# URL do arquivo CSV oficial "Domínios GOV.BR", publicado mensalmente pela
# Secretaria de Governo Digital em dados.gov.br. Configure com o link direto
# de download do CSV (obtido na página do dataset, botão "Ir para recurso").
URL_LISTA_GOVBR = os.environ.get("URL_LISTA_GOVBR", "")


def atualizar_cache_dominios_govbr():
    """
    Baixa a lista oficial de domínios .gov.br (dados.gov.br) e substitui o
    conteúdo da tabela gatekeeper_dominios_govbr no banco de dados.
    Feito para ser chamado periodicamente (ex.: 1x por dia via cron-job.org),
    nunca a cada e-mail — por isso os resultados ficam em cache no banco.
    """
    if not URL_LISTA_GOVBR:
        return False, "URL_LISTA_GOVBR não configurada"
    if not DATABASE_URL:
        return False, "DATABASE_URL não configurado"

    try:
        resp = requests.get(URL_LISTA_GOVBR, timeout=30)
        resp.raise_for_status()
        texto = resp.content.decode("utf-8", errors="replace")
    except requests.RequestException as e:
        return False, f"Falha ao baixar a lista: {e}"

    leitor = csv.DictReader(io.StringIO(texto), delimiter=";")
    linhas = []
    for linha in leitor:
        dominio = (linha.get("dominio") or "").strip().lower()
        orgao = (linha.get("nome") or "").strip()
        if dominio:
            linhas.append((dominio, orgao))

    if not linhas:
        return False, "Nenhuma linha válida encontrada no CSV (verifique o formato/URL)"

    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute("TRUNCATE TABLE gatekeeper_dominios_govbr;")
                cur.executemany(
                    "INSERT INTO gatekeeper_dominios_govbr (dominio, orgao) VALUES (%s, %s) "
                    "ON CONFLICT (dominio) DO UPDATE SET orgao = EXCLUDED.orgao, atualizado_em = now();",
                    linhas,
                )
            conn.commit()
        return True, f"{len(linhas)} domínios atualizados com sucesso"
    except Exception as e:
        return False, f"Erro ao salvar no banco: {e}"


def consultar_dominio_na_lista_oficial(dominio: str):
    """Verifica se um domínio .gov.br está na lista oficial já baixada (cache no banco)."""
    if not DATABASE_URL:
        return {"consultado": False, "erro": "DATABASE_URL não configurado"}
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT orgao, atualizado_em FROM gatekeeper_dominios_govbr WHERE dominio = %s;",
                    (dominio,),
                )
                linha = cur.fetchone()
        if linha:
            return {"consultado": True, "encontrado": True, "orgao": linha[0], "lista_atualizada_em": str(linha[1])}
        return {"consultado": True, "encontrado": False}
    except Exception as e:
        return {"consultado": False, "erro": str(e)}


def dominio_do_email(endereco: str) -> str:
    return endereco.split("@")[-1].lower() if "@" in endereco else ""


def eh_dominio_institucional(endereco: str) -> bool:
    """Verifica se o remetente usa um domínio institucional protegido (ou subdomínio dele)."""
    dominio = dominio_do_email(endereco)
    return any(dominio == d or dominio.endswith("." + d) for d in DOMINIOS_INSTITUCIONAIS)


def consultar_idade_dominio(dominio: str) -> dict:
    """
    Consulta há quanto tempo o domínio existe, usando o protocolo RDAP:
    - Domínios .br: consulta direto no Registro.br (rdap.registro.br).
    - Qualquer outro domínio (.com, .net, etc.): usa o RDAP Bootstrap (rdap.org),
      que encaminha automaticamente para o registro correto no mundo todo.

    Retorna um aviso se o domínio foi registrado há pouco tempo — sinal comum
    de domínio criado especificamente para golpe (ex.: 'banco-seguro.com.br'
    criado ontem, imitando um banco de verdade).
    """
    resultado = {"consultado": False, "dias_desde_registro": None, "aviso": None, "erro": None}

    if dominio.endswith(".br"):
        url = f"https://rdap.registro.br/domain/{dominio}"
    else:
        url = f"https://rdap.org/domain/{dominio}"

    try:
        resp = requests.get(url, timeout=6, headers={"Accept": "application/rdap+json"})
        if resp.status_code != 200:
            resultado["erro"] = f"RDAP retornou status {resp.status_code} (domínio pode não existir ou estar indisponível)"
            return resultado

        dados = resp.json()
        data_registro = None
        for evento in dados.get("events", []):
            if evento.get("eventAction") in ("registration",):
                data_registro = evento.get("eventDate")
                break

        if not data_registro:
            resultado["erro"] = "Data de registro não encontrada na resposta do RDAP"
            return resultado

        data_registro_dt = datetime.fromisoformat(data_registro.replace("Z", "+00:00"))
        dias = (datetime.now(timezone.utc) - data_registro_dt).days

        resultado["consultado"] = True
        resultado["dias_desde_registro"] = dias
        if dias < 90:
            resultado["aviso"] = f"Domínio registrado há apenas {dias} dias — sinal de alerta para um domínio institucional."

        return resultado

    except requests.RequestException as e:
        resultado["erro"] = f"Falha ao consultar RDAP: {e}"
        return resultado
    except Exception as e:
        resultado["erro"] = f"Erro ao interpretar resposta do RDAP: {e}"
        return resultado


def checar_autenticacao(msg) -> dict:
    """
    Lê o cabeçalho 'Authentication-Results', que o próprio servidor de e-mail já
    preenche com o resultado das checagens de SPF, DKIM e DMARC. Não refazemos
    essa verificação criptográfica do zero — confiamos no resultado já calculado
    pelo servidor que recebeu a mensagem, que é a prática padrão do mercado.
    """
    resultado = {"spf": "nao_verificado", "dkim": "nao_verificado", "dmarc": "nao_verificado", "cabecalho_bruto": None}
    cabecalhos = msg.get_all("Authentication-Results") or []
    if not cabecalhos:
        return resultado

    texto_completo = " ".join(cabecalhos)
    resultado["cabecalho_bruto"] = texto_completo

    m = re.search(r"spf=(\w+)", texto_completo, re.IGNORECASE)
    if m:
        resultado["spf"] = m.group(1).lower()
    m = re.search(r"dkim=(\w+)", texto_completo, re.IGNORECASE)
    if m:
        resultado["dkim"] = m.group(1).lower()
    m = re.search(r"dmarc=(\w+)", texto_completo, re.IGNORECASE)
    if m:
        resultado["dmarc"] = m.group(1).lower()

    return resultado


def classificar_autenticacao(auth: dict) -> str:
    """
    Classifica o resultado da checagem de SPF/DKIM/DMARC em três estados,
    em vez de só 'passou ou não' — a distinção importa muito na prática:

    - 'passou': pelo menos um protocolo confirmou 'pass', e nenhum falhou.
    - 'falhou': algum protocolo teve 'fail' explícito — sinal real de alerta.
    - 'sem_dados': o servidor de e-mail não registrou essa informação (comum
      em provedores como a Locaweb, diferente do Gmail). Isso NÃO é prova de
      falsificação — é só ausência de como confirmar. Deve ser tratado com
      cautela (quarentena), mas sem apagar o e-mail original, já que não há
      evidência real de fraude.
    """
    valores = [auth["spf"], auth["dkim"], auth["dmarc"]]
    if any(v == "fail" for v in valores):
        return "falhou"
    if all(v == "nao_verificado" for v in valores):
        return "sem_dados"
    if any(v == "pass" for v in valores):
        return "passou"
    return "sem_dados"


def autenticacao_passou(auth: dict) -> bool:
    """Mantido por compatibilidade — usa a nova classificação por trás dos panos."""
    return classificar_autenticacao(auth) == "passou"


def carregar_whitelist():
    """Combina a lista fixa (variável de ambiente) com a lista salva no banco (aprovações)."""
    whitelist = set(WHITELIST_FIXA)
    if not DATABASE_URL:
        return whitelist
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT email FROM gatekeeper_whitelist;")
                for (e,) in cur.fetchall():
                    whitelist.add(e.strip().lower())
    except Exception as e:
        print(f"Aviso: não foi possível carregar a whitelist do banco: {e}", file=sys.stderr, flush=True)
    return whitelist


def obter_estado(chave: str):
    """Lê um valor guardado (ex.: 'último UID processado'). Retorna None se não existir ou faltar banco."""
    if not DATABASE_URL:
        return None
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT valor FROM gatekeeper_estado WHERE chave = %s;", (chave,))
                linha = cur.fetchone()
                return linha[0] if linha else None
    except Exception as e:
        print(f"Aviso: não foi possível ler estado ({chave}): {e}", file=sys.stderr, flush=True)
        return None


def salvar_estado(chave: str, valor: str):
    """Guarda um valor (ex.: 'último UID processado') para ser lembrado na próxima execução."""
    if not DATABASE_URL:
        return
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO gatekeeper_estado (chave, valor, atualizado_em)
                    VALUES (%s, %s, now())
                    ON CONFLICT (chave) DO UPDATE SET valor = EXCLUDED.valor, atualizado_em = now();
                    """,
                    (chave, valor),
                )
            conn.commit()
    except Exception as e:
        print(f"Aviso: não foi possível salvar estado ({chave}): {e}", file=sys.stderr, flush=True)


def aprovar_remetentes_em_lote(lista_emails: list):
    """
    Aprova vários remetentes de uma vez, usando UMA SÓ conexão com o banco
    de dados (em vez de abrir uma conexão nova para cada e-mail, o que seria
    lento e arriscado de causar timeout em listas grandes).
    Retorna (lista_aprovados, lista_falhas).
    """
    if not DATABASE_URL:
        return [], [{"email": e, "erro": "DATABASE_URL não configurado"} for e in lista_emails]

    aprovados = []
    falharam = []
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                for endereco in lista_emails:
                    try:
                        with conn.transaction():  # savepoint: isola o erro deste item sem abortar a conexão inteira
                            cur.execute(
                                "INSERT INTO gatekeeper_whitelist (email, conta_email) VALUES (%s, %s) "
                                "ON CONFLICT (email, conta_email) DO NOTHING;",
                                (endereco.strip().lower(), EMAIL_USER.strip().lower()),
                            )
                        aprovados.append(endereco)
                    except Exception as e:
                        falharam.append({"email": endereco, "erro": str(e)})
            conn.commit()
    except Exception as e:
        # Se nem a conexão em si funcionar, todos os pendentes falham juntos.
        print(f"Erro ao aprovar em lote: {e}", file=sys.stderr, flush=True)
        return [], [{"email": e_addr, "erro": str(e)} for e_addr in lista_emails]

    return aprovados, falharam


def aprovar_remetente(email_addr: str):
    """Adiciona um e-mail permanentemente à Lista Branca (tabela gatekeeper_whitelist)."""
    if not DATABASE_URL:
        return False, "DATABASE_URL não configurado"
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO gatekeeper_whitelist (email, conta_email) VALUES (%s, %s) "
                    "ON CONFLICT (email, conta_email) DO NOTHING;",
                    (email_addr.strip().lower(), EMAIL_USER.strip().lower()),
                )
            conn.commit()
        return True, None
    except Exception as e:
        print(f"Erro ao aprovar remetente: {e}", file=sys.stderr, flush=True)
        return False, str(e)


def carregar_blacklist():
    """Carrega o conjunto de remetentes bloqueados permanentemente (tabela gatekeeper_blacklist)."""
    blacklist = set()
    if not DATABASE_URL:
        return blacklist
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT email FROM gatekeeper_blacklist WHERE conta_email = %s;",
                    (EMAIL_USER.strip().lower(),),
                )
                for (e,) in cur.fetchall():
                    blacklist.add(e.strip().lower())
    except Exception as e:
        print(f"Aviso: não foi possível carregar a blacklist do banco: {e}", file=sys.stderr, flush=True)
    return blacklist


def remover_e_bloquear_remetente(email_addr: str):
    """
    Ação discricionária e definitiva do usuário: remove o remetente da Lista Branca
    (se estiver lá) e o adiciona à Lista Negra (gatekeeper_blacklist). A partir daí,
    e-mails desse remetente são apagados direto na origem em /organize, antes mesmo
    da checagem institucional — nunca mais passam pela Quarentena para revisão.
    """
    if not DATABASE_URL:
        return False, "DATABASE_URL não configurado"
    email_norm = email_addr.strip().lower()
    conta_norm = EMAIL_USER.strip().lower()
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM gatekeeper_whitelist WHERE email = %s AND conta_email = %s;",
                    (email_norm, conta_norm),
                )
                cur.execute(
                    "INSERT INTO gatekeeper_blacklist (email, conta_email) VALUES (%s, %s) "
                    "ON CONFLICT (email, conta_email) DO NOTHING;",
                    (email_norm, conta_norm),
                )
            conn.commit()
        return True, None
    except Exception as e:
        print(f"Erro ao remover/bloquear remetente: {e}", file=sys.stderr, flush=True)
        return False, str(e)


def carregar_blacklist_nomes():
    """Carrega o conjunto de nomes de exibição bloqueados (tabela gatekeeper_blacklist_nomes)."""
    nomes = set()
    if not DATABASE_URL:
        return nomes
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT nome FROM gatekeeper_blacklist_nomes WHERE conta_email = %s;",
                    (EMAIL_USER.strip().lower(),),
                )
                for (n,) in cur.fetchall():
                    nomes.add(n.strip().lower())
    except Exception as e:
        print(f"Aviso: não foi possível carregar a blacklist de nomes: {e}", file=sys.stderr, flush=True)
    return nomes


def bloquear_nome_remetente(nome: str):
    """
    Bloqueia um NOME DE EXIBIÇÃO (não o e-mail) permanentemente. Útil quando um
    golpista varia o endereço de e-mail mas mantém o mesmo nome ('Suporte Banco X'),
    ou quando o mesmo nome aparece em múltiplos domínios forjados diferentes.
    """
    if not DATABASE_URL:
        return False, "DATABASE_URL não configurado"
    nome_norm = nome.strip().lower()
    if not nome_norm:
        return False, "Nome vazio"
    conta_norm = EMAIL_USER.strip().lower()
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO gatekeeper_blacklist_nomes (nome, conta_email) VALUES (%s, %s) "
                    "ON CONFLICT (nome, conta_email) DO NOTHING;",
                    (nome_norm, conta_norm),
                )
            conn.commit()
        return True, None
    except Exception as e:
        print(f"Erro ao bloquear nome de remetente: {e}", file=sys.stderr, flush=True)
        return False, str(e)


@app.route("/whitelist/remover-e-bloquear", methods=["GET"])
def whitelist_remover_e_bloquear():
    """
    Ação discricionária do usuário: remove um remetente da Lista Branca e o bloqueia
    permanentemente (Lista Negra). Diferente da Quarentena (que é reversível e aguarda
    revisão), esta é uma decisão definitiva — e-mails futuros desse remetente são
    apagados direto na origem em /organize, sem passar por revisão nenhuma.

    Por segurança, roda em modo SIMULAÇÃO por padrão. Use ?confirmar=sim para executar.
    """
    email_addr = (request.args.get("email") or "").strip().lower()
    if not email_addr:
        return jsonify({"ok": False, "error": "Parâmetro 'email' é obrigatório"}), 400

    modo_real = request.args.get("confirmar", "").lower() == "sim"
    if not modo_real:
        return jsonify({
            "ok": True,
            "modo": "SIMULAÇÃO — nada foi alterado",
            "seria_removido_da_lista_branca": email_addr,
            "seria_bloqueado_permanentemente": email_addr,
        })

    sucesso, erro = remover_e_bloquear_remetente(email_addr)
    if not sucesso:
        return jsonify({"ok": False, "error": erro}), 500

    return jsonify({
        "ok": True,
        "modo": "REAL — removido e bloqueado de verdade",
        "email": email_addr,
        "aviso": "Este remetente não entra mais na Caixa de Entrada nem na Quarentena — e-mails dele serão apagados direto no próximo /organize.",
    })


@app.route("/whitelist/bloquear-nome", methods=["GET"])
def whitelist_bloquear_nome():
    """
    Bloqueia um NOME DE EXIBIÇÃO (ex.: 'Suporte Banco X'), não um e-mail específico.
    Útil contra golpistas que trocam o endereço mas mantêm o mesmo nome forjado.
    Por segurança, roda em modo SIMULAÇÃO por padrão. Use ?confirmar=sim para executar.
    """
    nome = (request.args.get("nome") or "").strip()
    if not nome:
        return jsonify({"ok": False, "error": "Parâmetro 'nome' é obrigatório"}), 400

    modo_real = request.args.get("confirmar", "").lower() == "sim"
    if not modo_real:
        return jsonify({
            "ok": True,
            "modo": "SIMULAÇÃO — nada foi alterado",
            "seria_bloqueado_permanentemente": nome,
        })

    sucesso, erro = bloquear_nome_remetente(nome)
    if not sucesso:
        return jsonify({"ok": False, "error": erro}), 500

    return jsonify({
        "ok": True,
        "modo": "REAL — nome bloqueado de verdade",
        "nome": nome,
        "aviso": "Qualquer e-mail com este nome de exibição será apagado direto no próximo /organize, não importa o endereço usado.",
    })


def carregar_blacklist_dominios():
    """Carrega o conjunto de domínios bloqueados INTEIROS (tabela gatekeeper_blacklist_dominios)."""
    dominios = set()
    if not DATABASE_URL:
        return dominios
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT dominio FROM gatekeeper_blacklist_dominios WHERE conta_email = %s;",
                    (EMAIL_USER.strip().lower(),),
                )
                for (d,) in cur.fetchall():
                    dominios.add(d.strip().lower())
    except Exception as e:
        print(f"Aviso: não foi possível carregar a blacklist de domínios: {e}", file=sys.stderr, flush=True)
    return dominios


def bloquear_dominio_remetente(dominio: str):
    """
    Bloqueia um DOMÍNIO INTEIRO (a 'raiz', ex.: 'empresa-chata.com.br') permanentemente.
    Diferente do bloqueio por e-mail (só aquele endereço específico), isso derruba
    TODOS os remetentes daquele domínio de uma vez — use com cautela, já que também
    bloqueia endereços legítimos do mesmo domínio que você ainda não conhece.
    """
    if not DATABASE_URL:
        return False, "DATABASE_URL não configurado"
    dominio_norm = dominio.strip().lower().lstrip("@")
    if not dominio_norm or "." not in dominio_norm:
        return False, "Domínio inválido"
    conta_norm = EMAIL_USER.strip().lower()
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO gatekeeper_blacklist_dominios (dominio, conta_email) VALUES (%s, %s) "
                    "ON CONFLICT (dominio, conta_email) DO NOTHING;",
                    (dominio_norm, conta_norm),
                )
            conn.commit()
        return True, None
    except Exception as e:
        print(f"Erro ao bloquear domínio: {e}", file=sys.stderr, flush=True)
        return False, str(e)


@app.route("/whitelist/bloquear-dominio", methods=["GET"])
def whitelist_bloquear_dominio():
    """
    Bloqueia um DOMÍNIO INTEIRO (ex.: 'empresa-chata.com.br'), derrubando todos os
    remetentes desse domínio de uma vez — inclusive endereços ainda desconhecidos.
    Por segurança, roda em modo SIMULAÇÃO por padrão. Use ?confirmar=sim para executar.
    """
    dominio = (request.args.get("dominio") or "").strip()
    if not dominio:
        return jsonify({"ok": False, "error": "Parâmetro 'dominio' é obrigatório"}), 400

    modo_real = request.args.get("confirmar", "").lower() == "sim"
    if not modo_real:
        return jsonify({
            "ok": True,
            "modo": "SIMULAÇÃO — nada foi alterado",
            "seria_bloqueado_permanentemente": dominio,
        })

    sucesso, erro = bloquear_dominio_remetente(dominio)
    if not sucesso:
        return jsonify({"ok": False, "error": erro}), 500

    return jsonify({
        "ok": True,
        "modo": "REAL — domínio bloqueado de verdade",
        "dominio": dominio,
        "aviso": "Qualquer e-mail de qualquer endereço deste domínio será apagado direto no próximo /organize.",
    })


def registrar_envio_para_quarentena(message_id: str, remetente: str, assunto: str):
    """
    Guarda a 'identidade' (Message-ID) de um e-mail no momento em que ele é
    movido para a Quarentena. Isso permite, mais tarde, perceber se o próprio
    usuário moveu esse e-mail de volta para a Caixa de Entrada manualmente
    (ex.: arrastando no Outlook) — o que é interpretado como uma aprovação.

    IMPORTANTE: o registro é feito por CONTA (EMAIL_USER) — e-mails de
    newsletter costumam ter o mesmo Message-ID para todos os destinatários,
    então sem essa separação, o histórico de uma conta poderia 'colidir'
    com o de outra conta diferente.
    """
    if not DATABASE_URL or not message_id:
        return
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO gatekeeper_historico_quarentena (message_id, conta_email, remetente, assunto)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (message_id, conta_email) DO NOTHING;
                    """,
                    (message_id, EMAIL_USER.strip().lower(), remetente.strip().lower(), assunto),
                )
            conn.commit()
    except Exception as e:
        print(f"Aviso: não foi possível registrar histórico de quarentena: {e}", file=sys.stderr, flush=True)


def detectar_aprovacoes_por_movimento(imap, limite_pendentes: int = 15) -> list:
    """
    Verifica se algum e-mail que estava na Quarentena voltou, sozinho, para a
    Caixa de Entrada (ex.: o usuário arrastou manualmente no Outlook/Gmail).
    Se sim, aprova o remetente automaticamente e marca o histórico como resolvido.
    Retorna a lista de aprovações feitas por esse caminho.

    IMPORTANTE: só olha o histórico DESTA conta (EMAIL_USER) — nunca o de
    outras contas que compartilhem o mesmo banco de dados.

    Por segurança de desempenho, só confere um número limitado de pendências
    por execução (padrão: 15) — sem isso, o tempo desta função cresceria sem
    limite conforme o histórico de pendências acumula, arriscando estourar o
    tempo-limite de agendadores externos (como o cron-job.org, com teto de
    30 segundos no plano gratuito). O que sobrar é conferido na próxima execução.

    PRÉ-REQUISITO: quem chama esta função precisa já ter selecionado a pasta
    INBOX no objeto 'imap' (com o modo de acesso correto) ANTES de chamar.
    """
    if not DATABASE_URL:
        return []

    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT message_id, remetente, assunto FROM gatekeeper_historico_quarentena "
                    "WHERE resolvido = false AND conta_email = %s "
                    "ORDER BY movido_para_quarentena_em DESC LIMIT %s;",
                    (EMAIL_USER.strip().lower(), limite_pendentes),
                )
                pendentes = cur.fetchall()
    except Exception as e:
        print(f"Aviso: não foi possível ler histórico de quarentena: {e}", file=sys.stderr, flush=True)
        return []

    if not pendentes:
        return []

    # OTIMIZAÇÃO: em vez de listar TODA a Caixa de Entrada e comparar (o que
    # seria lento em caixas com milhares de e-mails), pedimos ao próprio
    # servidor para procurar, um a um, só os Message-IDs específicos que
    # estão pendentes — o servidor já sabe fazer essa busca com eficiência.
    aprovados_agora = []
    for message_id, remetente, assunto in pendentes:
        if not message_id:
            continue
        # Escapa aspas e barras invertidas, exigido pela sintaxe de string
        # entre aspas do protocolo IMAP — evita que um Message-ID com
        # caracteres incomuns 'quebre' a busca de forma imprevisível.
        message_id_seguro = message_id.replace("\\", "\\\\").replace('"', '\\"')
        criterio = f'HEADER "Message-ID" "{message_id_seguro}"'
        status, data = imap.uid("search", None, criterio)
        uids_encontrados = data[0].split() if (status == "OK" and data and data[0]) else []

        if not uids_encontrados:
            continue

        # TRAVA DE SEGURANÇA EXTRA: antes de aprovar qualquer coisa, confirma
        # de verdade que o remetente do e-mail encontrado bate exatamente com
        # o esperado — isso impede uma aprovação indevida mesmo que a busca
        # do servidor, por algum motivo, encontre algo que não devia.
        uid_encontrado = uids_encontrados[0]
        status_fetch, msg_data = imap.uid("fetch", uid_encontrado, "(BODY.PEEK[HEADER.FIELDS (FROM)])")
        remetente_confere = False
        if status_fetch == "OK" and msg_data and msg_data[0]:
            raw_from = msg_data[0][1].decode("utf-8", errors="replace")
            parsed_from = email.message_from_string(raw_from)
            _, endereco_encontrado = email.utils.parseaddr(parsed_from.get("From", ""))
            remetente_confere = endereco_encontrado.strip().lower() == remetente.strip().lower()

        if not remetente_confere:
            print(
                f"Aviso: aprovação por movimento BLOQUEADA — remetente não confere para message_id={message_id!r} "
                f"(esperado: {remetente}).",
                file=sys.stderr, flush=True,
            )
            continue

        ok, _ = aprovar_remetente(remetente)
        if ok:
            try:
                with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE gatekeeper_historico_quarentena SET resolvido = true "
                            "WHERE message_id = %s AND conta_email = %s;",
                            (message_id, EMAIL_USER.strip().lower()),
                        )
                    conn.commit()
            except Exception as e:
                print(f"Aviso: falha ao marcar histórico como resolvido: {e}", file=sys.stderr, flush=True)
            aprovados_agora.append({"de": remetente, "assunto": assunto, "motivo": "movido de volta para a Caixa de Entrada pelo usuário"})

    return aprovados_agora


def decode_str(value):
    """Decodifica cabeçalhos de e-mail que podem vir com acentuação especial."""
    if value is None:
        return ""
    parts = decode_header(value)
    result = ""
    for text, enc in parts:
        if isinstance(text, bytes):
            result += text.decode(enc or "utf-8", errors="replace")
        else:
            result += text
    return result


def _bytes_seguro(valor) -> bytes:
    """
    Converte qualquer valor vindo de uma resposta IMAP para bytes, de forma
    segura — alguns servidores de e-mail, para mensagens antigas ou com
    formato incomum, podem devolver a resposta em um formato ligeiramente
    diferente do esperado (ex.: um número em vez de texto). Em vez de travar
    a execução inteira por causa de um único e-mail malformado, convertemos
    com segurança, tratando esse caso como 'sem conteúdo' se necessário.
    """
    if valor is None:
        return b""
    if isinstance(valor, bytes):
        return valor
    if isinstance(valor, str):
        return valor.encode("utf-8", errors="replace")
    # Qualquer outro tipo inesperado (ex.: int) — não é um e-mail de verdade,
    # tratamos como vazio em vez de travar.
    return b""


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "gatekeeper-mail-engine"})


@app.route("/test-connection", methods=["GET"])
def test_connection():
    """
    Teste somente-leitura: conecta na caixa de e-mail e lista os remetentes
    e assuntos das últimas mensagens. NÃO apaga, NÃO move e NÃO altera nada.
    """
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=20)
        imap.login(EMAIL_USER, EMAIL_PASS)
        imap.select("INBOX", readonly=True)  # readonly=True: impossível alterar a caixa nesta etapa

        status, data = imap.search(None, "ALL")
        if status != "OK":
            return jsonify({"ok": False, "error": "Não foi possível listar as mensagens"}), 500

        all_ids = data[0].split()
        last_ids = all_ids[-10:] if len(all_ids) > 10 else all_ids

        mensagens = []
        for msg_id in reversed(last_ids):
            status, msg_data = imap.fetch(msg_id, "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])")
            if status != "OK" or not msg_data or not msg_data[0]:
                continue
            raw_header = msg_data[0][1].decode("utf-8", errors="replace")
            parsed = email.message_from_string(raw_header)
            mensagens.append({
                "de": decode_str(parsed.get("From")),
                "assunto": decode_str(parsed.get("Subject")),
                "data": parsed.get("Date"),
            })

        return jsonify({
            "ok": True,
            "total_de_emails_na_caixa": len(all_ids),
            "ultimas_mensagens": mensagens,
        })

    except imaplib.IMAP4.error as e:
        print(f"Erro de login/IMAP: {e}", file=sys.stderr, flush=True)
        return jsonify({"ok": False, "error": f"Erro de conexão/login IMAP: {e}"}), 500
    except Exception as e:
        print(f"Erro inesperado: {e}", file=sys.stderr, flush=True)
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


@app.route("/list-folders", methods=["GET"])
def list_folders():
    """Rota de diagnóstico, somente leitura: mostra como o servidor nomeia as pastas."""
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=20)
        imap.login(EMAIL_USER, EMAIL_PASS)
        status, pastas = imap.list()
        pastas_legiveis = [p.decode("utf-8", errors="replace") for p in pastas] if status == "OK" else []
        return jsonify({"ok": True, "status": status, "pastas_no_servidor": pastas_legiveis})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


@app.route("/atualizar-lista-govbr", methods=["GET"])
def atualizar_lista_govbr_rota():
    """
    Atualiza o cache local da lista oficial de domínios .gov.br.
    Deve ser chamada periodicamente (ex.: 1x por dia via cron-job.org),
    nunca a cada e-mail recebido.
    """
    ok, mensagem = atualizar_cache_dominios_govbr()
    return jsonify({"ok": ok, "mensagem": mensagem})


@app.route("/diagnostico-ultima-mensagem", methods=["GET"])
def diagnostico_ultima_mensagem():
    """
    Rota de diagnóstico: mostra a data da mensagem mais recente numa pasta
    específica — ajuda a saber se uma pasta ainda está 'ativa' (recebendo
    mensagens novas) ou se é uma pasta antiga, parada no tempo.
    Uso: /diagnostico-ultima-mensagem?pasta=INBOX.Enviadas
    """
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    pasta = request.args.get("pasta", "").strip()
    if not pasta:
        return jsonify({"ok": False, "error": "Informe a pasta em ?pasta="}), 400

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=20)
        imap.login(EMAIL_USER, EMAIL_PASS)
        status, resp = imap.select(pasta, readonly=True)
        if status != "OK":
            return jsonify({"ok": False, "error": f"Não foi possível abrir a pasta '{pasta}'"}), 404

        total_mensagens = int(resp[0])
        status, data = imap.uid("search", None, "ALL")
        uids = data[0].split() if status == "OK" else []

        if not uids:
            return jsonify({"ok": True, "pasta": pasta, "total_mensagens": total_mensagens, "ultima_mensagem": None})

        ultimo_uid = uids[-1]
        status, msg_data = imap.uid("fetch", ultimo_uid, "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])")
        raw_header = msg_data[0][1].decode("utf-8", errors="replace")
        parsed = email.message_from_string(raw_header)

        return jsonify({
            "ok": True,
            "pasta": pasta,
            "total_mensagens": total_mensagens,
            "ultima_mensagem": {
                "data": parsed.get("Date"),
                "de": parsed.get("From"),
                "assunto": decode_str(parsed.get("Subject")),
            },
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


@app.route("/diagnostico-enviados-todos", methods=["GET"])
def diagnostico_enviados_todos():
    """
    Rota de diagnóstico: verifica quantas mensagens existem em VÁRIAS pastas
    candidatas a 'Enviados' de uma vez — útil quando a caixa tem várias
    pastas parecidas (comum em contas antigas, com anos de uso).
    """
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    candidatas = [
        "INBOX.Sent", "INBOX.enviadas", "INBOX.Enviadas",
        "INBOX.Itens Enviados", "INBOX.Sent Items", "INBOX.Sent Messages",
    ]

    imap = None
    resultado = {}
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=20)
        imap.login(EMAIL_USER, EMAIL_PASS)
        for pasta in candidatas:
            try:
                status, resp = imap.select(pasta, readonly=True)
                resultado[pasta] = resp[0].decode() if status == "OK" else f"erro ({status})"
            except Exception as e:
                resultado[pasta] = f"erro: {e}"
        return jsonify({"ok": True, "quantidade_de_mensagens_por_pasta": resultado})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


@app.route("/diagnostico-enviados", methods=["GET"])
def diagnostico_enviados():
    """Rota de diagnóstico: mostra quantas mensagens o servidor vê na pasta de Enviados configurada."""
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=20)
        imap.login(EMAIL_USER, EMAIL_PASS)
        status, resposta_select = imap.select(SENT_FOLDER, readonly=True)
        return jsonify({
            "ok": True,
            "pasta_configurada": SENT_FOLDER,
            "status_ao_abrir_pasta": status,
            "quantidade_de_mensagens_segundo_o_servidor": resposta_select[0].decode() if status == "OK" else None,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


@app.route("/diagnostico-pastas", methods=["GET"])
def diagnostico_pastas():
    """
    Rota de diagnóstico, somente leitura: compara TODAS as pastas que existem
    no servidor com as que estão efetivamente "inscritas" (subscribed) — é a
    inscrição que faz uma pasta aparecer na lista do webmail/app de e-mail.
    """
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=20)
        imap.login(EMAIL_USER, EMAIL_PASS)

        status_todas, todas = imap.list()
        status_inscritas, inscritas = imap.lsub()

        todas_legivel = [p.decode("utf-8", errors="replace") for p in todas] if status_todas == "OK" else []
        inscritas_legivel = [p.decode("utf-8", errors="replace") for p in inscritas] if status_inscritas == "OK" else []

        quarentena_existe = any("Quarentena" in p for p in todas_legivel)
        quarentena_inscrita = any("Quarentena" in p for p in inscritas_legivel)

        return jsonify({
            "ok": True,
            "quarentena_existe_no_servidor": quarentena_existe,
            "quarentena_esta_inscrita": quarentena_inscrita,
            "diagnostico": (
                "Tudo certo — deveria aparecer no webmail." if quarentena_inscrita
                else "A pasta existe mas NÃO está inscrita — por isso não aparece no webmail."
            ),
            "todas_as_pastas": todas_legivel,
            "pastas_inscritas": inscritas_legivel,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


@app.route("/diagnostico-credenciais", methods=["GET"])
def diagnostico_credenciais():
    """
    Rota de diagnóstico: mostra características das credenciais configuradas
    (tamanho, espaços escondidos, etc.) SEM nunca revelar a senha em si.
    Ajuda a identificar problemas de 'copiar e colar' na variável EMAIL_PASS.
    """
    tem_espaco_inicio_fim = EMAIL_PASS != EMAIL_PASS.strip()
    tem_espaco_no_meio = " " in EMAIL_PASS.strip()
    tem_quebra_de_linha = "\n" in EMAIL_PASS or "\r" in EMAIL_PASS

    return jsonify({
        "email_user_configurado": EMAIL_USER,
        "email_user_tamanho": len(EMAIL_USER),
        "email_pass_tamanho": len(EMAIL_PASS),
        "email_pass_tem_espaco_no_inicio_ou_fim": tem_espaco_inicio_fim,
        "email_pass_tem_espaco_no_meio": tem_espaco_no_meio,
        "email_pass_tem_quebra_de_linha_escondida": tem_quebra_de_linha,
        "imap_host_configurado": IMAP_HOST,
        "imap_port_configurado": IMAP_PORT,
        "dica": "Uma senha de app do Google, sem espaços, deve ter exatamente 16 caracteres.",
    })


@app.route("/verificar-dominio", methods=["GET"])
def verificar_dominio():
    """
    Rota de teste isolada: consulta há quanto tempo um domínio existe.
    Uso: /verificar-dominio?dominio=itau.com.br
    """
    dominio = request.args.get("dominio", "").strip().lower()
    if not dominio:
        return jsonify({"ok": False, "error": "Informe um domínio em ?dominio="}), 400
    info = consultar_idade_dominio(dominio)
    return jsonify({"ok": True, "dominio": dominio, **info})


@app.route("/organize-async", methods=["GET"])
def organize_async():
    """
    Dispara o /organize em SEGUNDO PLANO, sem esperar o processamento
    terminar — pensado especificamente para agendadores externos com
    tempo-limite curto (ex.: cron-job.org, plano gratuito, teto de 30s).

    Responde imediatamente ('processamento iniciado'), enquanto o
    processamento de verdade continua rodando no servidor. Para conferir
    o resultado depois, use /organize-visual ou os relatórios.

    Aceita os mesmos parâmetros do /organize (confirmar, limite, etc.) —
    eles são repassados por baixo dos panos.
    """
    query_string = request.query_string.decode()
    url_interna = request.url_root.rstrip("/") + "/organize"
    if query_string:
        url_interna += "?" + query_string

    def _disparar_em_segundo_plano():
        try:
            requests.get(url_interna, timeout=300)
        except Exception as e:
            print(f"Aviso: processamento em segundo plano terminou com erro: {e}", file=sys.stderr, flush=True)

    thread = threading.Thread(target=_disparar_em_segundo_plano, daemon=True)
    thread.start()

    return jsonify({
        "ok": True,
        "mensagem": "Processamento iniciado em segundo plano — não espere esta resposta para saber o resultado.",
        "dica": "Confira o resultado depois em /organize-visual ou nos relatórios.",
    })


@app.route("/organize-visual", methods=["GET"])
def organize_visual():
    """
    Mesma lógica do /organize, mas mostra o resultado como uma página visual,
    organizada em seções — bem mais fácil de acompanhar com os olhos do que
    um bloco só de texto (JSON).
    """
    resposta_organize = organize()
    if isinstance(resposta_organize, tuple):
        corpo, status = resposta_organize
        dados = corpo.get_json()
    else:
        dados = resposta_organize.get_json()

    if not dados.get("ok"):
        return f"<h1 style='font-family:sans-serif;color:#b00'>Erro</h1><p style='font-family:sans-serif'>{dados.get('error', 'Erro desconhecido')}</p>"

    def linha(item, extra=""):
        assunto = (item.get("assunto") or "(sem assunto)")[:90]
        return f"<tr><td style='padding:6px 10px;border-bottom:1px solid #333'>{item.get('de','')}</td><td style='padding:6px 10px;border-bottom:1px solid #333'>{assunto}</td><td style='padding:6px 10px;border-bottom:1px solid #333;color:#999'>{extra}</td></tr>"

    def tabela(titulo, itens, cor, vazio_msg):
        if not itens:
            return f"<h2 style='color:{cor};font-family:sans-serif;margin-top:30px'>{titulo} (0)</h2><p style='font-family:sans-serif;color:#888'>{vazio_msg}</p>"
        linhas = "".join(linha(i) for i in itens)
        return f"""
        <h2 style='color:{cor};font-family:sans-serif;margin-top:30px'>{titulo} ({len(itens)})</h2>
        <table style='width:100%;border-collapse:collapse;font-family:sans-serif;font-size:14px'>
        <tr style='text-align:left;color:#aaa'><th style='padding:6px 10px'>De</th><th style='padding:6px 10px'>Assunto</th><th></th></tr>
        {linhas}
        </table>
        """

    html = f"""
    <html><head><meta charset="utf-8"><title>Resultado do /organize</title></head>
    <body style='background:#111;color:#eee;padding:30px;max-width:900px;margin:0 auto'>
    <h1 style='font-family:sans-serif'>Resultado desta execução</h1>
    <p style='font-family:sans-serif;color:#aaa'>
        Modo: <b>{dados.get('modo')}</b> |
        Processamento: {dados.get('processamento')} |
        Analisadas agora: {dados.get('mensagens_analisadas_nesta_execucao')} |
        Restam: {dados.get('restam_para_processar', 0)}
    </p>
    {tabela("✅ Mantidos na Caixa de Entrada (já confiáveis)", dados.get("mantidos_na_caixa_de_entrada", []), "#4caf50", "Nenhum e-mail confiável neste lote.")}
    {tabela("📥 Movidos para Quarentena (desconhecidos)", dados.get("movidos_para_quarentena", []), "#ffa726", "Nenhum e-mail desconhecido neste lote.")}
    {tabela("🚨 Alertas de possível falsificação institucional", dados.get("alertas_de_possivel_falsificacao_institucional", []), "#e53935", "Nenhum alerta institucional neste lote.")}
    {tabela("↩️ Aprovados por movimento (você moveu de volta)", dados.get("aprovados_por_movimento", []), "#42a5f5", "Nenhuma aprovação por movimento neste lote — isso é o esperado, a não ser que você tenha movido algo manualmente.")}
    </body></html>
    """
    return html


@app.route("/multi/organizar-todas", methods=["GET"])
def organizar_todas_as_contas():
    """
    Roda o /organize para CADA conta cadastrada na tabela gatekeeper_contas,
    buscando a senha protegida do cofre (Doppler + Supabase Vault) para cada
    uma. Esse é o primeiro passo do 'motor multi-conta' (Fase B.3) — no
    futuro, substitui a necessidade de um serviço/agendamento separado por
    conta, permitindo que um único agendamento cuide de todas de uma vez.

    Uso: /multi/organizar-todas?confirmar=sim&limite=30
    """
    if not DATABASE_URL:
        return jsonify({"ok": False, "error": "DATABASE_URL não configurado"}), 500

    limite_por_conta = request.args.get("limite", "30")
    confirmar = request.args.get("confirmar", "")

    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT email, imap_host, quarentena_geral, quarentena_institucional, sent_folder "
                    "FROM gatekeeper_contas WHERE ativa = true ORDER BY criada_em;"
                )
                contas = cur.fetchall()
    except Exception as e:
        return jsonify({"ok": False, "error": f"Falha ao listar contas cadastradas: {e}"}), 500

    if not contas:
        return jsonify({"ok": True, "contas_processadas": 0, "resultados": [], "aviso": "Nenhuma conta cadastrada ainda."})

    # Guarda a configuração original (a conta fixa configurada por variável de
    # ambiente neste serviço, se houver) para restaurar ao final — mesmo em
    # caso de erro no meio do caminho.
    global EMAIL_USER, EMAIL_PASS, IMAP_HOST, QUARENTENA_SUBPASTA_GERAL, QUARENTENA_SUBPASTA_INSTITUCIONAL, SENT_FOLDER
    _originais = (EMAIL_USER, EMAIL_PASS, IMAP_HOST, QUARENTENA_SUBPASTA_GERAL, QUARENTENA_SUBPASTA_INSTITUCIONAL, SENT_FOLDER)

    resultados = []
    try:
        for (email_conta, imap_host, q_geral, q_inst, sent_folder) in contas:
            try:
                senha = cofre.obter_credencial_email(DATABASE_URL, email_conta)
            except Exception as e:
                resultados.append({"conta": email_conta, "ok": False, "error": f"Falha ao obter credencial do cofre: {e}"})
                continue

            if not senha:
                resultados.append({"conta": email_conta, "ok": False, "error": "Credencial não encontrada no cofre para esta conta."})
                continue

            # Troca temporariamente a configuração global para esta conta específica.
            EMAIL_USER = email_conta
            EMAIL_PASS = senha
            IMAP_HOST = imap_host
            QUARENTENA_SUBPASTA_GERAL = q_geral
            QUARENTENA_SUBPASTA_INSTITUCIONAL = q_inst
            SENT_FOLDER = sent_folder or SENT_FOLDER

            with app.test_client() as cliente_interno:
                resposta = cliente_interno.get(f"/organize?confirmar={confirmar}&limite={limite_por_conta}&resumo=sim")
                dados = resposta.get_json()
                resultados.append({"conta": email_conta, **(dados or {"ok": False, "error": "sem resposta"})})
    finally:
        EMAIL_USER, EMAIL_PASS, IMAP_HOST, QUARENTENA_SUBPASTA_GERAL, QUARENTENA_SUBPASTA_INSTITUCIONAL, SENT_FOLDER = _originais

    return jsonify({"ok": True, "contas_processadas": len(resultados), "resultados": resultados})


@app.route("/organize", methods=["GET"])
def organize():
    """
    Analisa a Caixa de Entrada e decide, para cada e-mail, se o remetente
    está na Lista Branca (fica) ou não (vai para a Quarentena).

    Por padrão, roda em MODO SIMULAÇÃO (não mexe em nada) — só mostra o
    que faria. Para executar de verdade (mover os e-mails), é preciso
    acessar com ?confirmar=sim no final do endereço.

    OTIMIZAÇÃO: em vez de reler a Caixa de Entrada inteira a cada execução
    (o que seria lento e arriscado em caixas com milhares de e-mails), o
    sistema lembra até qual UID (identificador único e crescente de cada
    e-mail) já processou, e da próxima vez olha só o que é mais novo que
    isso. Use ?reprocessar_tudo=sim para forçar uma varredura completa
    (por exemplo, na primeira vez, ou depois de mudanças manuais grandes).
    """
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    modo_real = request.args.get("confirmar", "").lower() == "sim"
    reprocessar_tudo = request.args.get("reprocessar_tudo", "").lower() == "sim"
    try:
        limite_lote = int(request.args.get("limite", "0"))
    except ValueError:
        limite_lote = 0
    whitelist = carregar_whitelist()
    blacklist = carregar_blacklist()
    blacklist_nomes = carregar_blacklist_nomes()
    blacklist_dominios = carregar_blacklist_dominios()
    chave_uidvalidity = f"uidvalidity:{EMAIL_USER}"

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=20)
        imap.login(EMAIL_USER, EMAIL_PASS)

        # Garante que as duas subpastas de Quarentena existem (Geral e Alerta Institucional).
        if modo_real:
            # Inscreve também a pasta 'pai' (INBOX.Quarentena) — mesmo ela não
            # guardando e-mail nenhum diretamente (só serve de 'gaveta' para
            # as duas subpastas), alguns clientes de e-mail (como o Outlook)
            # só mostram a árvore de pastas corretamente se o 'pai' também
            # estiver inscrito, não só as filhas.
            imap.subscribe(QUARANTINE_FOLDER)
            for pasta in (QUARENTENA_SUBPASTA_GERAL, QUARENTENA_SUBPASTA_INSTITUCIONAL):
                imap.create(pasta)
                imap.subscribe(pasta)

            status_lista, pastas = imap.list()
            pastas_confirmadas = status_lista == "OK" and all(
                any(nome.encode() in (p or b"") for p in pastas)
                for nome in (QUARENTENA_SUBPASTA_GERAL, QUARENTENA_SUBPASTA_INSTITUCIONAL)
            )
            if not pastas_confirmadas:
                return jsonify({
                    "ok": False,
                    "error": "As pastas de Quarentena não puderam ser confirmadas no servidor. "
                             "Por segurança, nada foi movido ou apagado.",
                }), 500

        imap.select("INBOX", readonly=not modo_real)

        aprovados_por_movimento = []
        if modo_real:
            aprovados_por_movimento = detectar_aprovacoes_por_movimento(imap)
            whitelist = carregar_whitelist()  # recarrega, caso alguma aprovação nova tenha entrado agora

        # Descobre o UIDVALIDITY atual (um "número de versão" da caixa — se
        # mudar, o servidor reorganizou tudo e nosso ponteiro salvo não vale mais).
        uidvalidity_atual = None
        status_val, dat_val = imap.status("INBOX", "(UIDVALIDITY)")
        if status_val == "OK" and dat_val and dat_val[0]:
            m = re.search(rb"UIDVALIDITY (\d+)", dat_val[0])
            if m:
                uidvalidity_atual = m.group(1).decode()

        ultimo_uid_salvo = obter_estado(chave_uid)
        uidvalidity_salva = obter_estado(chave_uidvalidity)

        usar_incremental = (
            not reprocessar_tudo
            and ultimo_uid_salvo is not None
            and uidvalidity_atual is not None
            and uidvalidity_salva == uidvalidity_atual
        )

        if usar_incremental:
            criterio_busca = f"UID {int(ultimo_uid_salvo) + 1}:*"
        else:
            criterio_busca = "ALL"

        status, data = imap.uid("search", None, criterio_busca)
        if status != "OK":
            return jsonify({"ok": False, "error": "Não foi possível listar as mensagens"}), 500

        uids = data[0].split()
        # Proteção extra: alguns servidores, quando "N:*" não encontra nada
        # com UID maior que N, devolvem a última mensagem existente mesmo
        # assim. Filtramos de novo aqui, manualmente, por segurança.
        if usar_incremental:
            limite = int(ultimo_uid_salvo)
            uids = [u for u in uids if int(u) > limite]

        total_pendente_antes_do_lote = len(uids)
        lote_parcial = False
        if limite_lote > 0 and len(uids) > limite_lote:
            uids = uids[:limite_lote]
            lote_parcial = True

        mantidos = []
        quarentena = []
        bloqueados = []
        falhas = []
        alertas_falsificacao = []
        maior_uid_visto = int(ultimo_uid_salvo) if (usar_incremental and ultimo_uid_salvo) else 0

        for uid in uids:
            maior_uid_visto = max(maior_uid_visto, int(uid))

            try:
                status, msg_data = imap.uid(
                    "fetch", uid, "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT AUTHENTICATION-RESULTS MESSAGE-ID)])"
                )
                if status != "OK" or not msg_data or not msg_data[0]:
                    continue
                raw_header = _bytes_seguro(msg_data[0][1] if isinstance(msg_data[0], (tuple, list)) and len(msg_data[0]) >= 2 else None).decode("utf-8", errors="replace")
                parsed = email.message_from_string(raw_header)

                from_header = parsed.get("From", "")
                nome_exibicao, endereco = email.utils.parseaddr(from_header)
                endereco = endereco.lower()
                nome_exibicao_norm = decode_str(nome_exibicao).strip().lower()
                if not endereco:
                    # Resposta do servidor não trouxe conteúdo utilizável para
                    # este e-mail (formato incomum/malformado) — pula, em vez
                    # de criar uma entrada vazia sem sentido.
                    continue
                assunto = decode_str(parsed.get("Subject"))
                message_id = (parsed.get("Message-ID") or "").strip()

                info = {"de": endereco, "nome": decode_str(nome_exibicao).strip(), "assunto": assunto}

                # Bloqueio definitivo (decisão discricionária do usuário) vem ANTES de
                # qualquer outra checagem — inclusive da institucional. Um remetente
                # bloqueado (por e-mail OU por nome de exibição) é apagado direto na
                # origem, nunca passa por Quarentena.
                if endereco in blacklist or (nome_exibicao_norm and nome_exibicao_norm in blacklist_nomes) or dominio_do_email(endereco) in blacklist_dominios:
                    info["alerta"] = "REMETENTE BLOQUEADO PERMANENTEMENTE — apagado direto, sem quarentena"
                    bloqueados.append(info)
                    if modo_real:
                        imap.uid("store", uid, "+FLAGS", "\\Deleted")
                    continue

                # Camada extra: se o remetente usa um domínio institucional protegido
                # (governo, judiciário, Correios etc.), a autenticidade técnica manda
                # mais que a Lista Branca — mesmo que pareça "conhecido", se falhar
                # na checagem de SPF/DKIM/DMARC, é tratado como possível falsificação.
                if eh_dominio_institucional(endereco):
                    auth = checar_autenticacao(parsed)
                    dominio_remetente = dominio_do_email(endereco)
                    confirmacao_govbr = None
                    if dominio_remetente.endswith(".gov.br"):
                        confirmacao_govbr = consultar_dominio_na_lista_oficial(dominio_remetente)
                        info["confirmacao_lista_oficial_govbr"] = confirmacao_govbr

                    classificacao = classificar_autenticacao(auth)

                    if classificacao == "passou":
                        info["institucional_verificado"] = True
                        mantidos.append(info)
                        continue

                    if classificacao == "sem_dados" and confirmacao_govbr and confirmacao_govbr.get("encontrado"):
                        # O servidor não registrou SPF/DKIM/DMARC (comum na Locaweb),
                        # mas o domínio consta na lista oficial do governo — sinal
                        # de confiança suficiente para manter na Caixa de Entrada.
                        info["institucional_verificado"] = True
                        info["observacao"] = "Autenticidade técnica (SPF/DKIM/DMARC) não verificável neste servidor, mas domínio confirmado na lista oficial gov.br."
                        mantidos.append(info)
                        continue

                    info["detalhe_autenticacao"] = auth
                    info["idade_do_dominio"] = consultar_idade_dominio(dominio_do_email(endereco))

                    if classificacao == "falhou":
                        # Falha CONFIRMADA de autenticidade — tratamento agressivo:
                        # gera um registro seguro (foto) e apaga o e-mail original,
                        # que pode conter anexos/links maliciosos de verdade.
                        info["alerta"] = "POSSÍVEL FALSIFICAÇÃO DE DOMÍNIO INSTITUCIONAL (falha confirmada de autenticação)"
                        alertas_falsificacao.append(info)
                        if modo_real:
                            ok_arquivo, detalhe_arquivo = arquivar_alerta_institucional_com_seguranca(
                                imap, uid, endereco, assunto
                            )
                            if ok_arquivo:
                                registrar_envio_para_quarentena(message_id, endereco, assunto)
                                info["registro_seguro"] = detalhe_arquivo
                            else:
                                info["motivo_falha"] = detalhe_arquivo
                    else:
                        # 'sem_dados': o servidor simplesmente não informa SPF/DKIM/DMARC
                        # (não é evidência de fraude). Por cautela, colocamos em
                        # quarentena para revisão manual — mas preservando o e-mail
                        # ORIGINAL intacto (incluindo anexos reais, como certidões em
                        # PDF), em vez de substituí-lo por uma foto. Isso evita perder
                        # documentos legítimos só por falta de dado técnico.
                        info["alerta"] = "AUTENTICIDADE NÃO VERIFICÁVEL NESTE SERVIDOR — revisar manualmente (documento original preservado)"
                        alertas_falsificacao.append(info)
                        if modo_real:
                            status_copy, _ = imap.uid("copy", uid, QUARENTENA_SUBPASTA_INSTITUCIONAL)
                            if status_copy == "OK":
                                imap.uid("store", uid, "+FLAGS", "\\Deleted")
                                registrar_envio_para_quarentena(message_id, endereco, assunto)
                            else:
                                info["motivo_falha"] = "Cópia para a Quarentena institucional falhou — e-mail NÃO foi apagado."
                    continue

                if endereco in whitelist:
                    mantidos.append(info)
                else:
                    if modo_real:
                        # TRAVA DE SEGURANÇA: só apaga o original se a cópia for confirmada.
                        status_copy, _ = imap.uid("copy", uid, QUARENTENA_SUBPASTA_GERAL)
                        if status_copy == "OK":
                            imap.uid("store", uid, "+FLAGS", "\\Deleted")
                            registrar_envio_para_quarentena(message_id, endereco, assunto)
                            quarentena.append(info)
                        else:
                            info["motivo_falha"] = "Cópia para a Quarentena falhou — e-mail NÃO foi apagado."
                            falhas.append(info)
                    else:
                        quarentena.append(info)
            except Exception as e:
                print(f"Aviso: pulando e-mail (uid={uid}) por erro inesperado ao processar: {e}", file=sys.stderr, flush=True)
                continue

        if modo_real:
            imap.expunge()
            # Só avançamos o "ponteiro de progresso" em modo real — uma
            # simulação nunca deve fazer o sistema "esquecer" de processar
            # algo de verdade depois.
            if maior_uid_visto > 0:
                salvar_estado(chave_uid, str(maior_uid_visto))
                if uidvalidity_atual is not None:
                    salvar_estado(chave_uidvalidity, uidvalidity_atual)

        modo_resumido = request.args.get("resumo", "").lower() == "sim"

        if modo_resumido:
            resposta = {
                "ok": True,
                "modo": "REAL — e-mails movidos de verdade" if modo_real else "SIMULAÇÃO — nada foi alterado",
                "processamento": "incremental (só mensagens novas)" if usar_incremental else "completo (caixa inteira)",
                "mensagens_analisadas_nesta_execucao": len(uids),
                "total_mantidos": len(mantidos),
                "total_quarentena": len(quarentena),
                "total_bloqueados": len(bloqueados),
                "total_alertas_institucionais": len(alertas_falsificacao),
                "total_aprovados_por_movimento": len(aprovados_por_movimento),
                "total_falhas": len(falhas),
            }
            if lote_parcial:
                resposta["lote_parcial"] = True
                resposta["restam_para_processar"] = total_pendente_antes_do_lote - len(uids)
            return jsonify(resposta)

        resposta = {
            "ok": True,
            "modo": "REAL — e-mails movidos de verdade" if modo_real else "SIMULAÇÃO — nada foi alterado",
            "processamento": "incremental (só mensagens novas)" if usar_incremental else "completo (caixa inteira)",
            "mensagens_analisadas_nesta_execucao": len(uids),
            "lista_branca_atual": sorted(whitelist),
            "mantidos_na_caixa_de_entrada": mantidos,
            "movidos_para_quarentena": quarentena,
            "bloqueados_permanentemente": bloqueados,
        }
        if lote_parcial:
            resposta["lote_parcial"] = True
            resposta["restam_para_processar"] = total_pendente_antes_do_lote - len(uids)
            resposta["dica"] = "Acesse o mesmo link de novo para processar o próximo lote."
        if alertas_falsificacao:
            resposta["alertas_de_possivel_falsificacao_institucional"] = alertas_falsificacao
        if aprovados_por_movimento:
            resposta["aprovados_por_movimento"] = aprovados_por_movimento
        if falhas:
            resposta["falhas_nao_apagadas_por_seguranca"] = falhas
        return jsonify(resposta)

    except imaplib.IMAP4.error as e:
        print(f"Erro de login/IMAP: {e}", file=sys.stderr, flush=True)
        return jsonify({"ok": False, "error": f"Erro de conexão/login IMAP: {e}"}), 500
    except Exception as e:
        print(f"Erro inesperado: {e}", file=sys.stderr, flush=True)
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


def _listar_pasta_quarentena(imap, pasta: str, categoria: str) -> list:
    """Lista as mensagens de uma subpasta específica da Quarentena, com a categoria já marcada."""
    status, _ = imap.select(pasta, readonly=True)
    if status != "OK":
        return []

    status, data = imap.uid("search", None, "ALL")
    ids = data[0].split() if status == "OK" else []

    mensagens = []
    for msg_id in ids:
        try:
            status, msg_data = imap.uid("fetch", msg_id, "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])")
            if status != "OK" or not msg_data or not msg_data[0]:
                continue
            conteudo = _bytes_seguro(msg_data[0][1] if isinstance(msg_data[0], (tuple, list)) and len(msg_data[0]) >= 2 else None)
            raw_header = conteudo.decode("utf-8", errors="replace")
            parsed = email.message_from_string(raw_header)
            from_header = parsed.get("From", "")
            nome_exibicao, endereco = email.utils.parseaddr(from_header)
            if not endereco:
                continue
            mensagens.append({
                "id": msg_id.decode(),
                "pasta": pasta,
                "categoria": categoria,
                "de": endereco.lower(),
                "nome": decode_str(nome_exibicao).strip(),
                "assunto": decode_str(parsed.get("Subject")),
                "data": parsed.get("Date"),
            })
        except Exception as e:
            print(f"Aviso: pulando mensagem da quarentena por erro: {e}", file=sys.stderr, flush=True)
            continue
    return mensagens


@app.route("/api/painel/resumo", methods=["GET"])
def api_painel_resumo():
    """
    Resumo pensado especificamente para os cartões do painel: quantos
    e-mails há na Caixa de Entrada, quantos alertas institucionais, quantos
    desconhecidos, e status geral da conta.
    """
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    def _contar_mensagens(imap, pasta):
        try:
            status, resp = imap.status(pasta, "(MESSAGES)")
            if status != "OK" or not resp or not resp[0]:
                return None
            m = re.search(rb"MESSAGES (\d+)", resp[0])
            return int(m.group(1)) if m else None
        except Exception:
            return None

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=20)
        imap.login(EMAIL_USER, EMAIL_PASS)

        total_caixa_de_entrada = _contar_mensagens(imap, "INBOX")
        total_institucional = _contar_mensagens(imap, QUARENTENA_SUBPASTA_INSTITUCIONAL)
        total_geral = _contar_mensagens(imap, QUARENTENA_SUBPASTA_GERAL)

        return jsonify({
            "ok": True,
            "conta_email": EMAIL_USER,
            "protegida": True,
            "total_caixa_de_entrada": total_caixa_de_entrada,
            "total_alerta_institucional": total_institucional,
            "total_geral": total_geral,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


@app.route("/quarentena", methods=["GET"])
def ver_quarentena():
    """Lista, somente leitura, o que está guardado nas DUAS subpastas de Quarentena (Geral e Alerta-Institucional)."""
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=20)
        imap.login(EMAIL_USER, EMAIL_PASS)

        mensagens = []
        mensagens += _listar_pasta_quarentena(imap, QUARENTENA_SUBPASTA_INSTITUCIONAL, "institucional")
        mensagens += _listar_pasta_quarentena(imap, QUARENTENA_SUBPASTA_GERAL, "geral")

        return jsonify({"ok": True, "total": len(mensagens), "mensagens": mensagens})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


class _ExtratorTextoHTML(HTMLParser):
    """
    Interpretador de HTML de verdade (não regex) para extrair só o texto visível.
    Isso é bem mais robusto que procurar por padrões de texto: um interpretador
    de HTML entende a estrutura da página como um navegador entenderia, então é
    muito mais difícil de burlar com HTML malformado ou tags aninhadas de propósito.
    """
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.partes = []
        self._ignorando = 0  # contador para lidar com <script>/<style> aninhados

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._ignorando += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._ignorando > 0:
            self._ignorando -= 1

    def handle_data(self, data):
        if self._ignorando == 0:
            self.partes.append(data)

    def texto(self):
        return "".join(self.partes)


def _extrair_texto_de_html(html: str) -> str:
    parser = _ExtratorTextoHTML()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass  # HTML malformado — segue com o que já foi extraído até o erro
    return parser.texto()


def extrair_texto_seguro(msg):
    """
    Extrai apenas o texto do e-mail, de forma segura:
    - Nunca executa nem baixa anexos.
    - Prefere a versão em texto puro (text/plain).
    - Se só houver HTML, usa um interpretador de HTML de verdade (não regex)
      para extrair só o texto visível, ignorando <script> e <style> por completo.
    - Substitui links por um aviso, para que nada seja clicável.
    """
    corpo = ""
    if msg.is_multipart():
        for parte in msg.walk():
            tipo = parte.get_content_type()
            disposicao = str(parte.get("Content-Disposition") or "")
            if "attachment" in disposicao:
                continue  # nunca extrai anexos
            if tipo == "text/plain" and not corpo:
                payload = parte.get_payload(decode=True) or b""
                corpo = payload.decode(parte.get_content_charset() or "utf-8", errors="replace")
        if not corpo:
            for parte in msg.walk():
                if parte.get_content_type() == "text/html":
                    payload = parte.get_payload(decode=True) or b""
                    html = payload.decode(parte.get_content_charset() or "utf-8", errors="replace")
                    corpo = _extrair_texto_de_html(html)
                    break
    else:
        payload = msg.get_payload(decode=True) or b""
        texto = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
        if msg.get_content_type() == "text/html":
            texto = _extrair_texto_de_html(texto)
        corpo = texto

    corpo = re.sub(r"https?://\S+", "[link removido por segurança]", corpo)
    corpo = re.sub(r"[ \t]+", " ", corpo)
    corpo = re.sub(r"\n{3,}", "\n\n", corpo).strip()

    anexos = []
    if msg.is_multipart():
        for parte in msg.walk():
            disposicao = str(parte.get("Content-Disposition") or "")
            if "attachment" in disposicao:
                nome = parte.get_filename() or "arquivo_sem_nome"
                anexos.append(decode_str(nome))

    return corpo[:5000], anexos  # limite de 5000 caracteres por segurança/tamanho


def extrair_bytes_dos_anexos(msg):
    """Retorna a lista de anexos (nome, tipo, bytes brutos), na mesma ordem usada em extrair_texto_seguro."""
    anexos = []
    if msg.is_multipart():
        for parte in msg.walk():
            disposicao = str(parte.get("Content-Disposition") or "")
            if "attachment" in disposicao:
                nome = decode_str(parte.get_filename() or "arquivo_sem_nome")
                tipo = parte.get_content_type()
                dados = parte.get_payload(decode=True) or b""
                anexos.append({"nome": nome, "tipo": tipo, "dados": dados})
    return anexos


def renderizar_anexo_como_imagem(nome: str, tipo: str, dados: bytes):
    """
    Converte um anexo em uma imagem PNG nova, desenhada do zero — nunca abre,
    executa ou interpreta o arquivo original como um programa/leitor faria.

    Para PDF: usa PyMuPDF só para desenhar a página como uma figura (não executa
    JavaScript nem ações embutidas no PDF).
    Para imagens: reabre e regrava os pixels numa imagem nova, descartando
    qualquer metadado ou conteúdo incomum embutido no arquivo original.

    Retorna (bytes_da_imagem_png, mensagem_de_erro).
    """
    nome_lower = nome.lower()
    try:
        if tipo == "application/pdf" or nome_lower.endswith(".pdf"):
            documento = fitz.open(stream=dados, filetype="pdf")
            if documento.page_count == 0:
                return None, "PDF sem páginas"
            pagina = documento.load_page(0)
            pixmap = pagina.get_pixmap(dpi=120)
            return pixmap.tobytes("png"), None

        elif tipo.startswith("image/") or nome_lower.endswith((".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp")):
            imagem = Image.open(io.BytesIO(dados))
            imagem = imagem.convert("RGB")
            buffer = io.BytesIO()
            imagem.save(buffer, format="PNG")
            return buffer.getvalue(), None

        else:
            return None, (
                f"Ainda não existe prévia segura para arquivos do tipo '{tipo}'. "
                "Por segurança, ele NÃO foi baixado nem aberto."
            )
    except Exception as e:
        return None, f"Não foi possível gerar uma prévia segura deste arquivo: {e}"


def renderizar_texto_como_imagem(texto: str, cabecalho: str = "") -> bytes:
    """
    Desenha um texto (já limpo/seguro) numa imagem PNG nova, do zero — como
    tirar uma 'foto' do conteúdo. Não interpreta HTML nem nenhum código;
    só recebe caracteres de texto puro e os desenha na tela, pixel a pixel.
    Isso elimina qualquer possibilidade de algo escondido 'nas entrelinhas'
    do e-mail sobreviver à conversão.
    """
    from PIL import ImageDraw, ImageFont

    largura = 900
    margem = 30
    fonte_corpo = ImageFont.load_default()
    try:
        fonte_titulo = ImageFont.load_default(size=16)
    except TypeError:
        fonte_titulo = fonte_corpo  # versões antigas do Pillow não aceitam 'size' aqui

    texto_completo = (cabecalho + "\n" + ("-" * 60) + "\n" + texto) if cabecalho else texto

    # Quebra o texto em linhas que cabem na largura da imagem
    linhas = []
    for paragrafo in texto_completo.split("\n"):
        if not paragrafo:
            linhas.append("")
            continue
        palavras = paragrafo.split(" ")
        linha_atual = ""
        for palavra in palavras:
            teste = (linha_atual + " " + palavra).strip()
            if len(teste) > 100:  # limite aproximado de caracteres por linha
                linhas.append(linha_atual)
                linha_atual = palavra
            else:
                linha_atual = teste
        linhas.append(linha_atual)

    altura_linha = 16
    altura = margem * 2 + len(linhas) * altura_linha
    altura = max(altura, 200)

    imagem = Image.new("RGB", (largura, altura), color="white")
    desenho = ImageDraw.Draw(imagem)

    y = margem
    for i, linha in enumerate(linhas):
        fonte_usada = fonte_titulo if (cabecalho and i < cabecalho.count("\n") + 1) else fonte_corpo
        desenho.text((margem, y), linha, fill="black", font=fonte_usada)
        y += altura_linha

    buffer = io.BytesIO()
    imagem.save(buffer, format="PNG")
    return buffer.getvalue()


def construir_email_de_registro_seguro(endereco_original: str, assunto_original: str, data_original: str, imagem_png: bytes) -> bytes:
    """
    Monta um novo e-mail sintético, contendo só a 'foto' segura (imagem) do
    conteúdo original como anexo — nunca o e-mail original em si. Esse é o
    e-mail que fica arquivado como prova, no lugar do original perigoso.
    """
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.image import MIMEImage

    novo = MIMEMultipart()
    novo["Subject"] = f"[REGISTRO SEGURO] {assunto_original}"
    novo["From"] = "gatekeeper-mail@registro-seguro.local"
    novo["To"] = EMAIL_USER
    novo["Date"] = email.utils.formatdate(localtime=True)

    texto_explicativo = (
        f"Este é um REGISTRO SEGURO gerado automaticamente pelo Gatekeeper Mail.\n\n"
        f"O e-mail original, de '{endereco_original}' (recebido em {data_original}), "
        f"foi identificado como possível falsificação de domínio institucional.\n\n"
        f"Por segurança, o e-mail original (que poderia conter anexos ou links "
        f"maliciosos) foi excluído do servidor. A imagem em anexo mostra o "
        f"conteúdo de texto do e-mail original, de forma segura, como prova.\n\n"
        f"AVISO: esta imagem mostra o que o e-mail dizia — isso NÃO significa "
        f"que o conteúdo é verdadeiro ou confiável."
    )
    novo.attach(MIMEText(texto_explicativo, "plain", "utf-8"))

    anexo_imagem = MIMEImage(imagem_png, _subtype="png")
    anexo_imagem.add_header("Content-Disposition", "attachment", filename="registro_seguro.png")
    novo.attach(anexo_imagem)

    return novo.as_bytes()


def arquivar_alerta_institucional_com_seguranca(imap, uid, endereco: str, assunto: str) -> tuple:
    """
    Para um e-mail já identificado como possível falsificação institucional:
    1. Busca o conteúdo completo do e-mail original.
    2. Gera uma 'foto' segura (texto renderizado em imagem) do conteúdo.
    3. Monta um novo e-mail só com essa foto, e o guarda na subpasta de
       Alerta Institucional (arquivamento seguro, como prova).
    4. SÓ DEPOIS de confirmar que o registro seguro foi guardado com sucesso,
       apaga o e-mail original (que pode conter anexos/links perigosos).

    Retorna (sucesso: bool, detalhe: str).
    """
    try:
        status, msg_data = imap.uid("fetch", uid, "(BODY.PEEK[])")
        if status != "OK" or not msg_data or not msg_data[0]:
            return False, "Não foi possível buscar o conteúdo completo do e-mail original."

        msg_completo = email.message_from_bytes(msg_data[0][1])
        corpo_seguro, anexos = extrair_texto_seguro(msg_completo)
        data_original = msg_completo.get("Date", "desconhecida")

        cabecalho = f"De: {endereco}\nAssunto: {assunto}\nData: {data_original}"
        if anexos:
            cabecalho += f"\nAnexos no original (não incluídos, nunca baixados): {', '.join(anexos)}"

        imagem_png = renderizar_texto_como_imagem(corpo_seguro, cabecalho)
        email_registro = construir_email_de_registro_seguro(endereco, assunto, data_original, imagem_png)

        # TRAVA DE SEGURANÇA: só apaga o original depois de confirmar que o
        # registro seguro foi guardado com sucesso na subpasta institucional.
        status_append, _ = imap.append(
            QUARENTENA_SUBPASTA_INSTITUCIONAL, None, None, email_registro
        )
        if status_append != "OK":
            return False, "Falha ao guardar o registro seguro — o e-mail original NÃO foi apagado."

        imap.uid("store", uid, "+FLAGS", "\\Deleted")
        return True, "Registro seguro guardado; e-mail original perigoso removido."

    except Exception as e:
        return False, f"Erro ao arquivar com segurança: {e}"


@app.route("/quarentena/foto", methods=["GET"])
def foto_email_quarentena():
    """
    Rota de TESTE: gera a 'foto' segura (texto renderizado em imagem) do
    conteúdo de um e-mail da Quarentena — sem apagar nada ainda, só para
    conferir visualmente como fica o resultado.
    Uso: /quarentena/foto?id=123&pasta=INBOX.Quarentena.Geral
    """
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    msg_id = request.args.get("id", "").strip()
    pasta = request.args.get("pasta", QUARENTENA_SUBPASTA_GERAL).strip()
    if not msg_id:
        return jsonify({"ok": False, "error": "Informe o número do e-mail em ?id="}), 400

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=20)
        imap.login(EMAIL_USER, EMAIL_PASS)
        status, _ = imap.select(pasta, readonly=True)
        if status != "OK":
            return jsonify({"ok": False, "error": f"A pasta '{pasta}' não existe"}), 404

        status, msg_data = imap.uid("fetch", msg_id.encode(), "(BODY.PEEK[])")
        if status != "OK" or not msg_data or not msg_data[0]:
            return jsonify({"ok": False, "error": "E-mail não encontrado na Quarentena"}), 404

        conteudo = _bytes_seguro(msg_data[0][1] if isinstance(msg_data[0], (tuple, list)) and len(msg_data[0]) >= 2 else None)
        msg = email.message_from_bytes(conteudo)
        from_header = msg.get("From", "")
        _, endereco = email.utils.parseaddr(from_header)
        assunto = decode_str(msg.get("Subject"))
        corpo_seguro, anexos = extrair_texto_seguro(msg)

        cabecalho = f"De: {endereco}\nAssunto: {assunto}\nData: {msg.get('Date', '')}"
        if anexos:
            cabecalho += f"\nAnexos no original (não incluídos nesta foto): {', '.join(anexos)}"

        imagem_png = renderizar_texto_como_imagem(corpo_seguro, cabecalho)
        return Response(imagem_png, mimetype="image/png")

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


@app.route("/quarentena/ver", methods=["GET"])
def ver_email_quarentena():
    """
    Visualização SEGURA de um e-mail específico da Quarentena.
    Uso: /quarentena/ver?id=123&pasta=INBOX.Quarentena.Geral
    (o parâmetro 'pasta' identifica em qual subpasta procurar — Geral ou
    Alerta-Institucional; se não informado, tenta a Geral por padrão)
    Mostra só texto (nunca HTML renderizado, nunca anexos, nunca links clicáveis).
    """
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    msg_id = request.args.get("id", "").strip()
    pasta = request.args.get("pasta", QUARENTENA_SUBPASTA_GERAL).strip()
    if not msg_id:
        return jsonify({"ok": False, "error": "Informe o número do e-mail em ?id="}), 400

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=20)
        imap.login(EMAIL_USER, EMAIL_PASS)
        status, _ = imap.select(pasta, readonly=True)
        if status != "OK":
            return jsonify({"ok": False, "error": f"A pasta '{pasta}' não existe"}), 404

        status, msg_data = imap.uid("fetch", msg_id.encode(), "(BODY.PEEK[])")
        if status != "OK" or not msg_data or not msg_data[0]:
            return jsonify({"ok": False, "error": "E-mail não encontrado na Quarentena"}), 404

        raw_email = _bytes_seguro(msg_data[0][1] if isinstance(msg_data[0], (tuple, list)) and len(msg_data[0]) >= 2 else None)
        msg = email.message_from_bytes(raw_email)

        from_header = msg.get("From", "")
        _, endereco = email.utils.parseaddr(from_header)
        corpo, anexos = extrair_texto_seguro(msg)

        return jsonify({
            "ok": True,
            "de": endereco.lower(),
            "assunto": decode_str(msg.get("Subject")),
            "data": msg.get("Date"),
            "corpo_seguro": corpo,
            "anexos_encontrados_mas_nao_baixados": anexos,
            "aviso": "Links e anexos foram neutralizados nesta visualização — nada aqui pode executar automaticamente. Isso NÃO significa que o conteúdo é verdadeiro ou confiável. Leia com atenção antes de agir.",
        })

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


@app.route("/quarentena/apagar", methods=["GET"])
def apagar_email_quarentena():
    """
    Apaga PERMANENTEMENTE um e-mail da pasta de Quarentena.
    Por segurança, só apaga de verdade com ?confirmar=sim — sem isso, apenas
    mostra qual e-mail seria apagado, sem fazer nada.
    Uso: /quarentena/apagar?id=8&confirmar=sim
    """
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    msg_id = request.args.get("id", "").strip()
    pasta = request.args.get("pasta", QUARENTENA_SUBPASTA_GERAL).strip()
    if not msg_id:
        return jsonify({"ok": False, "error": "Informe o número do e-mail em ?id="}), 400

    modo_real = request.args.get("confirmar", "").lower() == "sim"

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=20)
        imap.login(EMAIL_USER, EMAIL_PASS)
        status, _ = imap.select(pasta, readonly=not modo_real)
        if status != "OK":
            return jsonify({"ok": False, "error": f"A pasta '{pasta}' não existe"}), 404

        status, msg_data = imap.uid("fetch", msg_id.encode(), "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)])")
        if status != "OK" or not msg_data or not msg_data[0]:
            return jsonify({"ok": False, "error": "E-mail não encontrado na Quarentena"}), 404

        conteudo = _bytes_seguro(msg_data[0][1] if isinstance(msg_data[0], (tuple, list)) and len(msg_data[0]) >= 2 else None)
        parsed = email.message_from_bytes(conteudo)
        from_header = parsed.get("From", "")
        _, endereco = email.utils.parseaddr(from_header)
        assunto = decode_str(parsed.get("Subject"))

        if not modo_real:
            return jsonify({
                "ok": True,
                "modo": "SIMULAÇÃO — nada foi apagado",
                "seria_apagado": {"id": msg_id, "de": endereco.lower(), "assunto": assunto},
                "dica": "Acesse este mesmo link com &confirmar=sim no final para apagar de verdade.",
            })

        imap.uid("store", msg_id.encode(), "+FLAGS", "\\Deleted")
        imap.expunge()

        return jsonify({
            "ok": True,
            "modo": "REAL — e-mail apagado permanentemente",
            "apagado": {"id": msg_id, "de": endereco.lower(), "assunto": assunto},
        })

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


@app.route("/quarentena/anexo", methods=["GET"])
def ver_anexo_quarentena():
    """
    Mostra uma prévia SEGURA de um anexo de um e-mail da Quarentena — nunca o
    arquivo original, sempre uma imagem redesenhada do zero.
    Uso: /quarentena/anexo?id=123&indice=0&pasta=INBOX.Quarentena.Geral
    """
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    msg_id = request.args.get("id", "").strip()
    pasta = request.args.get("pasta", QUARENTENA_SUBPASTA_GERAL).strip()
    try:
        indice = int(request.args.get("indice", "0"))
    except ValueError:
        return jsonify({"ok": False, "error": "O parâmetro 'indice' precisa ser um número"}), 400

    if not msg_id:
        return jsonify({"ok": False, "error": "Informe o número do e-mail em ?id="}), 400

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=20)
        imap.login(EMAIL_USER, EMAIL_PASS)
        status, _ = imap.select(pasta, readonly=True)
        if status != "OK":
            return jsonify({"ok": False, "error": f"A pasta '{pasta}' não existe"}), 404

        status, msg_data = imap.uid("fetch", msg_id.encode(), "(BODY.PEEK[])")
        if status != "OK" or not msg_data or not msg_data[0]:
            return jsonify({"ok": False, "error": "E-mail não encontrado na Quarentena"}), 404

        conteudo = _bytes_seguro(msg_data[0][1] if isinstance(msg_data[0], (tuple, list)) and len(msg_data[0]) >= 2 else None)
        msg = email.message_from_bytes(conteudo)
        anexos = extrair_bytes_dos_anexos(msg)

        if indice < 0 or indice >= len(anexos):
            return jsonify({"ok": False, "error": f"Esse e-mail tem {len(anexos)} anexo(s); índice {indice} não existe"}), 404

        anexo = anexos[indice]
        imagem_png, erro = renderizar_anexo_como_imagem(anexo["nome"], anexo["tipo"], anexo["dados"])

        if erro:
            return jsonify({"ok": False, "error": erro, "nome_do_anexo": anexo["nome"]}), 415

        return Response(imagem_png, mimetype="image/png")

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


@app.route("/sugestoes", methods=["GET"])
def sugestoes():
    """
    Varre a pasta de Enviados e sugere, em lote, quem aprovar na Lista Branca —
    baseado em para quem o usuário já escreveu antes (curadoria assistida).

    Por segurança/velocidade, olha só as últimas N mensagens enviadas
    (parâmetro opcional ?limite=300, padrão 300) — em caixas muito grandes,
    processar o histórico inteiro de uma vez poderia demorar demais.
    """
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    try:
        limite = int(request.args.get("limite", "300"))
    except ValueError:
        limite = 300

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=20)
        imap.login(EMAIL_USER, EMAIL_PASS)
        status, _ = imap.select(SENT_FOLDER, readonly=True)
        if status != "OK":
            return jsonify({
                "ok": False,
                "error": f"Não foi possível abrir a pasta de Enviados ('{SENT_FOLDER}'). "
                         "Se o nome for diferente nesse provedor, configure a variável SENT_FOLDER_NAME.",
            }), 404

        status, data = imap.search(None, "ALL")
        if status != "OK":
            return jsonify({"ok": False, "error": "Não foi possível listar os e-mails enviados"}), 500

        todos_ids = data[0].split()
        ids_recentes = todos_ids[-limite:] if len(todos_ids) > limite else todos_ids

        contagem = {}
        nomes = {}
        for msg_id in ids_recentes:
            status, msg_data = imap.fetch(msg_id, "(BODY.PEEK[HEADER.FIELDS (TO)])")
            if status != "OK" or not msg_data or not msg_data[0]:
                continue
            raw_header = msg_data[0][1].decode("utf-8", errors="replace")
            parsed = email.message_from_string(raw_header)
            destinatarios = email.utils.getaddresses([parsed.get("To", "")])
            for nome_bruto, endereco in destinatarios:
                endereco = endereco.strip().lower()
                if endereco:
                    contagem[endereco] = contagem.get(endereco, 0) + 1
                    nome_decodificado = decode_str(nome_bruto).strip()
                    if nome_decodificado:
                        nomes[endereco] = nome_decodificado  # guarda a ocorrência mais recente

        whitelist_atual = carregar_whitelist()

        sugestoes_lista = [
            {
                "email": endereco,
                "nome": nomes.get(endereco, ""),
                "vezes_que_voce_escreveu": qtd,
                "ja_esta_na_lista_branca": endereco in whitelist_atual,
            }
            for endereco, qtd in contagem.items()
        ]
        sugestoes_lista.sort(key=lambda x: x["vezes_que_voce_escreveu"], reverse=True)

        return jsonify({
            "ok": True,
            "total_de_enviados_analisados": len(ids_recentes),
            "total_de_destinatarios_unicos": len(sugestoes_lista),
            "sugestoes": sugestoes_lista,
        })

    except imaplib.IMAP4.error as e:
        return jsonify({"ok": False, "error": f"Erro de conexão/login IMAP: {e}"}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


@app.route("/sugestoes/aprovar-todos", methods=["GET"])
def aprovar_todas_sugestoes():
    """
    Aprova, de uma vez, todos os remetentes sugeridos (que ainda não estão na
    Lista Branca). Por segurança, só executa de verdade com ?confirmar=sim —
    sem isso, só mostra quem seria aprovado.
    """
    modo_real = request.args.get("confirmar", "").lower() == "sim"

    resposta_sugestoes = sugestoes()
    if isinstance(resposta_sugestoes, tuple):
        return resposta_sugestoes  # propaga erro, se houver

    dados = resposta_sugestoes.get_json()
    if not dados.get("ok"):
        return jsonify(dados), 500

    pendentes = [s["email"] for s in dados["sugestoes"] if not s["ja_esta_na_lista_branca"]]

    if not modo_real:
        return jsonify({
            "ok": True,
            "modo": "SIMULAÇÃO — nada foi aprovado",
            "seriam_aprovados": pendentes,
            "dica": "Acesse este mesmo link com &confirmar=sim no final para aprovar de verdade.",
        })

    aprovados, falharam = aprovar_remetentes_em_lote(pendentes)

    resposta = {"ok": True, "modo": "REAL — aprovados de verdade", "aprovados": aprovados}
    if falharam:
        resposta["falharam"] = falharam
    return jsonify(resposta)


@app.route("/aprovar", methods=["POST", "GET"])
def aprovar():
    """
    Aprova um remetente de forma permanente: adiciona à Lista Branca (banco de dados).
    Uso: /aprovar?email=alguem@exemplo.com
    Isso NÃO move e-mails antigos automaticamente — só passa a valer para os próximos.
    """
    email_addr = request.args.get("email", "").strip().lower()
    if not email_addr or "@" not in email_addr:
        return jsonify({"ok": False, "error": "Informe um e-mail válido em ?email="}), 400

    ok, erro = aprovar_remetente(email_addr)
    if not ok:
        return jsonify({"ok": False, "error": erro}), 500

    return jsonify({"ok": True, "mensagem": f"{email_addr} foi adicionado à Lista Branca permanentemente."})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
