import os
import sys
import re
import imaplib
import email
import email.utils
from email.header import decode_header
from flask import Flask, jsonify, request
from flask_cors import CORS
import psycopg

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ------------------------------------------------------------------
# Variáveis de ambiente (configure no painel do Render, em "Environment"):
#   EMAIL_USER       -> gatekeeper@ccat.com.br
#   EMAIL_PASS       -> a senha dessa caixa de e-mail (Locaweb)
#   WHITELIST_EMAILS -> lista "de fábrica", separada por vírgula (opcional)
#   DATABASE_URL     -> mesma conexão Postgres/Supabase usada no outro serviço
# ------------------------------------------------------------------
IMAP_HOST = "email-ssl.com.br"
IMAP_PORT = 993
EMAIL_USER = os.environ.get("EMAIL_USER", "")
EMAIL_PASS = os.environ.get("EMAIL_PASS", "")
QUARANTINE_FOLDER = "INBOX.Quarentena"
DATABASE_URL = os.environ.get("DATABASE_URL", "")

WHITELIST_FIXA = {
    e.strip().lower()
    for e in os.environ.get("WHITELIST_EMAILS", "").split(",")
    if e.strip()
}


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


def aprovar_remetente(email_addr: str):
    """Adiciona um e-mail permanentemente à Lista Branca (tabela gatekeeper_whitelist)."""
    if not DATABASE_URL:
        return False, "DATABASE_URL não configurado"
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO gatekeeper_whitelist (email) VALUES (%s) ON CONFLICT (email) DO NOTHING;",
                    (email_addr.strip().lower(),),
                )
            conn.commit()
        return True, None
    except Exception as e:
        print(f"Erro ao aprovar remetente: {e}", file=sys.stderr, flush=True)
        return False, str(e)


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
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
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
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
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


@app.route("/organize", methods=["GET"])
def organize():
    """
    Analisa a Caixa de Entrada e decide, para cada e-mail, se o remetente
    está na Lista Branca (fica) ou não (vai para a Quarentena).

    Por padrão, roda em MODO SIMULAÇÃO (não mexe em nada) — só mostra o
    que faria. Para executar de verdade (mover os e-mails), é preciso
    acessar com ?confirmar=sim no final do endereço.
    """
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    modo_real = request.args.get("confirmar", "").lower() == "sim"
    whitelist = carregar_whitelist()

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
        imap.login(EMAIL_USER, EMAIL_PASS)

        # Garante que a pasta de Quarentena existe.
        # imap.create() retorna erro se a pasta já existir — isso é esperado e não é problema.
        # Só tratamos como problema real se a pasta não existir DEPOIS de tentarmos criar.
        if modo_real:
            imap.create(QUARANTINE_FOLDER)
            imap.subscribe(QUARANTINE_FOLDER)  # torna a pasta visível em webmails/clientes de e-mail
            status_lista, pastas = imap.list()
            pasta_existe = status_lista == "OK" and any(
                QUARANTINE_FOLDER.encode() in (p or b"") for p in pastas
            )
            if not pasta_existe:
                return jsonify({
                    "ok": False,
                    "error": f"A pasta '{QUARANTINE_FOLDER}' não pôde ser confirmada no servidor. "
                             "Por segurança, nada foi movido ou apagado.",
                }), 500

        imap.select("INBOX", readonly=not modo_real)

        status, data = imap.search(None, "ALL")
        if status != "OK":
            return jsonify({"ok": False, "error": "Não foi possível listar as mensagens"}), 500

        ids = data[0].split()
        mantidos = []
        quarentena = []
        falhas = []

        for msg_id in ids:
            status, msg_data = imap.fetch(msg_id, "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)])")
            if status != "OK" or not msg_data or not msg_data[0]:
                continue
            raw_header = msg_data[0][1].decode("utf-8", errors="replace")
            parsed = email.message_from_string(raw_header)

            from_header = parsed.get("From", "")
            _, endereco = email.utils.parseaddr(from_header)
            endereco = endereco.lower()
            assunto = decode_str(parsed.get("Subject"))

            info = {"de": endereco, "assunto": assunto}

            if endereco in whitelist:
                mantidos.append(info)
            else:
                if modo_real:
                    # TRAVA DE SEGURANÇA: só apaga o original se a cópia for confirmada.
                    status_copy, _ = imap.copy(msg_id, QUARANTINE_FOLDER)
                    if status_copy == "OK":
                        imap.store(msg_id, "+FLAGS", "\\Deleted")
                        quarentena.append(info)
                    else:
                        info["motivo_falha"] = "Cópia para a Quarentena falhou — e-mail NÃO foi apagado."
                        falhas.append(info)
                else:
                    quarentena.append(info)

        if modo_real:
            imap.expunge()

        resposta = {
            "ok": True,
            "modo": "REAL — e-mails movidos de verdade" if modo_real else "SIMULAÇÃO — nada foi alterado",
            "lista_branca_atual": sorted(whitelist),
            "mantidos_na_caixa_de_entrada": mantidos,
            "movidos_para_quarentena": quarentena,
        }
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


@app.route("/quarentena", methods=["GET"])
def ver_quarentena():
    """Lista, somente leitura, o que está guardado na pasta de Quarentena."""
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
        imap.login(EMAIL_USER, EMAIL_PASS)
        status, _ = imap.select(QUARANTINE_FOLDER, readonly=True)
        if status != "OK":
            return jsonify({"ok": True, "mensagens": [], "aviso": "A pasta de Quarentena ainda não existe ou está vazia."})

        status, data = imap.search(None, "ALL")
        ids = data[0].split() if status == "OK" else []

        mensagens = []
        for msg_id in ids:
            status, msg_data = imap.fetch(msg_id, "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])")
            if status != "OK" or not msg_data or not msg_data[0]:
                continue
            raw_header = msg_data[0][1].decode("utf-8", errors="replace")
            parsed = email.message_from_string(raw_header)
            from_header = parsed.get("From", "")
            _, endereco = email.utils.parseaddr(from_header)
            mensagens.append({
                "id": msg_id.decode(),
                "de": endereco.lower(),
                "assunto": decode_str(parsed.get("Subject")),
                "data": parsed.get("Date"),
            })

        return jsonify({"ok": True, "total": len(mensagens), "mensagens": mensagens})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


def extrair_texto_seguro(msg):
    """
    Extrai apenas o texto do e-mail, de forma segura:
    - Nunca executa nem baixa anexos.
    - Prefere a versão em texto puro (text/plain).
    - Se só houver HTML, remove todas as tags e scripts, deixando só o texto.
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
                    html = re.sub(r"<script.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE)
                    html = re.sub(r"<style.*?</style>", " ", html, flags=re.DOTALL | re.IGNORECASE)
                    corpo = re.sub(r"<[^>]+>", " ", html)  # remove todas as tags restantes
                    break
    else:
        payload = msg.get_payload(decode=True) or b""
        texto = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
        if msg.get_content_type() == "text/html":
            texto = re.sub(r"<script.*?</script>", " ", texto, flags=re.DOTALL | re.IGNORECASE)
            texto = re.sub(r"<style.*?</style>", " ", texto, flags=re.DOTALL | re.IGNORECASE)
            texto = re.sub(r"<[^>]+>", " ", texto)
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


@app.route("/quarentena/ver", methods=["GET"])
def ver_email_quarentena():
    """
    Visualização SEGURA de um e-mail específico da Quarentena.
    Uso: /quarentena/ver?id=123
    Mostra só texto (nunca HTML renderizado, nunca anexos, nunca links clicáveis).
    """
    if not EMAIL_USER or not EMAIL_PASS:
        return jsonify({"ok": False, "error": "Faltam as variáveis EMAIL_USER / EMAIL_PASS"}), 500

    msg_id = request.args.get("id", "").strip()
    if not msg_id:
        return jsonify({"ok": False, "error": "Informe o número do e-mail em ?id="}), 400

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
        imap.login(EMAIL_USER, EMAIL_PASS)
        status, _ = imap.select(QUARANTINE_FOLDER, readonly=True)
        if status != "OK":
            return jsonify({"ok": False, "error": "A pasta de Quarentena não existe"}), 404

        status, msg_data = imap.fetch(msg_id.encode(), "(BODY.PEEK[])")
        if status != "OK" or not msg_data or not msg_data[0]:
            return jsonify({"ok": False, "error": "E-mail não encontrado na Quarentena"}), 404

        raw_email = msg_data[0][1]
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
            "aviso": "Links foram removidos e anexos não foram baixados, por segurança.",
        })

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass


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
