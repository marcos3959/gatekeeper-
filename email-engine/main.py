import os
import sys
import imaplib
import email
import email.utils
from email.header import decode_header
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ------------------------------------------------------------------
# Variáveis de ambiente (configure no painel do Render, em "Environment"):
#   EMAIL_USER       -> gatekeeper@ccat.com.br
#   EMAIL_PASS       -> a senha dessa caixa de e-mail (Locaweb)
#   WHITELIST_EMAILS -> lista de e-mails "conhecidos", separados por vírgula
#                       ex: autorizafoto@gmail.com,marcos.usp39@gmail.com
# ------------------------------------------------------------------
IMAP_HOST = "email-ssl.com.br"
IMAP_PORT = 993
EMAIL_USER = os.environ.get("EMAIL_USER", "")
EMAIL_PASS = os.environ.get("EMAIL_PASS", "")
QUARANTINE_FOLDER = "INBOX.Quarentena"

WHITELIST = {
    e.strip().lower()
    for e in os.environ.get("WHITELIST_EMAILS", "").split(",")
    if e.strip()
}


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

    imap = None
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
        imap.login(EMAIL_USER, EMAIL_PASS)

        # Garante que a pasta de Quarentena existe.
        # imap.create() retorna erro se a pasta já existir — isso é esperado e não é problema.
        # Só tratamos como problema real se a pasta não existir DEPOIS de tentarmos criar.
        if modo_real:
            imap.create(QUARANTINE_FOLDER)
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

            if endereco in WHITELIST:
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
            "lista_branca_atual": sorted(WHITELIST),
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
