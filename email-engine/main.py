import os
import sys
import imaplib
import email
from email.header import decode_header
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ------------------------------------------------------------------
# Variáveis de ambiente (configure no painel do Render, em "Environment"):
#   EMAIL_USER  -> gatekeeper@ccat.com.br
#   EMAIL_PASS  -> a senha dessa caixa de e-mail (Locaweb)
# ------------------------------------------------------------------
IMAP_HOST = "email-ssl.com.br"
IMAP_PORT = 993
EMAIL_USER = os.environ.get("EMAIL_USER", "")
EMAIL_PASS = os.environ.get("EMAIL_PASS", "")


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
