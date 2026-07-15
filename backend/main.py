import os
import sys
from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg
import requests

app = Flask(__name__)
CORS(app, resources={r"/signup": {"origins": "*"}})

# ------------------------------------------------------------------
# Variáveis de ambiente (configure no painel do Render, em "Environment"):
#   DATABASE_URL    -> a mesma informação que você já usa no reescreve-ai-web
#                      (Render > seu projeto Supabase > Connect > Connection string)
#   RESEND_API_KEY  -> chave da API do Resend (dashboard do Resend)
#   NOTIFY_EMAIL    -> seu e-mail, para receber aviso de novo cadastro
# ------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
NOTIFY_EMAIL = os.environ.get("NOTIFY_EMAIL", "")


def save_email(email: str):
    """Salva o e-mail na tabela gatekeeper_waitlist. Retorna (sucesso, detalhe_do_erro)."""
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO gatekeeper_waitlist (email)
                    VALUES (%s)
                    ON CONFLICT (email) DO NOTHING;
                    """,
                    (email,),
                )
            conn.commit()
        return True, None
    except Exception as e:
        print(f"Erro ao salvar no banco: {e}", file=sys.stderr, flush=True)
        return False, str(e)


@app.route("/", methods=["GET"])
def health():
    """Rota simples para o Render confirmar que o serviço está no ar."""
    return jsonify({"status": "ok", "service": "gatekeeper-mail-waitlist"})


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").strip().lower()

    if not email or "@" not in email or "." not in email:
        return jsonify({"ok": False, "error": "E-mail inválido"}), 400

    if not DATABASE_URL:
        return jsonify({"ok": False, "error": "Backend ainda não configurado (falta DATABASE_URL)"}), 500

    ok, error_detail = save_email(email)
    if not ok:
        # O detalhe técnico do erro já é registrado nos Logs do Render
        # (dentro da função save_email) — não é mais exposto na resposta
        # pública, por segurança.
        return jsonify({
            "ok": False,
            "error": "Não foi possível salvar o cadastro",
        }), 500

    # Envia e-mail de confirmação para quem se cadastrou (via Resend)
    #    "onboarding@resend.dev" funciona sem precisar verificar domínio próprio,
    #    MAS só entrega para o e-mail que você usou para criar a conta no Resend,
    #    até que um domínio próprio seja verificado. Ver Resend > Domains.
    if RESEND_API_KEY:
        try:
            resend_resp = requests.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": "Gatekeeper Mail <onboarding@resend.dev>",
                    "to": [email],
                    "subject": "Você entrou na lista de espera do Gatekeeper Mail",
                    "html": (
                        "<p>Recebemos seu cadastro.</p>"
                        "<p>Assim que o grupo piloto abrir, avisamos você por aqui.</p>"
                    ),
                },
                timeout=10,
            )
            if resend_resp.status_code >= 400:
                print(f"Resend recusou o envio: {resend_resp.status_code} {resend_resp.text}", file=sys.stderr, flush=True)
        except requests.RequestException as e:
            print(f"Erro de rede ao chamar o Resend: {e}", file=sys.stderr, flush=True)

        # Avisa você (o idealizador) que chegou um novo cadastro
        if NOTIFY_EMAIL:
            try:
                notify_resp = requests.post(
                    "https://api.resend.com/emails",
                    headers={
                        "Authorization": f"Bearer {RESEND_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "from": "Gatekeeper Mail <onboarding@resend.dev>",
                        "to": [NOTIFY_EMAIL],
                        "subject": "Novo cadastro na lista de espera — Gatekeeper Mail",
                        "html": f"<p>Novo e-mail cadastrado: {email}</p>",
                    },
                    timeout=10,
                )
                if notify_resp.status_code >= 400:
                    print(f"Resend recusou o aviso: {notify_resp.status_code} {notify_resp.text}", file=sys.stderr, flush=True)
            except requests.RequestException as e:
                print(f"Erro de rede ao chamar o Resend (aviso): {e}", file=sys.stderr, flush=True)

    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
