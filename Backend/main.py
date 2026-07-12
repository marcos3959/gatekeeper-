import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

app = Flask(__name__)
CORS(app, resources={r"/signup": {"origins": "*"}})

# ------------------------------------------------------------------
# Variáveis de ambiente (configure no painel do Render, em "Environment"):
#   SUPABASE_URL          -> ex: https://xxxxxxxx.supabase.co
#   SUPABASE_SERVICE_KEY  -> chave "service_role" do Supabase (Settings > API)
#   RESEND_API_KEY        -> chave da API do Resend (dashboard do Resend)
#   NOTIFY_EMAIL          -> seu e-mail, para receber aviso de novo cadastro
# ------------------------------------------------------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
NOTIFY_EMAIL = os.environ.get("NOTIFY_EMAIL", "")


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

    if not SUPABASE_URL or not SUPABASE_KEY:
        return jsonify({"ok": False, "error": "Backend ainda não configurado (faltam variáveis do Supabase)"}), 500

    # 1) Salva o cadastro no Supabase (tabela "waitlist" — ver schema.sql)
    try:
        supa_resp = requests.post(
            f"{SUPABASE_URL}/rest/v1/waitlist",
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "application/json",
                "Prefer": "resolution=ignore-duplicates,return=minimal",
            },
            json={"email": email},
            timeout=10,
        )
    except requests.RequestException:
        return jsonify({"ok": False, "error": "Falha ao conectar com o banco de dados"}), 502

    if supa_resp.status_code not in (200, 201, 204, 409):
        return jsonify({"ok": False, "error": "Não foi possível salvar o cadastro"}), 500

    # 2) Envia e-mail de confirmação para quem se cadastrou (via Resend)
    #    "onboarding@resend.dev" funciona sem precisar verificar domínio próprio —
    #    ótimo para esta fase de teste. Depois, troque pelo seu domínio verificado.
    if RESEND_API_KEY:
        try:
            requests.post(
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
        except requests.RequestException:
            pass  # não travar o cadastro por causa do e-mail de confirmação

        # 3) Avisa você (o idealizador) que chegou um novo cadastro
        if NOTIFY_EMAIL:
            try:
                requests.post(
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
            except requests.RequestException:
                pass

    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
