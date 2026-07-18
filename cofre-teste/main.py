import os
import imaplib
import psycopg
from flask import Flask, jsonify, request
from flask_cors import CORS
import cofre

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

DATABASE_URL = os.environ.get("DATABASE_URL", "")

PADROES_POR_PROVEDOR = {
    "gmail": {
        "imap_host": "imap.gmail.com",
        "quarentena_geral": "Quarentena.Geral",
        "quarentena_institucional": "Quarentena.Alerta-Institucional",
        "sent_folder": "[Gmail]/E-mails enviados",
    },
    "outlook": {
        "imap_host": "outlook.office365.com",
        "quarentena_geral": "Quarentena.Geral",
        "quarentena_institucional": "Quarentena.Alerta-Institucional",
        "sent_folder": "Sent Items",
    },
    "locaweb": {
        "imap_host": "email-ssl.com.br",
        "quarentena_geral": "INBOX.Quarentena.Geral",
        "quarentena_institucional": "INBOX.Quarentena.Alerta-Institucional",
        "sent_folder": "INBOX.enviadas",
    },
    "outro": {
        "imap_host": "",
        "quarentena_geral": "Quarentena.Geral",
        "quarentena_institucional": "Quarentena.Alerta-Institucional",
        "sent_folder": "",
    },
}


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "gatekeeper-cofre-teste"})


@app.route("/testar-doppler", methods=["GET"])
def testar_doppler():
    """Testa SÓ a Camada 1 — buscar a chave no Doppler e criptografar/decifrar um texto de teste."""
    try:
        texto = "teste-de-criptografia-123"
        cifrado = cofre.criptografar_camada1(texto)
        decifrado = cofre.descriptografar_camada1(cifrado)
        return jsonify({
            "ok": True,
            "texto_original": texto,
            "cifrado_camada1": cifrado,
            "decifrado_de_volta": decifrado,
            "bateu": texto == decifrado,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/testar-vault-completo", methods=["GET"])
def testar_vault_completo():
    """Testa as DUAS camadas juntas: guarda uma senha de teste e recupera de volta."""
    if not DATABASE_URL:
        return jsonify({"ok": False, "error": "Falta DATABASE_URL"}), 500
    try:
        identificador = "conta_de_teste_1"
        senha_teste = "senha-app-de-teste-abc123"

        resultado_guardar = cofre.guardar_credencial_email(DATABASE_URL, identificador, senha_teste)
        senha_recuperada = cofre.obter_credencial_email(DATABASE_URL, identificador)

        return jsonify({
            "ok": True,
            "id_gerado_no_vault": str(resultado_guardar),
            "senha_original": senha_teste,
            "senha_recuperada_apos_as_duas_camadas": senha_recuperada,
            "bateu": senha_teste == senha_recuperada,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/contas/cadastrar", methods=["POST"])
def cadastrar_conta():
    """
    Cadastra uma nova conta de e-mail de verdade:
    1) Testa a conexão IMAP antes de qualquer coisa (nunca salva credencial não testada).
    2) Guarda a senha protegida pelas duas camadas do cofre (Doppler + Supabase Vault).
    3) Guarda os metadados da conta (e-mail, pastas, provedor) na tabela gatekeeper_contas.
    """
    if not DATABASE_URL:
        return jsonify({"ok": False, "error": "DATABASE_URL não configurado"}), 500

    dados = request.get_json(silent=True) or {}
    email_conta = (dados.get("email") or "").strip().lower()
    senha_app = dados.get("senha_app") or ""
    provedor = (dados.get("provedor") or "outro").strip().lower()

    if not email_conta or not senha_app:
        return jsonify({"ok": False, "error": "Informe 'email' e 'senha_app'"}), 400

    padrao = PADROES_POR_PROVEDOR.get(provedor, PADROES_POR_PROVEDOR["outro"])
    imap_host = dados.get("imap_host") or padrao["imap_host"]
    quarentena_geral = dados.get("quarentena_geral") or padrao["quarentena_geral"]
    quarentena_institucional = dados.get("quarentena_institucional") or padrao["quarentena_institucional"]
    sent_folder = dados.get("sent_folder") or padrao["sent_folder"]

    if not imap_host:
        return jsonify({"ok": False, "error": "Informe 'imap_host' para este provedor"}), 400

    # PASSO 1 — testa a conexão de verdade antes de guardar qualquer coisa.
    try:
        imap = imaplib.IMAP4_SSL(imap_host, 993, timeout=15)
        imap.login(email_conta, senha_app)
        imap.logout()
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": f"Não foi possível conectar com essas credenciais: {e}",
            "dica": "Confira o e-mail, a senha de app e o servidor IMAP antes de tentar de novo.",
        }), 400

    # PASSO 2 — guarda a senha protegida pelas duas camadas do cofre.
    try:
        cofre.guardar_credencial_email(DATABASE_URL, email_conta, senha_app)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Conexão OK, mas falhou ao guardar a credencial no cofre: {e}"}), 500

    # PASSO 3 — guarda os metadados da conta (nunca a senha em si) na tabela de contas.
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO gatekeeper_contas
                        (email, provedor, imap_host, quarentena_geral, quarentena_institucional, sent_folder, ativa)
                    VALUES (%s, %s, %s, %s, %s, %s, true)
                    ON CONFLICT (email) DO UPDATE SET
                        provedor = EXCLUDED.provedor,
                        imap_host = EXCLUDED.imap_host,
                        quarentena_geral = EXCLUDED.quarentena_geral,
                        quarentena_institucional = EXCLUDED.quarentena_institucional,
                        sent_folder = EXCLUDED.sent_folder,
                        ativa = true;
                    """,
                    (email_conta, provedor, imap_host, quarentena_geral, quarentena_institucional, sent_folder),
                )
            conn.commit()
    except Exception as e:
        return jsonify({"ok": False, "error": f"Credencial guardada, mas falhou ao registrar a conta: {e}"}), 500

    return jsonify({
        "ok": True,
        "mensagem": f"Conta {email_conta} conectada e protegida com sucesso.",
        "conta": {
            "email": email_conta,
            "provedor": provedor,
            "imap_host": imap_host,
            "quarentena_geral": quarentena_geral,
            "quarentena_institucional": quarentena_institucional,
        },
    })


@app.route("/contas/listar", methods=["GET"])
def listar_contas():
    """Lista as contas cadastradas (nunca expõe a senha — ela fica só no cofre)."""
    if not DATABASE_URL:
        return jsonify({"ok": False, "error": "DATABASE_URL não configurado"}), 500
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT email, provedor, ativa, criada_em FROM gatekeeper_contas ORDER BY criada_em DESC;"
                )
                linhas = cur.fetchall()
        contas = [
            {"email": e, "provedor": p, "ativa": a, "criada_em": str(c)}
            for (e, p, a, c) in linhas
        ]
        return jsonify({"ok": True, "total": len(contas), "contas": contas})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
