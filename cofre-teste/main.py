import os
from flask import Flask, jsonify, request
import cofre

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "")


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
