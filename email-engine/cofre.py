import os
import base64
import requests
import psycopg
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ------------------------------------------------------------------
# CAMADA 1 — chave guardada no Doppler (separado do Render)
# Usa AES-256-GCM diretamente: os 256 bits inteiros da chave são usados
# na criptografia (diferente da técnica anterior, Fernet, que dividia a
# chave em duas metades de 128 bits — uma para cifrar, outra para
# autenticar). GCM já garante autenticidade nativamente, com os 256 bits
# completos dedicados à cifra em si.
# ------------------------------------------------------------------
_chave_em_cache = None


def _buscar_chave_mestra_base64():
    """Busca a chave mestra da Camada 1 no Doppler (texto base64, como foi gerada)."""
    global _chave_em_cache
    if _chave_em_cache:
        return _chave_em_cache

    token = os.environ.get("DOPPLER_SERVICE_TOKEN", "")
    if not token:
        raise RuntimeError("DOPPLER_SERVICE_TOKEN não configurado")

    resp = requests.get(
        "https://api.doppler.com/v3/configs/config/secret",
        params={"name": "CHAVE_MESTRA_CAMADA1"},
        auth=(token, ""),
        timeout=10,
    )
    resp.raise_for_status()
    valor = resp.json()["value"]["raw"]
    _chave_em_cache = valor.encode() if isinstance(valor, str) else valor
    return _chave_em_cache


def _obter_chave_256_bits() -> bytes:
    """Decodifica a chave (que vem em base64) para os 32 bytes (256 bits) reais."""
    chave_base64 = _buscar_chave_mestra_base64()
    return base64.urlsafe_b64decode(chave_base64)


def criptografar_camada1(texto_plano: str) -> str:
    """Criptografa um texto com AES-256-GCM, usando os 256 bits completos da chave do Doppler."""
    chave = _obter_chave_256_bits()
    aesgcm = AESGCM(chave)
    nonce = os.urandom(12)  # valor aleatório de uso único, recomendado para GCM
    cifrado = aesgcm.encrypt(nonce, texto_plano.encode(), None)
    # Guarda o 'nonce' junto com o resultado cifrado (precisa dele para decifrar depois)
    return base64.urlsafe_b64encode(nonce + cifrado).decode()


def descriptografar_camada1(texto_cifrado: str) -> str:
    """Reverte a criptografia AES-256-GCM da Camada 1."""
    chave = _obter_chave_256_bits()
    dados = base64.urlsafe_b64decode(texto_cifrado.encode())
    nonce, cifrado = dados[:12], dados[12:]
    aesgcm = AESGCM(chave)
    texto_plano = aesgcm.decrypt(nonce, cifrado, None)
    return texto_plano.decode()


# ------------------------------------------------------------------
# CAMADA 2 — Supabase Vault (guarda o resultado já cifrado da Camada 1)
# ------------------------------------------------------------------

def guardar_no_vault(database_url: str, nome_unico: str, valor_ja_cifrado: str, descricao: str = ""):
    """
    Guarda um valor (já cifrado pela Camada 1) dentro do Supabase Vault.
    Se já existir um segredo com esse mesmo nome, ATUALIZA em vez de tentar
    criar de novo (importante para quando o usuário troca a senha de app
    de uma conta que já estava cadastrada).
    """
    with psycopg.connect(database_url, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute("select id from vault.secrets where name = %s;", (nome_unico,))
            existente = cur.fetchone()

            if existente:
                secret_id = existente[0]
                cur.execute(
                    "select vault.update_secret(%s, %s, %s, %s);",
                    (secret_id, valor_ja_cifrado, nome_unico, descricao),
                )
                resultado = (secret_id,)
            else:
                cur.execute(
                    "select vault.create_secret(%s, %s, %s);",
                    (valor_ja_cifrado, nome_unico, descricao),
                )
                resultado = cur.fetchone()
        conn.commit()
    return resultado[0] if resultado else None


def buscar_do_vault(database_url: str, nome_unico: str):
    """Busca (e decifra a Camada 2 automaticamente) um valor guardado no Vault."""
    with psycopg.connect(database_url, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select decrypted_secret from vault.decrypted_secrets where name = %s;",
                (nome_unico,),
            )
            linha = cur.fetchone()
    return linha[0] if linha else None


def atualizar_no_vault(database_url: str, nome_unico: str, novo_valor_ja_cifrado: str):
    """Atualiza um segredo já existente no Vault (pelo nome)."""
    with psycopg.connect(database_url, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select vault.update_secret(id, %s) from vault.secrets where name = %s;",
                (novo_valor_ja_cifrado, nome_unico),
            )
        conn.commit()


# ------------------------------------------------------------------
# FUNÇÕES DE ALTO NÍVEL — o que o resto do sistema deve usar
# ------------------------------------------------------------------

def guardar_credencial_email(database_url: str, identificador_conta: str, senha_app_texto_plano: str):
    """
    Guarda a senha de app de uma conta de e-mail, protegida em duas camadas:
    1) Criptografada com a chave do Doppler.
    2) O resultado já cifrado é guardado dentro do Supabase Vault.
    """
    cifrado_camada1 = criptografar_camada1(senha_app_texto_plano)
    nome_unico = f"gatekeeper_senha_conta_{identificador_conta}"
    return guardar_no_vault(
        database_url, nome_unico, cifrado_camada1,
        descricao=f"Senha de app — conta {identificador_conta}",
    )


def obter_credencial_email(database_url: str, identificador_conta: str):
    """Recupera e decifra (das duas camadas) a senha de app de uma conta de e-mail."""
    nome_unico = f"gatekeeper_senha_conta_{identificador_conta}"
    cifrado_camada1 = buscar_do_vault(database_url, nome_unico)
    if cifrado_camada1 is None:
        return None
    return descriptografar_camada1(cifrado_camada1)
