"""Funções de segurança do Core Box (versão corrigida)."""
import datetime
import functools

import jwt
from flask import current_app, g, request, jsonify, redirect
from werkzeug.security import generate_password_hash, check_password_hash

from app.db import get_db

# Hash "isca" para equalizar o tempo de resposta quando o CPF não existe (TM-23)
_HASH_ISCA = generate_password_hash("senha-isca-que-nunca-confere")


def hash_senha(senha):
    # TM-12: KDF lenta com salt (scrypt/pbkdf2 conforme versão do Werkzeug)
    return generate_password_hash(senha)


def verificar_senha(senha, senha_hash):
    return check_password_hash(senha_hash or _HASH_ISCA, senha)


def emitir_token(usuario):
    agora = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": str(usuario["id"]),
        "perfil": usuario["perfil"],  # TM-06: sem CPF/nome no token
        "iss": current_app.config["JWT_ISSUER"],
        "aud": current_app.config["JWT_AUDIENCE"],
        "iat": agora,
        "exp": agora + datetime.timedelta(minutes=current_app.config["JWT_EXPIRACAO_MINUTOS"]),
    }
    token = jwt.encode(payload, current_app.config["JWT_SECRET"], algorithm="HS256")
    return token.decode() if isinstance(token, bytes) else token


def decodificar_token(token):
    return jwt.decode(token, current_app.config["JWT_SECRET"], algorithms=["HS256"],
                      audience=current_app.config["JWT_AUDIENCE"], issuer=current_app.config["JWT_ISSUER"])


def _token_da_requisicao():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.cookies.get("box_token")


def usuario_atual():
    token = _token_da_requisicao()
    if not token:
        return None
    try:
        dados = decodificar_token(token)
    except jwt.PyJWTError:
        return None
    return get_db().execute("SELECT * FROM usuarios WHERE id = ?", (int(dados["sub"]),)).fetchone()


def set_cookie_sessao(resp, token):
    resp.set_cookie("box_token", token, httponly=True, samesite="Strict",
                    secure=current_app.config["COOKIE_SECURE"],
                    max_age=current_app.config["JWT_EXPIRACAO_MINUTOS"] * 60)


def mascarar_cpf(cpf):
    # 987.654.321-00 -> ***.654.321-**
    return "***" + cpf[3:12] + "**" if cpf and len(cpf) == 14 else "***"


def login_obrigatorio(perfil=None, api=False):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            usuario = usuario_atual()
            if usuario is None or (perfil and usuario["perfil"] != perfil):
                if api or request.path.startswith("/api/"):
                    return jsonify({"erro": "não autenticado"}), 401
                destino = "/backoffice/login" if request.path.startswith("/backoffice") else "/login"
                return redirect(destino)
            g.usuario = usuario
            return fn(*args, **kwargs)
        return wrapper
    return deco
