"""Endpoint interno (versão corrigida): assinatura sempre verificada."""
import jwt
from flask import Blueprint, request, jsonify

from app.seguranca import decodificar_token

bp = Blueprint("interna", __name__, url_prefix="/api/v1/interno")


@bp.route("/token-info")
def token_info():
    try:
        dados = decodificar_token(request.args.get("token", ""))  # TM-16: verifica assinatura, iss e aud
    except jwt.PyJWTError:
        return jsonify({"erro": "token inválido"}), 401
    return jsonify({"sub": dados["sub"], "perfil": dados["perfil"], "exp": dados["exp"]})
