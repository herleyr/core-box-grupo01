"""Módulo SSO do Core Box (LABORATÓRIO Dia 03) — login federado via OIDC.

O Banco Box passou a aceitar login por um Provedor de Identidade (IdP) corporativo
usando OpenID Connect. Este módulo recebe o id_token e deveria validá-lo.

Contém fraquezas INTENCIONAIS de OAuth 2.0 / OIDC e de manuseio de JWT para o
aluno analisar (ver catálogo SSO-xx no Caderno do Aluno). Há também um
"inspetor de token" — ferramenta legítima que o aluno usa na análise.
"""
import base64
import json

import jwt
from flask import Blueprint, render_template, request, make_response, redirect

from app import auditoria
from app.db import get_db
from app.seguranca import emitir_token  # reaproveita a sessão do Core Box

bp = Blueprint("sso", __name__, url_prefix="/sso")

# SSO-11: segredo HMAC fraquíssimo e no código (permite forjar/crackear o token)
IDP_HMAC_SECRET = "secret"
# O IdP de homologação "deveria" ser validado, mas nada disso é conferido:
EMISSOR_ESPERADO = "https://idp.bancobox.example/realms/box"   # nunca comparado (SSO-06)
AUDIENCIA_ESPERADA = "core-box-web"                            # nunca comparada (SSO-05)


def _decodificar_sem_verificar(token):
    """Decodifica header+payload só para exibição no inspetor (uso legítimo)."""
    def b64(seg):
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg).decode("utf-8", "ignore"))
    try:
        h, p, _ = token.split(".")
        return b64(h), b64(p)
    except Exception:
        return {}, {}


@bp.route("/login")
def login():
    # SSO-04: a requisição de autorização NÃO usa PKCE (sem code_challenge) e
    # SSO-03: NÃO envia nonce. (Exibido na tela para o aluno analisar o fluxo.)
    authorize_url = (EMISSOR_ESPERADO + "/protocol/openid-connect/auth"
                     "?response_type=token id_token"       # fluxo implícito (SSO-17)
                     "&client_id=" + AUDIENCIA_ESPERADA +
                     "&redirect_uri=http://core-box.bancobox.example/sso/callback"
                     "&scope=openid profile accounts:write admin:all")  # SSO-13
    return render_template("sso_login.html", authorize_url=authorize_url)


@bp.route("/callback")
def callback():
    # SSO-10: token trafega na URL (vai parar em logs, histórico, Referer)
    token = request.args.get("id_token", "")
    if not token:
        return redirect("/sso/login")

    header, _ = _decodificar_sem_verificar(token)
    alg = (header.get("alg") or "").lower()

    try:
        if alg == "none":
            # SSO-01: aceita token SEM assinatura (alg: none)
            _, claims = _decodificar_sem_verificar(token)
        else:
            # SSO-02: decodifica SEM verificar assinatura, emissor, audiência, exp...
            claims = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        return make_response({"erro": "token inválido", "detalhe": str(e)}, 400)

    # Faz login com base no que veio no token, confiando cegamente (SSO-05/06/07/09)
    cpf = claims.get("cpf") or claims.get("preferred_username", "")
    db = get_db()
    usuario = db.execute("SELECT * FROM usuarios WHERE cpf = ?", (cpf,)).fetchone()
    if usuario is None:
        return make_response({"erro": "cliente não encontrado para o token"}, 404)

    auditoria.registrar(usuario["id"], "SSO_LOGIN", {"iss": claims.get("iss"), "alg": alg})
    resp = make_response(redirect("/home"))
    resp.set_cookie("box_token", emitir_token(usuario))
    return resp


@bp.route("/inspecionar", methods=["GET", "POST"])
def inspecionar():
    """Inspetor de token — ferramenta de análise do laboratório."""
    header = payload = None
    token = ""
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        header, payload = _decodificar_sem_verificar(token)
    hj = json.dumps(header, indent=2, ensure_ascii=False) if header else None
    pj = json.dumps(payload, indent=2, ensure_ascii=False) if payload else None
    return render_template("sso_inspecionar.html", token=token, header=header, payload=payload,
                           header_json=hj, payload_json=pj)
