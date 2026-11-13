"""Abertura de conta / KYC (versão corrigida)."""
import os
import uuid

from flask import Blueprint, render_template, request, current_app, send_from_directory, abort

from app import auditoria
from app.seguranca import login_obrigatorio

bp = Blueprint("onboarding", __name__)
ASSINATURAS = {b"\x89PNG\r\n\x1a\n": ".png", b"\xff\xd8\xff": ".jpg", b"%PDF-": ".pdf"}


def _extensao_por_conteudo(cabecalho):
    for magia, ext in ASSINATURAS.items():
        if cabecalho.startswith(magia):
            return ext
    return None


@bp.route("/abrir-conta", methods=["GET", "POST"])
def abrir_conta():
    if request.method == "GET":
        return render_template("abrir_conta.html")
    os.makedirs(current_app.config["UPLOAD_DIR"], exist_ok=True)
    recebidos = 0
    for campo in ("documento", "selfie"):
        arq = request.files.get(campo)
        if arq is None or arq.filename == "":
            continue
        ext = _extensao_por_conteudo(arq.stream.read(8))
        arq.stream.seek(0)
        if ext is None:  # TM-28: tipo validado pelo conteúdo (magic bytes)
            return render_template("abrir_conta.html", erro="Formato não aceito (PNG, JPG ou PDF)."), 400
        nome = uuid.uuid4().hex + ext  # nunca o nome enviado pelo usuário
        arq.save(os.path.join(current_app.config["UPLOAD_DIR"], nome))
        recebidos += 1
    auditoria.registrar("onboarding", "KYC_UPLOAD", {"arquivos": recebidos})
    return render_template("abrir_conta.html", enviados=["documento recebido"] * recebidos)


@bp.route("/uploads/<nome>")
@login_obrigatorio(perfil="operador")
def ver_upload(nome):
    # TM-09: apenas operadores autenticados; send_from_directory impede path traversal
    if not nome.replace(".", "").isalnum():
        abort(404)
    return send_from_directory(current_app.config["UPLOAD_DIR"], nome, as_attachment=True)
