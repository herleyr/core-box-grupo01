"""Login, recuperação de senha e troca de celular (versão corrigida)."""
import datetime
import secrets

from flask import Blueprint, render_template, request, make_response, jsonify, redirect, current_app

from app import auditoria
from app.db import get_db
from app.seguranca import verificar_senha, emitir_token, hash_senha, set_cookie_sessao

bp = Blueprint("auth", __name__)
MSG_GENERICA = "CPF ou senha inválidos."


def _bloqueado(db, cpf):
    row = db.execute("SELECT bloqueado_ate FROM tentativas_login WHERE cpf = ?", (cpf,)).fetchone()
    return bool(row and row["bloqueado_ate"] and row["bloqueado_ate"] > datetime.datetime.now().isoformat())


def _registrar_falha(db, cpf):
    db.execute("INSERT INTO tentativas_login (cpf, falhas) VALUES (?, 1) "
               "ON CONFLICT(cpf) DO UPDATE SET falhas = falhas + 1", (cpf,))
    falhas = db.execute("SELECT falhas FROM tentativas_login WHERE cpf = ?", (cpf,)).fetchone()["falhas"]
    if falhas >= current_app.config["MAX_TENTATIVAS_LOGIN"]:
        ate = datetime.datetime.now() + datetime.timedelta(minutes=current_app.config["BLOQUEIO_MINUTOS"])
        db.execute("UPDATE tentativas_login SET bloqueado_ate = ?, falhas = 0 WHERE cpf = ?", (ate.isoformat(), cpf))
        auditoria.evento_seguranca(cpf, "LOGIN_BLOQUEADO", {"cpf": cpf, "ip": request.remote_addr})
    db.commit()


def _autenticar(cpf, senha):
    """Retorna (usuario, erro, status_http)."""
    db = get_db()
    # TM-01: bloqueio progressivo por CPF
    if _bloqueado(db, cpf):
        return None, "Muitas tentativas. Tente novamente mais tarde.", 429
    usuario = db.execute("SELECT * FROM usuarios WHERE cpf = ?", (cpf,)).fetchone()
    # TM-23: verificação sempre executada (tempo constante) e mensagem única
    ok = verificar_senha(senha, usuario["senha_hash"] if usuario else None)
    if not usuario or not ok:
        _registrar_falha(db, cpf)
        return None, MSG_GENERICA, 401
    db.execute("DELETE FROM tentativas_login WHERE cpf = ?", (cpf,))
    db.commit()
    return usuario, None, 200


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    cpf = request.form.get("cpf", "").strip()
    usuario, erro, status = _autenticar(cpf, request.form.get("senha", ""))
    if erro:
        return render_template("login.html", erro=erro, cpf=cpf), status
    auditoria.registrar(usuario["id"], "LOGIN_OK", {"ip": request.remote_addr})
    resp = make_response(redirect("/home"))
    set_cookie_sessao(resp, emitir_token(usuario))
    return resp


@bp.route("/api/v1/auth/login", methods=["POST"])
def api_login():
    dados = request.get_json(silent=True) or {}
    usuario, erro, status = _autenticar(str(dados.get("cpf", "")), str(dados.get("senha", "")))
    if erro:
        return jsonify({"erro": erro}), status
    auditoria.registrar(usuario["id"], "LOGIN_API_OK", {"ip": request.remote_addr})
    return jsonify({"token": emitir_token(usuario), "tipo": "Bearer",
                    "expira_em_minutos": current_app.config["JWT_EXPIRACAO_MINUTOS"]})


@bp.route("/logout")
def logout():
    resp = make_response(redirect("/login"))
    resp.delete_cookie("box_token")
    return resp


@bp.route("/recuperar", methods=["GET", "POST"])
def recuperar():
    # TM-02: o fluxo completo (fator de posse + biometria) é tratado no Dia 03; aqui endurecemos o OTP
    if request.method == "GET":
        return render_template("recuperar.html", etapa="dados")
    db = get_db()
    cpf = request.form.get("cpf", "").strip()
    usuario = db.execute("SELECT * FROM usuarios WHERE cpf = ? AND nascimento = ?",
                         (cpf, request.form.get("nascimento", "").strip())).fetchone()
    if usuario:
        codigo = f"{secrets.randbelow(10**6):06d}"
        expira = (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat()
        db.execute("INSERT OR REPLACE INTO otp (cpf, codigo, expira_em) VALUES (?,?,?)", (cpf, hash_senha(codigo), expira))
        db.commit()
        auditoria.registrar(usuario["id"], "OTP_ENVIADO", {})
    # Mesma resposta exista ou não o cliente; telefone mascarado
    return render_template("recuperar.html", etapa="codigo", cpf=cpf, celular="(**) *****-**** cadastrado")


@bp.route("/recuperar/confirmar", methods=["POST"])
def recuperar_confirmar():
    db = get_db()
    cpf = request.form.get("cpf", "")
    otp = db.execute("SELECT * FROM otp WHERE cpf = ?", (cpf,)).fetchone()
    valido = otp and otp["expira_em"] > datetime.datetime.now().isoformat() and \
        verificar_senha(request.form.get("codigo", ""), otp["codigo"])
    if not valido:
        _registrar_falha(db, "otp:" + cpf)
        return render_template("recuperar.html", etapa="codigo", cpf=cpf, erro="Código inválido ou expirado."), 400
    db.execute("UPDATE usuarios SET senha_hash = ? WHERE cpf = ?", (hash_senha(request.form.get("nova_senha", "")), cpf))
    db.execute("DELETE FROM otp WHERE cpf = ?", (cpf,))
    db.commit()
    return render_template("recuperar.html", etapa="ok")


@bp.route("/recuperar/trocar-celular", methods=["POST"])
def trocar_celular():
    # TM-02 (T2-D): troca de celular não é mais autosserviço com dados cadastrais
    return render_template("recuperar.html", etapa="dados",
                           info="Por segurança, a troca de celular é feita no app com biometria ou em uma agência."), 403
