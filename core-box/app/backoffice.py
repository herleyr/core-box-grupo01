"""Backoffice das agências (versão corrigida)."""
import csv
import datetime
import io
import re
import subprocess

from flask import Blueprint, render_template, request, g, make_response, redirect, Response, current_app, jsonify

from app import auditoria
from app.db import get_db
from app.seguranca import login_obrigatorio, verificar_senha, emitir_token, set_cookie_sessao, mascarar_cpf

bp = Blueprint("backoffice", __name__, url_prefix="/backoffice")
HOST_VALIDO = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")


def _quer_json():
    return request.headers.get("Accept") == "application/json"


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("backoffice/login.html")
    u = get_db().execute("SELECT * FROM usuarios WHERE nome = ? AND perfil = 'operador'",
                         (request.form.get("usuario", ""),)).fetchone()
    if not verificar_senha(request.form.get("senha", ""), u["senha_hash"] if u else None) or not u:
        return render_template("backoffice/login.html", erro="Credenciais inválidas"), 401
    resp = make_response(redirect("/backoffice"))
    set_cookie_sessao(resp, emitir_token(u))
    return resp


@bp.route("")
@login_obrigatorio(perfil="operador")
def painel():
    termo = request.args.get("q", "")
    db = get_db()
    clientes = []
    if termo:
        # TM-29: consulta parametrizada; dados mínimos, CPF mascarado, sem hash de senha
        rows = db.execute("SELECT u.nome, u.cpf, c.numero, c.saldo FROM usuarios u JOIN contas c ON c.usuario_id = u.id"
                          " WHERE u.nome LIKE ? OR u.cpf = ? LIMIT 20", (f"%{termo}%", termo)).fetchall()
        clientes = [{"nome": r["nome"], "cpf": mascarar_cpf(r["cpf"]), "numero": r["numero"], "saldo": r["saldo"],
                     "senha_hash": "—"} for r in rows]
    eventos = db.execute("SELECT * FROM auditoria ORDER BY id DESC LIMIT 15").fetchall()
    total = db.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
    return render_template("backoffice/painel.html", usuario=g.usuario, clientes=clientes, termo=termo,
                           eventos=eventos, total=total)


@bp.route("/ajuste", methods=["POST"])
@login_obrigatorio(perfil="operador")
def ajuste():
    db = get_db()
    conta = request.form.get("conta", "")
    tipo = request.form.get("tipo", "")
    justificativa = request.form.get("justificativa", "").strip()
    try:
        valor = float(request.form.get("valor", ""))
    except ValueError:
        valor = -1
    if tipo not in ("credito", "debito") or valor <= 0 or len(justificativa) < 5:
        return (jsonify({"erro": "Informe conta, tipo, valor positivo e justificativa."}), 400) if _quer_json() \
            else redirect("/backoffice")
    agora = datetime.datetime.now().isoformat(timespec="seconds")
    # TM-10: acima da alçada, fica pendente de aprovação de OUTRO operador (maker-checker)
    if valor > current_app.config["ALCADA_AJUSTE"]:
        db.execute("INSERT INTO ajustes_pendentes (conta, tipo, valor, justificativa, solicitante, criado_em)"
                   " VALUES (?,?,?,?,?,?)", (conta, tipo, valor, justificativa, g.usuario["nome"], agora))
        db.commit()
        auditoria.evento_seguranca(g.usuario["nome"], "AJUSTE_ACIMA_ALCADA", {"conta": conta, "valor": valor})
        return (jsonify({"status": "pendente_aprovacao"}), 202) if _quer_json() else redirect("/backoffice")
    sinal = 1 if tipo == "credito" else -1
    db.execute("UPDATE contas SET saldo = saldo + ? WHERE numero = ?", (sinal * valor, conta))
    db.commit()
    auditoria.registrar(g.usuario["nome"], "AJUSTE_SALDO",
                        {"conta": conta, "tipo": tipo, "valor": valor, "justificativa": justificativa})
    return (jsonify({"status": "efetivado", "conta": conta, "valor": valor}), 200) if _quer_json() \
        else redirect("/backoffice")

# TM-11: rota de "limpar auditoria" REMOVIDA. Retenção e expurgo são feitos pela plataforma de logs (WORM).


@bp.route("/exportar")
@login_obrigatorio(perfil="operador")
def exportar():
    # TM-12: sem hash de senha; CPF mascarado; exportação limitada e auditada
    rows = get_db().execute("SELECT u.nome, u.cpf, c.numero FROM usuarios u JOIN contas c ON c.usuario_id = u.id"
                            " LIMIT 500").fetchall()
    auditoria.evento_seguranca(g.usuario["nome"], "EXPORTACAO_CLIENTES", {"linhas": len(rows)})
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["nome", "cpf", "conta"])
    for r in rows:
        w.writerow([r["nome"], mascarar_cpf(r["cpf"]), r["numero"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=clientes.csv"})


@bp.route("/diagnostico")
@login_obrigatorio(perfil="operador")
def diagnostico():
    host = request.args.get("host", "")
    # CWE-78 corrigido: validação estrita + lista de argumentos, sem shell
    if not HOST_VALIDO.match(host) or host.startswith("-"):
        return Response("host inválido", status=400, mimetype="text/plain")
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "2", host], capture_output=True, text=True, timeout=5)
        saida = r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        saida = "ferramenta indisponível"
    return Response(saida or "sem resposta", mimetype="text/plain")
