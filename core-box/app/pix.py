"""Pix (versão corrigida)."""
import datetime
import logging
from decimal import Decimal, InvalidOperation

from flask import Blueprint, render_template, request, g, jsonify, redirect

from app import antifraude, auditoria, psti_client
from app.contas import conta_do_usuario
from app.db import get_db
from app.seguranca import login_obrigatorio, mascarar_cpf

bp = Blueprint("pix", __name__)
log = logging.getLogger("box.pix")


class ErroPix(Exception):
    def __init__(self, mensagem, status=422):
        super().__init__(mensagem)
        self.mensagem = mensagem
        self.status = status


def _limite_vigente(conta, agora=None):
    agora = agora or datetime.datetime.now()
    noturno = agora.hour >= 20 or agora.hour < 6
    return conta["limite_noturno"] if noturno else conta["limite_diurno"]


def _valor(bruto):
    try:
        v = Decimal(str(bruto).replace(",", "."))
    except (InvalidOperation, ValueError):
        raise ErroPix("Valor inválido.", 400)
    if not v.is_finite() or v <= 0 or v.as_tuple().exponent < -2:
        raise ErroPix("Valor inválido.", 400)
    return float(v)


def executar_pix(usuario, dados, idempotency_key=None):
    db = get_db()
    # TM-03: a conta de origem é SEMPRE a do usuário autenticado
    origem = conta_do_usuario(usuario["id"])
    informada = dados.pop("conta_origem", None)
    if informada and informada != origem["numero"]:
        auditoria.evento_seguranca(usuario["id"], "BOLA_ATTEMPT", {"conta_informada": informada})
        raise ErroPix("Operação não permitida.", 403)

    # TM-20: idempotência por (conta, chave de idempotência)
    if idempotency_key:
        anterior = db.execute("SELECT * FROM transacoes WHERE conta_origem = ? AND idempotency_key = ?",
                              (origem["numero"], idempotency_key)).fetchone()
        if anterior:
            return {"id": anterior["id"], "e2e": anterior["e2e"], "valor": anterior["valor"],
                    "comprovante": f"/comprovantes/{anterior['id']}", "repetida": True}

    valor = _valor(dados.get("valor"))  # TM-07: validação explícita, sem exceção crua
    chave = str(dados.get("chave") or "").strip()
    destino_num = db.execute("SELECT conta_numero FROM chaves_pix WHERE chave = ?", (chave,)).fetchone()
    if destino_num is None:
        raise ErroPix("Chave Pix não encontrada.", 404)
    destino = db.execute("SELECT * FROM contas WHERE numero = ?", (destino_num[0],)).fetchone()

    # TM-04: limite aplicado no servidor; nenhum parâmetro do cliente o ignora
    if valor > _limite_vigente(origem):
        raise ErroPix(f"Valor acima do seu limite atual de R$ {_limite_vigente(origem):.2f}.")
    if not antifraude.avaliar({"valor": valor, "descricao": dados.get("descricao"), "usuario": usuario["id"]}):
        raise ErroPix("Transação não autorizada pela análise de segurança.", 403)

    # TM-20: débito condicional e atômico (evita gasto duplo em concorrência)
    cur = db.execute("UPDATE contas SET saldo = saldo - ? WHERE numero = ? AND saldo >= ?",
                     (valor, origem["numero"], valor))
    if cur.rowcount != 1:
        db.rollback()
        raise ErroPix("Saldo insuficiente.")
    db.execute("UPDATE contas SET saldo = saldo + ? WHERE numero = ?", (valor, destino["numero"]))
    e2e = psti_client.enviar_pacs008({"origem": origem["numero"], "destino": destino["numero"], "valor": valor})
    cur = db.execute(
        "INSERT INTO transacoes (e2e, conta_origem, conta_destino, valor, descricao, idempotency_key, criado_em)"
        " VALUES (?,?,?,?,?,?,?)",
        (e2e, origem["numero"], destino["numero"], valor, dados.get("descricao"), idempotency_key,
         datetime.datetime.now().isoformat(timespec="seconds")))
    db.commit()
    tx_id = cur.lastrowid
    auditoria.registrar(usuario["id"], "PIX_ENVIADO", {"id": tx_id, "e2e": e2e, "valor": valor})
    return {"id": tx_id, "e2e": e2e, "valor": valor, "comprovante": f"/comprovantes/{tx_id}"}


@bp.route("/pix", methods=["GET", "POST"])
@login_obrigatorio()
def pix_web():
    conta = conta_do_usuario(g.usuario["id"])
    if request.method == "GET":
        return render_template("pix.html", usuario=g.usuario, conta=conta, conta_origem=conta["numero"],
                               limite=_limite_vigente(conta))
    try:
        resultado = executar_pix(g.usuario, request.form.to_dict())
    except ErroPix as e:
        return render_template("pix.html", usuario=g.usuario, conta=conta, conta_origem=conta["numero"],
                               limite=_limite_vigente(conta), erro=e.mensagem), e.status
    return redirect(resultado["comprovante"])


@bp.route("/api/v1/pix/transferencias", methods=["POST"])
@login_obrigatorio(api=True)
def pix_api():
    dados = request.get_json(silent=True)
    if not isinstance(dados, dict):
        return jsonify({"erro": "Requisição inválida."}), 400
    try:
        resultado = executar_pix(g.usuario, dados, request.headers.get("Idempotency-Key"))
    except ErroPix as e:
        return jsonify({"erro": e.mensagem}), e.status
    return jsonify(resultado), (200 if resultado.get("repetida") else 201)


@bp.route("/api/v1/pix/dict/<path:chave>")
@login_obrigatorio(api=True)
def consulta_dict(chave):
    # TM-19: retorna apenas o necessário para confirmação (rate limit: Dia 03/04)
    row = get_db().execute(
        "SELECT u.nome, u.cpf FROM chaves_pix k JOIN contas c ON c.numero = k.conta_numero"
        " JOIN usuarios u ON u.id = c.usuario_id WHERE k.chave = ?", (chave,)).fetchone()
    if not row:
        return jsonify({"erro": "Chave não encontrada"}), 404
    return jsonify({"nome": row["nome"], "cpf": mascarar_cpf(row["cpf"])})


@bp.route("/comprovantes/<int:tx_id>")
@login_obrigatorio()
def comprovante(tx_id):
    # TM-08: somente participantes da transação; CPF mascarado
    db = get_db()
    conta = conta_do_usuario(g.usuario["id"])
    tx = db.execute("SELECT * FROM transacoes WHERE id = ? AND (conta_origem = ? OR conta_destino = ?)",
                    (tx_id, conta["numero"], conta["numero"])).fetchone()
    if tx is None:
        return render_template("comprovante.html", tx=None), 404

    def titular(numero):
        r = db.execute("SELECT u.nome, u.cpf, c.agencia, c.numero FROM contas c JOIN usuarios u"
                       " ON u.id = c.usuario_id WHERE c.numero = ?", (numero,)).fetchone()
        return {"nome": r["nome"], "cpf": mascarar_cpf(r["cpf"]), "agencia": r["agencia"], "numero": r["numero"]}
    return render_template("comprovante.html", tx=tx, origem=titular(tx["conta_origem"]),
                           destino=titular(tx["conta_destino"]), base_url=None)
