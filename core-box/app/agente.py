"""Módulo BoxGPT — assistente virtual do Core Box (LABORATÓRIO Dia 03).

Expõe o agente simulado (app/agente_engine.py) por UI e API. Contém fraquezas
INTENCIONAIS de agentes de IA (OWASP Top 10 for LLM Applications) para análise.
Os comentários AI-xx remetem ao catálogo de vulnerabilidades do Caderno do Aluno.
"""
import datetime
import json

from flask import Blueprint, render_template, request, g, jsonify, session

from app import agente_engine, auditoria
from app.contas import conta_do_usuario
from app.db import get_db
from app.seguranca import login_obrigatorio, usuario_atual

bp = Blueprint("agente", __name__, url_prefix="/assistente")


def _garante_tabelas():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS agente_conversas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sessao TEXT, usuario_id INTEGER, criada_em TEXT
        );
        CREATE TABLE IF NOT EXISTS agente_mensagens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversa_id INTEGER, papel TEXT, conteudo TEXT, criada_em TEXT
        );
        """
    )
    db.commit()


def _conversa_atual(usuario):
    db = get_db()
    # AI-19: identificador de sessão do agente previsível (sequencial), não aleatório
    cid = session.get("agente_conversa_id")
    if cid:
        return cid
    seq = db.execute("SELECT COALESCE(MAX(id),1000)+1 AS n FROM agente_conversas").fetchone()["n"]
    db.execute("INSERT INTO agente_conversas (id, sessao, usuario_id, criada_em) VALUES (?,?,?,?)",
               (seq, f"sess-{seq}", usuario["id"], datetime.datetime.now().isoformat(timespec="seconds")))
    db.commit()
    session["agente_conversa_id"] = seq
    return seq


def _historico(conversa_id, limite=20):
    return get_db().execute(
        "SELECT papel, conteudo FROM agente_mensagens WHERE conversa_id = ? ORDER BY id DESC LIMIT ?",
        (conversa_id, limite)).fetchall()


def _ferramenta_contexto(usuario, texto_usuario):
    """Simula o uso de ferramentas (tool calling) e a recuperação de memória/RAG.

    AI-02: injeção indireta — devolve descrições de transações (conteúdo que o
           cliente controla no Pix, ligado ao TM do Dia 01) SEM sanitização.
    AI-05/AI-13: excessive agency — ferramentas acionadas sem checar se a conta/CPF
           pertencem ao usuário autenticado (confused deputy).
    AI-07/AI-14: recuperação devolve dados de OUTROS clientes.
    """
    db = get_db()
    baixo = texto_usuario.lower()
    partes = []

    # "resuma minhas últimas transações" → lê descrições controladas pelo cliente
    if "transac" in baixo or "extrato" in baixo or "resum" in baixo:
        conta = conta_do_usuario(usuario["id"])
        txs = db.execute("SELECT descricao, valor FROM transacoes WHERE conta_origem = ? OR conta_destino = ?"
                         " ORDER BY id DESC LIMIT 10", (conta["numero"], conta["numero"])).fetchall()
        for t in txs:
            partes.append(f"- R$ {t['valor']:.2f}: {t['descricao'] or ''}")  # descrição NÃO sanitizada

    # AI-05/AI-13/AI-14: ferramenta "consultar_cliente" aceita qualquer CPF/conta citado
    import re
    for cpf in re.findall(r"\d{3}\.\d{3}\.\d{3}-\d{2}", texto_usuario):
        row = db.execute("SELECT u.nome, u.cpf, u.senha_hash, c.numero, c.saldo FROM usuarios u"
                         " JOIN contas c ON c.usuario_id = u.id WHERE u.cpf = ?", (cpf,)).fetchone()
        if row:
            partes.append(f"[consultar_cliente] {dict(row)}")
    for conta_n in re.findall(r"\d{8}-\d", texto_usuario):
        row = db.execute("SELECT u.nome, u.cpf, c.numero, c.saldo FROM contas c JOIN usuarios u"
                         " ON u.id = c.usuario_id WHERE c.numero = ?", (conta_n,)).fetchone()
        if row:
            partes.append(f"[consultar_conta] {dict(row)}")

    return "\n".join(partes)


@bp.route("", methods=["GET"])
@login_obrigatorio()
def chat():
    _garante_tabelas()
    cid = _conversa_atual(g.usuario)
    msgs = list(reversed(_historico(cid)))
    return render_template("assistente.html", usuario=g.usuario, mensagens=msgs, conversa_id=cid)


@bp.route("/api/mensagem", methods=["POST"])
@login_obrigatorio(api=True)
def mensagem():
    _garante_tabelas()
    db = get_db()
    dados = request.get_json(force=True)
    texto = str(dados.get("texto", ""))
    cid = _conversa_atual(g.usuario)
    # AI-15: sem limite de requisições / tamanho — permite exaustão e context stuffing (AI-20)
    estado = session.get("agente_estado", {})

    contexto = _ferramenta_contexto(g.usuario, texto)
    saida = agente_engine.responder(estado, texto, contexto)
    session["agente_estado"] = estado

    agora = datetime.datetime.now().isoformat(timespec="seconds")
    # AI-17: histórico gravado em claro (inclui o que vazou)
    db.execute("INSERT INTO agente_mensagens (conversa_id, papel, conteudo, criada_em) VALUES (?,?,?,?)",
               (cid, "cliente", texto, agora))
    db.execute("INSERT INTO agente_mensagens (conversa_id, papel, conteudo, criada_em) VALUES (?,?,?,?)",
               (cid, "boxgpt", saida["texto"], agora))
    db.commit()
    auditoria.registrar(g.usuario["id"], "AGENTE_MSG", {"conversa": cid})

    resp = {"resposta": saida["texto"], "modo": saida.get("modo", "normal")}
    # AI-16: modo debug exposto por parâmetro revela o "raciocínio" e o contexto
    if request.args.get("debug") == "1" or dados.get("debug"):
        resp["debug"] = {"contexto_ferramentas": contexto, "estado": estado,
                         "gatilhos": saida.get("vaza", [])}
    return jsonify(resp)


@bp.route("/api/conversas/<int:conversa_id>", methods=["GET"])
@login_obrigatorio(api=True)
def ver_conversa(conversa_id):
    # AI-04 / AI-17 (IDOR): devolve QUALQUER conversa pelo id, sem checar o dono
    msgs = get_db().execute(
        "SELECT papel, conteudo, criada_em FROM agente_mensagens WHERE conversa_id = ? ORDER BY id",
        (conversa_id,)).fetchall()
    return jsonify({"conversa_id": conversa_id, "mensagens": [dict(m) for m in msgs]})


@bp.route("/api/historico")
@login_obrigatorio(api=True)
def historico_json():
    cid = session.get("agente_conversa_id")
    return jsonify({"conversa_id": cid, "mensagens": [dict(m) for m in _historico(cid or 0, 100)]})
