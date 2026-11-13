"""Trilha de auditoria (versão corrigida): sem segredos, com mascaramento e eventos de segurança."""
import datetime
import json
import logging

from app.db import get_db

log = logging.getLogger("box.auditoria")
CAMPOS_PROIBIDOS = {"token", "senha", "nova_senha", "codigo", "authorization", "otp"}


def _sanitizar(detalhe):
    if not isinstance(detalhe, dict):
        return detalhe
    limpo = {}
    for k, v in detalhe.items():
        if k.lower() in CAMPOS_PROIBIDOS:
            continue
        if k.lower() == "cpf" and isinstance(v, str) and len(v) == 14:
            v = "***" + v[3:12] + "**"
        limpo[k] = v
    return limpo


def registrar(ator, acao, detalhe=None):
    detalhe = _sanitizar(detalhe)
    log.info("AUDITORIA acao=%s ator=%s detalhe=%s", acao, ator, json.dumps(detalhe, ensure_ascii=False, default=str))
    db = get_db()
    db.execute("INSERT INTO auditoria (ts, ator, acao, detalhe) VALUES (?,?,?,?)",
               (datetime.datetime.now().isoformat(timespec="seconds"), str(ator), acao,
                json.dumps(detalhe, ensure_ascii=False, default=str)))
    db.commit()


def evento_seguranca(ator, tipo, detalhe=None):
    """Eventos que o SIEM vai consumir no Dia 04 (ex.: BOLA_ATTEMPT, LOGIN_BLOQUEADO)."""
    log.warning("SECURITY_EVENT tipo=%s ator=%s detalhe=%s", tipo, ator,
                json.dumps(_sanitizar(detalhe), ensure_ascii=False, default=str))
    registrar(ator, "SEC_" + tipo, detalhe)
