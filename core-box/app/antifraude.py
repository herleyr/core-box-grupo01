"""Cliente do antifraude (versão corrigida: modo degradado em vez de fail-open)."""
import logging
import os

log = logging.getLogger("box.antifraude")
VALOR_MAX_MODO_DEGRADADO = 200.0


class AntifraudeIndisponivel(Exception):
    pass


def _consultar_score(transacao):
    if os.getenv("BOX_ANTIFRAUDE_INDISPONIVEL") == "1":
        raise AntifraudeIndisponivel("timeout após 2s")
    score = 10
    descricao = (transacao.get("descricao") or "").lower()
    if any(p in descricao for p in ("urgente", "hospital", "sequestro", "presente")):
        score += 50
    if transacao["valor"] >= 10000:
        score += 30
    return score


def avaliar(transacao):
    try:
        score = _consultar_score(transacao)
    except AntifraudeIndisponivel:
        # TM-32: falha segura — só valores baixos seguem, e o evento é alertado
        log.warning("SECURITY_EVENT tipo=ANTIFRAUDE_INDISPONIVEL valor=%s", transacao["valor"])
        return transacao["valor"] <= VALOR_MAX_MODO_DEGRADADO
    return score < 90
