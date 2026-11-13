"""Configuração do Core Box (versão corrigida).

Segredos vêm SOMENTE do ambiente (injetados pela plataforma / cofre).
Em desenvolvimento e testes, gera-se um segredo aleatório efêmero.
"""
import os
import secrets

import yaml

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _carregar_yaml(caminho):
    with open(caminho, encoding="utf-8") as f:
        return yaml.safe_load(f)  # TM-31/CWE-502: nunca yaml.load com Loader completo


def _segredo(nome):
    valor = os.getenv(nome)
    if valor:
        return valor
    if os.getenv("BOX_AMBIENTE") == "producao":
        raise RuntimeError(f"Segredo obrigatório ausente: {nome}")
    return secrets.token_urlsafe(32)  # efêmero, apenas dev/teste


_cfg = _carregar_yaml(os.path.join(BASE_DIR, "config", "app-config.yaml"))


class Config:
    VERSAO = _cfg["app"]["versao"]
    AMBIENTE = os.getenv("BOX_AMBIENTE", _cfg["app"]["ambiente"])
    DEBUG = os.getenv("BOX_DEBUG", "false").lower() == "true"
    DATABASE = os.getenv("BOX_DATABASE", os.path.join(BASE_DIR, "box.db"))
    UPLOAD_DIR = os.getenv("BOX_UPLOAD_DIR", os.path.join(BASE_DIR, "uploads"))
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # TM-28: limite de upload

    SECRET_KEY = _segredo("BOX_SECRET_KEY")
    JWT_SECRET = _segredo("BOX_JWT_SECRET")
    JWT_EXPIRACAO_MINUTOS = 30
    JWT_ISSUER = "core-box"
    JWT_AUDIENCE = "box-clientes"
    # Cookie "Secure" só pode ser ligado quando houver TLS (Dia 04). Risco registrado em EXCECOES.md.
    COOKIE_SECURE = os.getenv("BOX_COOKIE_SECURE", "false").lower() == "true"

    PSTI_URL = _cfg["integracoes"]["psti_url"]
    PSTI_API_KEY = os.getenv("BOX_PSTI_API_KEY", "")
    PSTI_CA_BUNDLE = os.getenv("BOX_PSTI_CA_BUNDLE", True)  # True = CAs do sistema
    SMS_GATEWAY_TOKEN = os.getenv("BOX_SMS_GATEWAY_TOKEN", "")

    LIMITE_DIURNO_PADRAO = _cfg["pix"]["limite_diurno"]
    LIMITE_NOTURNO_PADRAO = _cfg["pix"]["limite_noturno"]
    ANTIFRAUDE_TIMEOUT_S = _cfg["antifraude"]["timeout_segundos"]
    ALCADA_AJUSTE = 10000.0
    MAX_TENTATIVAS_LOGIN = 5
    BLOQUEIO_MINUTOS = 15
