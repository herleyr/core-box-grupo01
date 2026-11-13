"""Integração com o PSTI (SPI/DICT) — versão corrigida."""
import datetime
import logging
import os
import uuid

import requests
from flask import current_app

log = logging.getLogger("box.psti")


def _gerar_e2e():
    return f"E00000000{datetime.datetime.now().strftime('%Y%m%d%H%M')}{uuid.uuid4().hex[:11].upper()}"


def enviar_pacs008(transacao):
    e2e = _gerar_e2e()
    if os.getenv("BOX_PSTI_MODO", "simulado") == "real":
        # TM-17: TLS verificado (CA da homologação informada explicitamente, nunca verify=False)
        resp = requests.post(current_app.config["PSTI_URL"] + "/pacs008", json={**transacao, "endToEndId": e2e},
                             headers={"X-Api-Key": current_app.config["PSTI_API_KEY"]},
                             verify=current_app.config["PSTI_CA_BUNDLE"], timeout=5)
        resp.raise_for_status()
    log.info("pacs.008 enviado e2e=%s", e2e)
    return e2e
