"""Core Box — Core Bancário do Banco Box (versão CORRIGIDA — gabarito do professor)."""
import logging
import uuid

from flask import Flask, redirect, jsonify, request

from app import config, db


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(config.Config)
    if test_config:
        app.config.update(test_config)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    db.init_app(app)

    from app.auth import bp as auth_bp
    from app.contas import bp as contas_bp
    from app.pix import bp as pix_bp
    from app.backoffice import bp as backoffice_bp
    from app.onboarding import bp as onboarding_bp
    from app.api_interna import bp as interna_bp
    from app.agente import bp as agente_bp
    from app.sso import bp as sso_bp
    for b in (auth_bp, contas_bp, pix_bp, backoffice_bp, onboarding_bp, interna_bp, agente_bp, sso_bp):
        app.register_blueprint(b)

    @app.route("/")
    def index():
        return redirect("/login")

    @app.route("/health")
    def health():
        return {"status": "ok"}  # TM-07: sem versão, ambiente ou flags internas

    @app.after_request
    def cabecalhos_seguranca(resp):
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.errorhandler(Exception)
    def erro_generico(exc):
        from werkzeug.exceptions import HTTPException
        if isinstance(exc, HTTPException):
            return exc
        correlacao = uuid.uuid4().hex[:12]
        # Detalhe completo SÓ no log do servidor, com id de correlação
        app.logger.exception("Erro não tratado [%s] em %s %s", correlacao, request.method, request.path)
        return jsonify({"erro": "Não foi possível concluir a operação.", "correlacao": correlacao}), 500

    return app
