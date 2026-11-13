# syntax=docker/dockerfile:1
# Core Box — imagem corrigida (gabarito)
# Em produção, fixe a imagem base por DIGEST: python:3.12-slim@sha256:<digest>
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Usuário sem privilégios e sem shell
RUN groupadd --system box && useradd --system --gid box --home-dir /app --shell /usr/sbin/nologin box

WORKDIR /app
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copia SOMENTE o necessário (nada de tests/, .git, docs, deploy, infra)
COPY app/ app/
COPY config/ config/
COPY wsgi.py .

RUN mkdir -p /dados/uploads && chown -R box:box /dados
USER box

ENV BOX_AMBIENTE=producao \
    BOX_DATABASE=/dados/box.db \
    BOX_UPLOAD_DIR=/dados/uploads
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", "--preload", "--access-logfile", "-", "wsgi:app"]
