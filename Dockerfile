FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libssl-dev \
    libffi-dev \
    curl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN python -m pip install --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

# cria usuário não-root com shell (permite docker exec /bin/sh se necessário)
RUN useradd --create-home --shell /bin/sh appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8005

ENV FLASK_ENV=production \
    GUNICORN_BIND=0.0.0.0:8005 \
    PORT=8005 \
    GUNICORN_WORKERS=3 \
    GUNICORN_THREADS=2 \
    GUNICORN_TIMEOUT=30 \
    PYTHONPATH=/app

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8005/health || exit 1

CMD ["gunicorn", "-c", "gunicorn_conf.py", "wsgi:app"]
