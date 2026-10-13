# One image for every Python service (ingest-api, worker, ti-service, approval-ui, migrate).
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TRIAGE_EMBED_CACHE_DIR=/models/fastembed

RUN useradd --create-home --uid 10001 app && mkdir -p /models/fastembed && chown -R app /models

WORKDIR /build
# 1) connector SDK
COPY packages/triage_connectors /build/triage_connectors
RUN pip install /build/triage_connectors

# 2) app dependencies (cached unless pyproject.toml changes)
COPY pyproject.toml /build/app/pyproject.toml
RUN mkdir -p /build/app/src/triage && touch /build/app/src/triage/__init__.py \
    && pip install "/build/app[embed]" && pip uninstall -y triage

# 3) app source
COPY src /build/app/src
RUN pip install --no-deps /build/app

WORKDIR /app
COPY migrations /app/migrations
COPY data/attack /app/data/attack
COPY data/ti /app/data/ti

USER app
