# ---- Base ----
FROM python:3.12-slim AS base
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc && \
    rm -rf /var/lib/apt/lists/*
COPY pyproject.toml .
COPY src/ /app/src/
RUN pip install --no-cache-dir ".[dev]"

# ---- Development ----
FROM base AS development
COPY migrations/ /app/migrations/
COPY alembic.ini /app/
ENV PYTHONPATH=/app/src
EXPOSE 5050

# ---- Production ----
FROM base AS production
COPY migrations/ /app/migrations/
COPY alembic.ini /app/
ENV PYTHONPATH=/app/src
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "dimsum.app:create_app()"]
