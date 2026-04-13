# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# System deps for asyncpg, chromadb and shap
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libpq-dev curl python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN grep -v "pywin32" requirements.txt > requirements_linux.txt && \
    pip install --upgrade pip setuptools wheel packaging && \
    pip install --prefix=/install --no-cache-dir -r requirements_linux.txt

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

WORKDIR /app

# System runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

# Ensure bootstrap tooling used by transformer imports is present even if the
# dependency resolver leaves it out of the runtime layer.
RUN pip install --no-cache-dir packaging==26.0

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Non-root user (security hardening)
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

# Copy source code
COPY --chown=appuser:appuser . .

EXPOSE 8000

# Health check for Docker / Kubernetes
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
