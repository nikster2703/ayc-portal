# ── AYC Portal — Dockerfile ───────────────────────────────────────────────────
# Multi-stage build:
#   builder  — compiles pysqlcipher3 (needs gcc + sqlcipher dev headers)
#   runtime  — lean image, copies only the compiled wheel
#
# Build:  docker compose build
# Run:    docker compose up -d

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS builder

# Build deps for pysqlcipher3 + cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libsqlcipher-dev \
    libssl-dev \
    libffi-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements.txt .

# Build all wheels into /wheels — pysqlcipher3 needs the sqlcipher headers here
RUN pip wheel --no-cache-dir --wheel-dir /wheels \
    --find-links /wheels \
    -r requirements.txt

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS runtime

# Runtime deps: libsqlcipher0 (shared library used at runtime by pysqlcipher3)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlcipher0 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for security
RUN useradd --create-home --shell /bin/bash ayc
WORKDIR /app

# Install wheels built in stage 1
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links /wheels /wheels/*.whl \
    && rm -rf /wheels

# Copy application source
COPY --chown=ayc:ayc . .

# The instance directory is mounted as a volume at runtime.
# INSTANCE_DIR tells app.py where to find .env, data/ayc.db, data/documents/
# Default matches the volume mount point defined in docker-compose.yml.
ENV INSTANCE_DIR=/data
ENV PORT=5001

# Ensure the data directory exists (volume will overlay this at runtime)
RUN mkdir -p /data && chown ayc:ayc /data

USER ayc

EXPOSE 5001

# Gunicorn: 1 worker, 4 threads.
# Rate limiters are DB-backed since v11.29 (shared across processes via the
# rate_limits table), so it is now safe to raise --workers for more concurrency
# on busy nights — bump the number below and `docker compose up -d --force-recreate`.
CMD ["gunicorn", \
     "--workers", "1", \
     "--threads", "4", \
     "--bind", "0.0.0.0:5001", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "app:app"]
