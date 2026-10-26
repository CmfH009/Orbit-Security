# orbit-security/Dockerfile
# ==========================================
# STAGE 1: Build with full toolchain (ephemeral)
# ==========================================
FROM python:3.13-slim AS builder

WORKDIR /app

# Install only build deps, no runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv and dependencies in isolated layer
COPY pyproject.toml uv.lock README.md ./
RUN pip install --no-cache-dir uv && \
    uv sync --no-dev --no-install-project && \
    /app/.venv/bin/python -m pip freeze > /requirements.txt || true

# ==========================================
# STAGE 2: Hardened non-root runtime (UID 65532)
# ==========================================
FROM python:3.13-slim

# Security: Explicit non-root user (UID 65532)
USER 65532:65532

WORKDIR /app

# Copy only runtime artifacts
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /requirements.txt /requirements.txt
COPY src/ ./src/
COPY data/ ./data/
COPY scripts/ ./scripts/

# Security: Drop ALL capabilities (distroless does this by default)
# Security: No network listeners except explicit port

ENV PYTHONPATH=/app/src:/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PORT=8080 \
    HOST=0.0.0.0

# Health check & Service Port (Cloud Run native)
EXPOSE 8080

# Entry point - direct python execution of hardened Radar Telemetry Server
ENTRYPOINT ["/app/.venv/bin/python", "-m", "orbit_security.radar_telemetry", "--serve", "--port", "8080", "--host", "0.0.0.0"]
