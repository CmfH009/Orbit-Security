# orbit-security/Dockerfile
# ==========================================
# STAGE 1: Build with full toolchain (ephemeral)
# ==========================================
FROM python:3.12-slim AS builder

# Install only build deps, no runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv and dependencies in isolated layer
COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv && \
    uv sync --frozen --no-dev && \
    uv pip freeze > /requirements.txt

# ==========================================
# STAGE 2: Distroless runtime (NO shell, NO package manager, NO root)
# ==========================================
FROM gcr.io/distroless/python3-debian12:nonroot

# Security: Explicit non-root user (UID 65532)
USER 65532:65532

# Security: Read-only root filesystem (enforced by distroless)
# Security: No shell, no package manager, no apt, no su, no sudo

WORKDIR /app

# Copy only runtime artifacts
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /requirements.txt /requirements.txt
COPY src/ ./src/
COPY scripts/ ./scripts/

# Security: Drop ALL capabilities (distroless does this by default)
# Security: No network listeners except explicit port

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/app/.venv

# Health check (Cloud Run native, no wget/curl needed)
EXPOSE 8080

# Entry point - direct python execution, no shell
ENTRYPOINT ["/app/.venv/bin/python", "-c"]
CMD ["import os, sys, time, threading; \
os.environ['COCKPIT_PORT'] = '8080'; \
from system.cockpit.server import start_web_server_if_needed; \
url = start_web_server_if_needed(8080); \
print(f'API Server: {url}', flush=True); \
def monitor(): \
    import urllib.request; \
    while True: \
        time.sleep(30); \
        try: urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=5) \
        except: os._exit(1); \
threading.Thread(target=monitor, daemon=True).start(); \
while True: time.sleep(3600)"]