# FortiGate MCP Server Dockerfile
# Multi-stage build for optimized image size

FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml ./
COPY README.md ./
COPY src/ ./src/

RUN uv venv /app/.venv && \
    . /app/.venv/bin/activate && \
    uv pip install --no-cache -e .

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY src/ ./src/
COPY certs/ ./certs/

RUN useradd --create-home --shell /bin/bash fgtmcp && \
    mkdir -p /app/config /app/logs && \
    chown -R fgtmcp:fgtmcp /app

USER fgtmcp

EXPOSE 8815 8814

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8815/health')" || exit 1

CMD ["python", "-m", "src.fortigate_mcp.server_http", \
     "--host", "0.0.0.0", "--port", "8815", "--transport", "all", \
     "--config", "/app/config/config.json"]
