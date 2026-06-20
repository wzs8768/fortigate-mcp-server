#!/bin/bash
# ============================================================
# FortiGate MCP Server — HTTP/HTTPS mode
# 提供 Streamable HTTP Transport 给 MCP Client (Claude Desktop, Cursor 等)
#
# 用法:
#   ./start_http.sh                      # HTTP 模式 (默认 0.0.0.0:8815)
#   ./start_http.sh ssl                   # HTTPS 模式 (默认 0.0.0.0:8814)
#   ./start_http.sh 192.168.1.100 8888    # 自定义 host:port (HTTP)
#   ./start_http.sh 192.168.1.100 8888 ssl # 自定义 host:port (HTTPS)
#
# Claude Desktop 配置示例:
# {
#   "mcpServers": {
#     "FortiGateMCP": {
#       "url": "https://<服务器IP>:8814/fortigate-mcp",
#       "transport": "streamable-http"
#     }
#   }
# }
# ============================================================
set -e

BASE_DIR="$(dirname "$(readlink -f "$0")")/.."
PYTHON="python3"

export FORTIGATE_MCP_CONFIG="$BASE_DIR/config/config.json"

HOST="${1:-0.0.0.0}"
PORT="${2:-8815}"
USE_SSL="${3:-}"

# 兼容旧用法: ./start_http.sh ssl
if [ "$HOST" = "ssl" ]; then
    HOST="0.0.0.0"
    USE_SSL="ssl"
fi
if [ "$PORT" = "ssl" ]; then
    PORT="8814"
    USE_SSL="ssl"
fi
# SSL 模式未显式指定端口时，默认用 8814
if [ "$USE_SSL" = "ssl" ] && [ "$PORT" = "8815" ]; then
    PORT="8814"
fi

if [ ! -f "$FORTIGATE_MCP_CONFIG" ]; then
    echo "Error: Config not found at $FORTIGATE_MCP_CONFIG" >&2
    exit 1
fi

mkdir -p "$BASE_DIR/logs"

SSL_ARGS=""
if [ "$USE_SSL" = "ssl" ]; then
    CERT_FILE="$BASE_DIR/certs/server.crt"
    KEY_FILE="$BASE_DIR/certs/server.key"
    if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
        echo "Error: SSL certificate not found. Run: openssl req -x509 ... first" >&2
        exit 1
    fi
    SSL_ARGS="--ssl-cert $CERT_FILE --ssl-key $KEY_FILE"
    echo "Starting with HTTPS..."
fi

cd "$BASE_DIR"
exec "$PYTHON" -m src.fortigate_mcp.server_http \
    --host "$HOST" \
    --port "$PORT" \
    $SSL_ARGS
