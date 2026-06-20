#!/bin/bash
# ============================================================
# FortiGate MCP Server — STDIO mode
# 供 MCP Client 直接调用 (Claude Desktop, Cursor, etc.)
#
# MCP Client 配置示例 (claude_desktop_config.json):
# {
#   "mcpServers": {
#     "fortigate": {
#       "command": "/path/to/fortigate-mcp-server/start_stdio.sh",
#       "args": []
#     }
#   }
# }
# ============================================================
set -e

BASE_DIR="$(dirname "$(readlink -f "$0")")/.."
PYTHON="python3"

export FORTIGATE_MCP_CONFIG="$BASE_DIR/config/config.json"

if [ ! -f "$FORTIGATE_MCP_CONFIG" ]; then
    echo "Error: Config not found at $FORTIGATE_MCP_CONFIG" >&2
    exit 1
fi

cd "$BASE_DIR"
exec "$PYTHON" -m src.fortigate_mcp.server
