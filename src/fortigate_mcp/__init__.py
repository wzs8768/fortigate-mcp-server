"""
FortiGate MCP — FortiOS 8.0 REST API 管理服务器

提供 279 个 MCP 工具，覆盖防火墙策略/地址对象/服务/调度/安全 Profile/VPN/
用户认证/路由/NAT/流量整形/证书/日志等管理。

540+ FortiOS 8.0 API 方法，全异步 Python (httpx)，多设备并发管理。

传输模式：
- server.py — STDIO（本地客户端直连）
- server_http.py — HTTP/HTTPS（SSE + Streamable HTTP 同端口共存）
"""

__version__ = "2.0.0"
__author__ = "FortiGate MCP Team"
__email__ = "support@fortimcp.dev"

from .server import FortiGateMCPServer
from .server_http import FortiGateMCPHTTPServer

__all__ = [
    "FortiGateMCPServer", 
    "FortiGateMCPHTTPServer",
]
