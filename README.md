<!-- FortiGate MCP Server — FortiOS 7.4.12 / 7.6.7 / 8.0.0 REST API 管理服务器 — 283 MCP 工具 · 540+ API 方法 · 1023+ CMDB 端点 -->
<p align="center">
  <img src="https://img.shields.io/badge/FortiGate-MCP%20Server-blue?style=for-the-badge&logo=fortinet&logoColor=white" alt="FortiGate MCP Server"/>
</p>

<h1 align="center">FortiGate MCP Server</h1>

<p align="center">
  <strong>🇨🇳 中文</strong> &nbsp;|&nbsp; <a href="README_EN.md">🇺🇸 English</a>
</p>

<p align="center">
  <strong>通过 Model Context Protocol (MCP) 让 AI 助手查询和管理 FortiGate</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/MCP-1.0-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/API%E6%96%B9%E6%B3%95-540+-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/MCP%E5%B7%A5%E5%85%B7-283+-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/CMDB%E7%AB%AF%E7%82%B9-1023+-purple?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"/>
</p>

---

## 简介

FortiGate MCP Server 将 FortiGate REST API 封装为 MCP 工具，让 Claude、ChatGPT、Hermes、Codex、Cursor 等支持 MCP 的 AI/Agent 通过自然语言完成设备查询、故障排查和配置管理。

项目基于异步 Python 实现，支持：

- **283+ MCP 工具**
- **540+ FortiOS API 方法**
- **1023+ CMDB 端点**
- 多 FortiGate / 多 VDOM
- FortiGate API Token 认证
- MCP Server Bearer Token 认证
- STDIO / Streamable HTTP / SSE
- HTTP / HTTPS

已针对以下 FortiOS 版本进行适配：

- FortiOS 7.4.12
- FortiOS 7.6.7
- FortiOS 8.0.0

> 其他 FortiOS 版本可能存在 API 差异，建议在生产环境使用前进行验证。

---

## 主要能力

| 类别 | 能力 |
|---|---|
| 防火墙 | Policy、Address、Service、VIP、IP Pool、Central SNAT |
| 安全 | IPS、AV、Web Filter、DNS Filter、DLP、SSL Inspection、Application Control |
| VPN | IPSec VPN、SSL VPN 配置与状态查询 |
| 网络 | Interface、Static Route、BGP、ARP、LLDP |
| SD-WAN | Health Check、Members、SLA Log |
| 认证 | Local User、User Group、LDAP、RADIUS、Authentication |
| 系统 | System Status、HA、Sensor、Resource、Storage、NTP、License |
| 日志 | FortiGate Log、FortiAnalyzer / FortiCloud 状态 |
| 通用 API | CMDB CRUD、Monitor API 通用调用 |

---

## 快速开始

### 环境要求

- Python 3.11+
- 已启用 REST API 的 FortiGate
- FortiGate API Token（推荐）

### 安装

```bash
git clone https://github.com/wzs8768/fortigate-mcp-server.git
cd fortigate-mcp-server

python -m venv .venv
source .venv/bin/activate
pip install -e .
```

也可以使用 `uv`（更快）：

```bash
uv venv
source .venv/bin/activate
uv pip install -e .
```

---

## 配置

创建配置文件 `config/config.json`（**文件位置**：`<项目目录>/config/config.json`）：

多 FortiGate / 多 MCP Client 完整示例：

```json
{
  "server": {
    "host": "0.0.0.0",
    "https_port": 8814,
    "http_port": 8815,
    "name": "fortigate-mcp-server",
    "version": "2.0.0"
  },
  "fortigate": {
    "devices": {
      "FGT-HQ": {
        "host": "192.168.1.1",
        "port": 443,
        "api_token": "<FortiGate-API-Token-HQ>",
        "vdom": "root",
        "verify_ssl": false,
        "timeout": 30
      },
      "FGT-BRANCH": {
        "host": "192.168.2.1",
        "port": 443,
        "api_token": "<FortiGate-API-Token-BRANCH>",
        "vdom": "root",
        "verify_ssl": false,
        "timeout": 30
      }
    }
  },
  "auth": {
    "require_auth": true,
    "api_tokens": [
      {
        "name": "hermes",
        "token": "<MCP-Server-Token-Hermes>"
      },
      {
        "name": "chatgpt",
        "token": "<MCP-Server-Token-ChatGPT>"
      },
      {
        "name": "claude",
        "token": "<MCP-Server-Token-Claude>"
      }
    ],
    "allowed_origins": []
  },
  "logging": {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file": "logs/server.log",
    "console": true
  }
}
```

### 配置字段说明

| 字段 | 说明 |
|------|------|
| `fortigate.devices` | 管理的 FortiGate 设备列表，每台设备一个命名字段 |
| `fortigate.devices.<name>.api_token` | FortiGate 设备本身的 API Token（在 FortiGate 上生成）。**优先于 username/password**，两者同时配置时以 api_token 为准 |
| `fortigate.devices.<name>.username` / `password` | 用户名密码认证（备选，推荐用 api_token） |
| `auth.api_tokens` | **MCP Server 认证 Token 列表**，客户端连接时携带，服务端验证 |
| `auth.api_tokens[].name` | Token 名称/标签，用于识别使用者（如 `hermes`、`chatgpt`、`claude`） |
| `auth.api_tokens[].token` | Token 值，用 `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` 生成。⚠️ 这是 **MCP Server 认证 Token**（本机生成），不要与上方 `api_token`（FortiGate 设备 API Token）混淆。 |
| `logging.file` | 日志文件路径，认证日志会记录客户端名称 |

---

## 启动

### STDIO（本地直连，不走网络）

适合 MCP Client 与 Server 在同一台机器：

```bash
export FORTIGATE_MCP_CONFIG=config/config.json
python -m src.fortigate_mcp.server
```

### HTTP

```bash
python -m src.fortigate_mcp.server_http \
  --host 0.0.0.0 \
  --port 8815 \
  --transport all
```

端点：

```text
Streamable HTTP: http://<server>:8815/fortigate-mcp
SSE:             http://<server>:8815/fortigate-mcp-sse
```

### HTTPS

内网测试可先生成自签名证书：

```bash
mkdir -p certs

openssl req -x509 -newkey rsa:4096 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -days 3650 \
  -nodes \
  -subj "/CN=<server-ip>" \
  -addext "subjectAltName=IP:<server-ip>"
```

> **SAN 说明**：`subjectAltName` 必须与实际访问地址匹配
> - 使用 IP 访问：`subjectAltName=IP:192.168.1.10`
> - 使用域名访问：`subjectAltName=DNS:mcp.example.local`

然后启动 HTTPS：

```bash
python -m src.fortigate_mcp.server_http \
  --host 0.0.0.0 \
  --port 8814 \
  --transport all \
  --ssl-cert certs/server.crt \
  --ssl-key certs/server.key
```

端点：

```text
Streamable HTTP: https://<server>:8814/fortigate-mcp
SSE:             https://<server>:8814/fortigate-mcp-sse
```

### 测试环境信任自签名证书

测试环境不必关闭 TLS 证书校验。

可以将生成的 `certs/server.crt` 导入 MCP Client 所在系统的受信任根证书存储，之后继续正常使用 HTTPS。

**Windows**

双击 `server.crt`：

`安装证书` → `本地计算机` → `受信任的根证书颁发机构`

**macOS**

将 `server.crt` 导入 System Keychain，并设置为 `Always Trust`。

**Ubuntu / Debian**

```bash
sudo cp certs/server.crt /usr/local/share/ca-certificates/fortigate-mcp.crt
sudo update-ca-certificates
```

> 证书中的 IP 地址或 FQDN 必须与 MCP Client 实际访问 MCP Server 时使用的地址匹配。生产环境建议使用受信任 CA 签发的证书。

### systemd 服务（开机自启）

```bash
cp contrib/fortigate-mcp.service ~/.config/systemd/user/
# 编辑 ExecStart 行，按需设置 --transport / --ssl-cert / --ssl-key
systemctl --user daemon-reload
systemctl --user enable --now fortigate-mcp

# 如需服务器重启后无需用户登录即可启动
sudo loginctl enable-linger $USER
```

---

## Docker 部署

无需安装 Python 环境，一条命令启动：

```bash
# 1. 克隆仓库并准备配置
git clone https://github.com/wzs8768/fortigate-mcp-server.git
cd fortigate-mcp-server

# 2. 创建 config/config.json（见上方[配置](#配置)）

# 3. 启动（HTTP · :8815）
docker compose up -d
```

HTTPS 模式需先在宿主机生成证书并挂载 `certs/` 目录。

---

## MCP Client 集成

### 远程连接（HTTPS）

```json
{
  "mcpServers": {
    "fortigate": {
      "url": "https://<server>:8814/fortigate-mcp",
      "transport": "streamable-http",
      "headers": {
        "Authorization": "Bearer <MCP-Server-Token>"
      }
    }
  }
}
```

### 本地 STDIO

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "python",
      "args": [
        "-m",
        "src.fortigate_mcp.server"
      ],
      "env": {
        "FORTIGATE_MCP_CONFIG": "/path/to/config/config.json"
      }
    }
  }
}
```

不同 MCP Client 的配置格式可能略有差异。

---

## 常用工具示例

```text
# 设备
list_devices
get_device_status
test_device_connection
get_system_status

# 防火墙
list_firewall_policies
get_firewall_policy_detail
create_firewall_policy
update_firewall_policy
delete_firewall_policy

# 网络
list_interfaces
get_routing_table
monitor_network_arp
monitor_network_lldp_neighbors

# VPN / SD-WAN
monitor_vpn_ipsec
monitor_vpn_ssl
monitor_virtual_wan_health_check
monitor_virtual_wan_members
monitor_virtual_wan_sla_log

# 系统
monitor_system_status
monitor_system_resource_usage
monitor_system_sensors
monitor_system_ha_status
monitor_system_storage

# 通用 API
cmdb_list
cmdb_get
cmdb_create
cmdb_update
cmdb_delete
monitor_request
```

通用 CMDB / Monitor 工具可以访问大量未单独封装的 FortiOS API。

---

## 安全建议

- 推荐使用 **FortiGate API Token**，避免使用管理员密码
- MCP Server 建议保持 **Bearer Token 认证**开启
- 生产环境建议使用可信 CA 证书并保持客户端证书校验开启
- MCP Server 建议仅暴露在可信网络、VPN 或安全反向代理之后
- FortiGate REST API 管理员应遵循最小权限原则
- 对生产环境的配置写操作，建议在 Agent 侧增加权限控制或人工审批

> MCP 工具包含配置写操作。将 AI Agent 接入生产 FortiGate 前，请确认调用权限、审批流程和审计策略。

---

## 开发

```bash
pytest tests/
ruff check src/
```

CI 主要检查：

- Ruff
- Pytest
- Python Package Build
- Docker Build

---

## License

MIT License.

## Acknowledgements

特别感谢原始项目及作者：

- [alpadalar/fortigate-mcp-server](https://github.com/alpadalar/fortigate-mcp-server) — 本项目基于其工作继续扩展和完善

同时感谢：

- [Model Context Protocol](https://modelcontextprotocol.io/)
- [FastMCP](https://github.com/jlowin/fastmcp)
- [Fortinet Documentation](https://docs.fortinet.com/)
- [httpx](https://www.python-httpx.org/)