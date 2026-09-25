<!-- FortiGate MCP Server — FortiOS 7.4.12 / 7.6.7 / 8.0.0 / 8.0.1 REST API 管理服务器 — 286 MCP 工具 · 1650 API 端点 -->
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
  <img src="https://img.shields.io/badge/MCP%E5%B7%A5%E5%85%B7-286+-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/%E7%AB%AF%E7%82%B9-1650+-purple?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"/>
</p>

---

## 简介

将 FortiGate REST API 封装为 MCP 工具，接入 Claude、ChatGPT、Hermes、Codex、Cursor 等 MCP 客户端，用自然语言完成设备查询、故障排查和配置管理。

- **286 个 MCP 工具**，覆盖 **1650 个 FortiOS REST 端点**（CMDB / Monitor / Log / Service）
- 多 FortiGate / 多 VDOM，全异步并发
- STDIO / Streamable HTTP / SSE，HTTP / HTTPS
- FortiGate API Token 认证 + MCP Server Bearer Token 认证

已适配 **FortiOS 7.4.12 / 7.6.7 / 8.0.0 / 8.0.1**；其他版本可能存在 API 差异，生产环境使用前请先验证。

设备版本首次调用时自动探测，无需手工配置。调用某版本不存在的端点时，返回信息会说明它属于哪些版本，
而不是 FortiOS 原始的 `404` / `500 -651`；`list_api_endpoints` / `get_api_endpoint_schema` / `check_api_compatibility`
可离线查询端点、字段与版本可用性。

---

## 主要能力

| 类别 | 能力 |
|---|---|
| 防火墙 | Policy、Address、Service、VIP、IP Pool、Central SNAT |
| 安全 | IPS、AV、Web Filter、DNS Filter、DLP、SSL Inspection、Application Control |
| VPN | IPSec VPN、SSL VPN 配置与状态查询 |
| 网络 | Interface、Static Route、BGP、ARP、LLDP |
| SD-WAN | Health Check、Members、SLA Log |
| 认证 | Local User、User Group、LDAP、RADIUS |
| 系统 | 状态、HA、Sensor、资源、存储、NTP、License |
| 日志 | FortiGate Log、FortiAnalyzer / FortiCloud 状态 |
| 通用 API | CMDB CRUD、Monitor API 通用调用、API 目录查询 |

---

## 快速开始

环境要求：Python 3.11+、已启用 REST API 的 FortiGate、FortiGate API Token（推荐）

```bash
git clone https://github.com/wzs8768/fortigate-mcp-server.git
cd fortigate-mcp-server

python -m venv .venv
source .venv/bin/activate
pip install -e .
```

用 `uv` 更快：`uv venv && source .venv/bin/activate && uv pip install -e .`

---

## 配置

创建 `config/config.json`：

```json
{
  "server": {
    "host": "0.0.0.0",
    "https_port": 8814,
    "http_port": 8815,
    "name": "fortigate-mcp-server",
    "version": "2.1.0"
  },
  "fortigate": {
    "devices": {
      "FGT-HQ": {
        "host": "192.168.1.1",
        "port": 443,
        "api_token": "<FortiGate-API-Token>",
        "vdom": "root",
        "verify_ssl": false,
        "timeout": 30
      },
      "FGT-BRANCH": {
        "host": "192.168.2.1",
        "port": 443,
        "api_token": "<FortiGate-API-Token>",
        "vdom": "root",
        "verify_ssl": false,
        "timeout": 30
      }
    }
  },
  "auth": {
    "require_auth": true,
    "api_tokens": [
      { "name": "hermes", "token": "<MCP-Server-Token>" }
    ]
  },
  "logging": {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file": "logs/server.log",
    "console": true
  }
}
```

两类 Token 用途不同，不要混淆：

| 配置 | 方向 | 说明 |
|---|---|---|
| `fortigate.devices.<name>.api_token` | MCP Server → FortiGate | 在 FortiGate 上生成 |
| `auth.api_tokens[].token` | MCP Client → MCP Server | 本机生成：`python3 -c "import secrets; print(secrets.token_urlsafe(32))"` |

- 设备认证可用 `api_token`（推荐）或 `username` + `password`，两者都配时以 `api_token` 为准
- `verify_ssl` 控制的是 **MCP Server → FortiGate** 的证书校验，与客户端是否信任 `server.crt` 无关

---

## 启动

### STDIO（本地直连，不走网络）

```bash
export FORTIGATE_MCP_CONFIG=config/config.json
python -m src.fortigate_mcp.server
```

### HTTP / HTTPS

```bash
# HTTP
python -m src.fortigate_mcp.server_http --host 0.0.0.0 --port 8815 --transport all

# HTTPS：先生成自签名证书，再启动
mkdir -p certs
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/server.key -out certs/server.crt \
  -days 3650 -nodes \
  -subj "/CN=<server-ip>" -addext "subjectAltName=IP:<server-ip>"

python -m src.fortigate_mcp.server_http --host 0.0.0.0 --port 8814 --transport all \
  --ssl-cert certs/server.crt --ssl-key certs/server.key
```

`subjectAltName` 必须与实际访问地址匹配：用 IP 访问填 `IP:192.168.1.10`，用域名填 `DNS:mcp.example.local`。
客户端把 `certs/server.crt` 导入系统受信任根证书即可（Windows 双击安装到「受信任的根证书颁发机构」；
macOS 导入 System Keychain 并设为 Always Trust；Ubuntu `cp certs/server.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`）。
生产环境建议使用受信任 CA 签发的证书。

端点：

```text
Streamable HTTP: http(s)://<server>:8814/fortigate-mcp
SSE:             http(s)://<server>:8814/fortigate-mcp-sse
```

### systemd（开机自启）

```bash
cp contrib/fortigate-mcp.service ~/.config/systemd/user/
# 按需编辑 ExecStart 的 --transport / --ssl-cert / --ssl-key
systemctl --user daemon-reload
systemctl --user enable --now fortigate-mcp

# 重启后无需用户登录即可启动
sudo loginctl enable-linger $USER
```

### Docker

```bash
git clone https://github.com/wzs8768/fortigate-mcp-server.git
cd fortigate-mcp-server
# 创建 config/config.json（见上方配置）
docker compose up -d
```

HTTPS 模式需先在宿主机生成证书并挂载 `certs/` 目录。

---

## 更新

```bash
cd fortigate-mcp-server
git pull
```

然后按部署方式重启：

| 部署方式 | 重启命令 |
|---|---|
| systemd | `systemctl --user restart fortigate-mcp`（部署了多个 unit 请一并重启） |
| Docker | `docker compose up -d --build` |
| 手动前台运行 | Ctrl-C 后重新执行启动命令 |

- 依赖有变化才需重装：`git diff ORIG_HEAD HEAD -- pyproject.toml` 有输出则执行 `uv pip install -e .`
- 用 `git clone` 而不是下载 ZIP：ZIP 解出的目录没有 `.git`，无法增量更新
- 新的 FortiOS 版本支持随仓库发布，`git pull` 后即可用，无需自行下载 Fortinet 文档
- `config/config.json`、`certs/`、`logs/` 不受 `git pull` 影响（已在 `.gitignore` 中）

验证：

```bash
curl -s http://localhost:8815/health
```

---

## 接入 MCP Client

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
      "args": ["-m", "src.fortigate_mcp.server"],
      "env": {
        "FORTIGATE_MCP_CONFIG": "/path/to/config/config.json"
      }
    }
  }
}
```

不同 MCP Client 的配置格式可能略有差异。

---

## 常用工具

```text
# 设备
list_devices  get_device_status  test_device_connection  get_system_status

# 防火墙
list_firewall_policies  get_firewall_policy_detail
create_firewall_policy  update_firewall_policy  delete_firewall_policy

# 网络 / VPN / 系统
list_interfaces  get_routing_table  monitor_network_arp  monitor_network_lldp_neighbors
monitor_vpn_ipsec  monitor_vpn_ssl
monitor_virtual_wan_health_check  monitor_virtual_wan_members  monitor_virtual_wan_sla_log
monitor_system_status  monitor_system_resource_usage  monitor_system_sensors
monitor_system_ha_status  monitor_system_storage

# 通用 API —— 可访问任意未单独封装的 FortiOS 端点
cmdb_list  cmdb_get  cmdb_create  cmdb_update  cmdb_delete  monitor_request

# API 目录 —— 离线查询，不连设备
list_api_endpoints        # 查端点，如 module="router", version="8.0.1"
get_api_endpoint_schema   # 写配置前查字段，避免 -651 / -56
check_api_compatibility   # 404 排查：该端点在当前设备版本存在吗
```

---

## 安全建议

- 推荐使用 **FortiGate API Token**，避免使用管理员密码
- MCP Server 保持 **Bearer Token 认证**开启
- 生产环境使用可信 CA 证书并保持客户端证书校验
- MCP Server 仅暴露在可信网络、VPN 或安全反向代理之后
- FortiGate REST API 管理员遵循最小权限原则
- 对生产环境的配置写操作，建议在 Agent 侧增加权限控制或人工审批

> MCP 工具包含配置写操作。接入生产 FortiGate 前，请确认调用权限、审批流程和审计策略。

---

## License

MIT License.

## Acknowledgements

- [alpadalar/fortigate-mcp-server](https://github.com/alpadalar/fortigate-mcp-server) — 本项目基于其工作继续扩展和完善
- [Model Context Protocol](https://modelcontextprotocol.io/) · [FastMCP](https://github.com/jlowin/fastmcp) · [Fortinet Documentation](https://docs.fortinet.com/) · [httpx](https://www.python-httpx.org/)
