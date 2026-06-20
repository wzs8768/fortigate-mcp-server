<!-- FortiGate MCP Server — FortiOS 8.0 REST API 管理服务器 — 279 MCP 工具 · 540+ API 方法 · 1023+ CMDB 端点 -->
<p align="center">
  <img src="https://img.shields.io/badge/FortiGate-MCP%20Server-blue?style=for-the-badge&logo=fortinet&logoColor=white" alt="FortiGate MCP Server"/>
</p>

<h1 align="center">FortiGate MCP Server</h1>

<p align="center">
  <strong>基于 Model Context Protocol (MCP) 的 FortiGate 防火墙管理服务器</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/MCP-1.0-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/API方法-540+-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/MCP工具-279+-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/覆盖模块-129+-purple?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"/>
</p>

---

## 概述

FortiGate MCP Server 通过 [Model Context Protocol](https://modelcontextprotocol.io/) 暴露 FortiGate 防火墙管理能力，让 AI 助手和 MCP 兼容工具可以编程化管理防火墙策略、网络对象、路由、VPN、安全 Profile、用户认证、日志、监控等。

基于 **全异步 Python** 构建，支持持久化 HTTP 连接池，安全优先默认配置。

**已覆盖 FortiOS 8.0 全部四大类 API：**

| API 类 | 路径 | 方法数 |
|--------|------|--------|
| Configuration | `/api/v2/cmdb/` | 480+ |
| Monitor | `/api/v2/monitor/` | 39 |
| Log | `/api/v2/log/` | 8 |
| Service | `/api/v2/service/` | 9 |

---

## 功能

### 设备管理
- 多设备并发管理
- API Token / 用户名密码两种认证
- 连接测试和健康监控
- VDOM 发现和按 VDOM 操作

### 防火墙策略
- 完整 CRUD：IPv4/IPv6 策略、Security Policy、Proxy Policy、Multicast Policy、DoS Policy、Local-in Policy、Interface Policy、Shaping Policy、TTL Policy
- 策略详情含地址/服务对象解析
- UTM Profile 绑定（IPS/AV/WF/DLP/SSL 等）

### 网络对象
- 地址对象（IP 子网、IP 范围、FQDN、通配符 FQDN）、地址组
- 服务对象（TCP/UDP/SCTP）、服务组
- 时间调度（一次性、周期、调度组）
- IPv6 地址和地址组

### NAT 和流量管理
- VIP/端口映射、VIP 组
- IP 池、Central SNAT Map
- IP 转换、DNS 转换
- 流量整形（共享 + 每 IP）

### 安全 Profile
- IPS Sensor、DLP Sensor/Profile、Antivirus、Web Filter、DNS Filter、Email Filter
- SSL/SSH 深度检测、WAF、VoIP、Video Filter、Virtual Patch
- Application Control、CASB、SSH Filter、SCTP Filter
- Profile Group、Protocol Options

### VPN
- IPSec Phase1/Phase2 Interface (CRUD)
- SSL VPN Settings / Portal
- 监控：IPSec/SSL VPN 状态、连接数

### 用户和认证
- 本地用户、用户组 (CRUD)
- LDAP / RADIUS 服务器
- 认证规则和方案

### 系统和网络
- DHCP Server、SNMP Community
- 证书管理（CA/本地）
- 防火墙全局设置、日志设置
- 告警邮件

### 路由和接口
- 静态路由 CRUD
- 路由表、BGP Neighbors/Paths 监控
- 接口配置更新
- ARP 表、LLDP 邻居

### 监控
- IPSec/SSL VPN 状态和统计
- SD-WAN Health Check / Members / SLA Log
- 防火墙用户、在线用户数
- License 许可状态
- 日志磁盘使用率、FortiAnalyzer/FortiCloud 状态
- IPS 性能统计、FortiGuard 通信统计
- FortiView 实时统计、GeoIP 查询
- UTM 应用分类和查找

### 工具
- 抓包（Sniffer）：列表/创建/更新/删除

---

## 快速开始

### 环境要求

- Python 3.11+
- 已启用 API 的 FortiGate 设备
- API Token（推荐）或管理员账号

### 安装

```bash
git clone https://github.com/wzs8768/fortigate-mcp-server.git
cd fortigate-mcp-server

# 方式一：pip
python -m venv .venv
source .venv/bin/activate
pip install -e .

# 方式二：uv（推荐，更快）
uv venv
source .venv/bin/activate
uv pip install -e .
```

### 配置

创建配置文件 `config/config.json`（**文件位置**：`<项目目录>/config/config.json`）：

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8814,
    "name": "fortigate-mcp-server",
    "version": "2.0.0"
  },
  "fortigate": {
    "devices": {
      "FW-01": {
        "host": "192.168.1.1",
        "port": 443,
        "api_token": "<FortiGate-API-Token>",
        "vdom": "root",
        "verify_ssl": false,
        "timeout": 30
      },
      "FW-02": {
        "host": "192.168.1.2",
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
      {"name": "hermes-local", "token": "<your-generated-token>"}
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

> 基于 FortiOS 8.0 适配开发，其他版本 API 可能存在差异，使用前请自行验证。

### 配置字段说明

| 字段 | 说明 |
|------|------|
| `fortigate.devices` | 管理的 FortiGate 设备列表，每台设备一个命名字段 |
| `fortigate.devices.<name>.api_token` | FortiGate 设备本身的 API Token（在 FortiGate 上生成）。**优先于 username/password**，两者同时配置时以 api_token 为准 |
| `fortigate.devices.<name>.username` / `password` | 用户名密码认证（备选，推荐用 api_token） |
| `auth.api_tokens` | **MCP Server 认证 Token 列表**，客户端连接时携带，服务端验证 |
| `auth.api_tokens[].name` | Token 名称/标签，用于识别使用者（如 `hermes-local`、`张三-claude`） |
| `auth.api_tokens[].token` | Token 值，用 `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` 生成。⚠️ 这是 **MCP Server 认证 Token**（本机生成），不要与上方 `api_token`（FortiGate 设备 API Token）混淆。 |
| `logging.file` | 日志文件路径，认证日志会记录客户端名称（如 `Auth OK — client=hermes-local`） |

### 启动服务

**STDIO**（本地直连，不走网络）→ `server.py`

```bash
export FORTIGATE_MCP_CONFIG=config/config.json
python -m src.fortigate_mcp.server
```

**HTTP / HTTPS**（网络访问）→ `server_http.py`

```bash
# HTTPS · SSE + Streamable HTTP 同时（可选，需要自签名证书，见下方）
python -m src.fortigate_mcp.server_http --host 0.0.0.0 --port 8814 \
  --transport all --ssl-cert certs/server.crt --ssl-key certs/server.key

# HTTP · SSE + Streamable HTTP 同时
python -m src.fortigate_mcp.server_http --host 0.0.0.0 --port 8815 --transport all
```

| `--transport` | 端点 |
|---------------|------|
| `all`（推荐） | `/fortigate-mcp` + `/fortigate-mcp-sse` 同时 |
| `streamable-http`（CLI 默认） | `/fortigate-mcp` |
| `sse` | `/fortigate-mcp-sse` |

> `server_http.py` 默认走 HTTP，加了 `--ssl-cert` + `--ssl-key` 就是 HTTPS，**与 `--transport` 无关**。要同时提供 HTTP 和 HTTPS，起两个进程用不同端口即可。

**自签名证书（内网测试）：**

```bash
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key \
  -out certs/server.crt -days 3650 -nodes \
  -subj "/CN=<你的服务器IP>" -addext "subjectAltName=IP:<你的服务器IP>"
```

**systemd 服务（开机自启）：**

```bash
cp contrib/fortigate-mcp.service ~/.config/systemd/user/
# 编辑 ExecStart 行，按需设置 --transport / --ssl-cert / --ssl-key
systemctl --user daemon-reload
systemctl --user enable --now fortigate-mcp
```

### Docker 部署

无需安装 Python 环境，一条命令启动：

```bash
# 1. 克隆仓库并准备配置
git clone https://github.com/wzs8768/fortigate-mcp-server.git
cd fortigate-mcp-server

# 2. 创建 config/config.json（见上方[配置](#配置)）

# 3. 启动（HTTP · :8815）
docker compose up -d
```

**HTTPS 模式：**

```bash
# 1. 生成自签名证书
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key \
  -out certs/server.crt -days 3650 -nodes \
  -subj "/CN=<服务器IP>" -addext "subjectAltName=IP:<服务器IP>"

# 2. 编辑 docker-compose.yml，取消 HTTPS 端口映射注释，添加启动参数：
#    command: [..., "--ssl-cert", "/app/certs/server.crt", "--ssl-key", "/app/certs/server.key", "--port", "8814"]

docker compose up -d
```

**容器特性：**

| 特性 | 说明 |
|------|------|
| 多阶段构建 | builder + runtime，镜像精简 |
| 安全运行 | 非 root 用户 `fgtmcp` |
| 健康检查 | 每 30 秒 `GET /health` |
| 资源限制 | CPU 1 核 / 内存 512M |
| 日志持久化 | `./logs` 目录挂载 |
| 配置挂载 | `config/`、`certs/` 只读挂载 |

### MCP 客户端集成

#### 场景一：客户端与服务器在同一台机器（STDIO 模式）

客户端直接启动进程，无需预运行服务：

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "python",
      "args": ["-m", "src.fortigate_mcp.server"],
      "env": { "FORTIGATE_MCP_CONFIG": "/path/to/config.json" }
    }
  }
}
```

适用于 Claude Desktop、OpenCode、Codex CLI 等 STDIO transport 客户端。

#### 场景二：客户端与服务器不在同一台机器（HTTP / HTTPS 模式）⭐

> **想同时提供 HTTP 和 HTTPS？** 启动两个进程，用不同端口（如 HTTPS→8814，HTTP→8815），按下方对应地址连接。

```json
// HTTPS · Streamable HTTP
{ "url": "https://<服务器IP>:8814/fortigate-mcp",           "transport": "streamable-http" }

// HTTPS · SSE
{ "url": "https://<服务器IP>:8814/fortigate-mcp-sse",       "transport": "sse" }

// HTTP · Streamable HTTP
{ "url": "http://<服务器IP>:8815/fortigate-mcp",            "transport": "streamable-http" }

// HTTP · SSE
{ "url": "http://<服务器IP>:8815/fortigate-mcp-sse",        "transport": "sse" }
```

> ⚠️ Claude Desktop **仅支持 STDIO transport**，远程连接需通过 `mcp-remote` 中转（见下方 Windows 配置），走 HTTPS。

各客户端配置文件位置：

| 客户端 | 配置文件 |
|--------|---------|
| Claude Desktop (macOS/Linux) | `~/.claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%LOCALAPPDATA%\Packages\Claude_<随机字符串>\LocalCache\Roaming\Claude\claude_desktop_config.json` |
| OpenCode | `~/.opencode/config.json` 或 `--mcp-config` 参数 |
| Cursor | `~/.cursor/mcp_servers.json` |
| Codex CLI | `~/.codex/mcp_servers.json` |
| Hermes | `~/.hermes/config.yaml` → `mcp_servers` 段 |
| OpenClaw | `~/.openclaw/openclaw.json` → `mcp.servers` 段 |

#### Windows Claude Desktop（自签名证书 / TLS 跳过验证）

Windows 版 Claude Desktop 不支持直接在配置中设置 `ssl_verify: false`，需使用 `mcp-remote` 中转并设置环境变量绕过证书验证：

**前置依赖：安装 Node.js**

```powershell
# PowerShell（管理员）
winget install OpenJS.NodeJS.LTS
```

**Claude Desktop 配置（JSON 格式，`claude_desktop_config.json`）：**

> 配置文件路径示例：`C:\Users\<用户名>\AppData\Local\Packages\Claude_<随机字符串>\LocalCache\Roaming\Claude\`（Windows 商店版），可通过文件资源管理器地址栏输入 `%LOCALAPPDATA%\Packages\` 定位 `Claude_*` 目录。

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://<服务器IP>:8814/fortigate-mcp",
        "--transport",
        "streamable-http",
        "--header",
        "Authorization:${FORTIGATE_AUTH}"
      ],
      "env": {
        "NODE_TLS_REJECT_UNAUTHORIZED": "0",
        "FORTIGATE_AUTH": "Bearer <your-shared-token>"
      }
    }
  },
  "coworkUserFilesPath": "C:\\Users\\<用户名>\\Claude",
  "preferences": { "...": "..." }
}
```

> 在已有的 `claude_desktop_config.json` 文件中，将 `mcpServers` 块合并进去即可，其余配置项保持不变。

> `NODE_TLS_REJECT_UNAUTHORIZED=0` 跳过 TLS 证书验证，适用于自签名证书环境。生产环境建议将证书导入系统受信任根。

#### 远程访问安全加固

`auth` 配置已在 [配置](#配置) 节完整给出（`config/config.json` → `auth.api_tokens`），此处补充操作说明：

**1. 生成 Token：**
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

**2. 写入 `config/config.json` 的 `auth.api_tokens` 数组**（见上方完整配置示例）。

**3. 多客户端 Token 命名示例：**
```json
"auth": {
  "require_auth": true,
  "api_tokens": [
    {"name": "hermes-local", "token": "<token-1>"},
    {"name": "claude-win",    "token": "<token-2>"},
    {"name": "cursor-laptop", "token": "<token-3>"}
  ]
}
```

> 也兼容旧格式（裸字符串）：`"api_tokens": ["token1", "token2"]`，自动标记为 `(unnamed)`。

**4. 重启服务生效：** `systemctl --user restart fortigate-mcp`

**5. Claude Desktop 客户端配置 — 见上方 [Windows Claude Desktop](#windows-claude-desktop自签名证书--tls-跳过验证) 节的完整 `claude_desktop_config.json` 示例。**
```

> `--header "Authorization:${FORTIGATE_AUTH}"` 中 `:` 和 `Bearer` 之间无空格，避免 Windows 版 Claude Desktop 的参数空格 bug。

Hermes Agent 配置（YAML 格式，`~/.hermes/config.yaml`）：

```yaml
mcp_servers:
  fortigate:
    url: https://<服务器IP>:8814/fortigate-mcp
    enabled: true
    ssl_verify: false
    connect_timeout: 30
    headers:
      Authorization: "Bearer <your-shared-token>"
```

> Hermes 的 HTTP 配置（无需证书）：将 `url` 改为 `http://<服务器IP>:8815/fortigate-mcp`，删除 `ssl_verify` 行。

Codex CLI 配置（TOML 格式，`~/.codex/config.toml` 或项目 `.codex.toml`）：

```toml
[mcp_servers.fortigate]
enabled = true
url = "http://<服务器IP>:8815/fortigate-mcp"

[mcp_servers.fortigate.http_headers]
Authorization = "Bearer <your-shared-token>"
Accept = "application/json, text/event-stream"
```

> ⚠️ Codex **必须使用 HTTP（8815 端口）**——Codex 不支持跳过自签名证书验证，HTTPS 连接会因证书错误失败。

Cursor / OpenCode / OpenClaw 等 JSON 格式客户端（**HTTPS**）：

Cursor / OpenCode：
```json
{
  "mcpServers": {
    "fortigate": {
      "url": "https://<服务器IP>:8814/fortigate-mcp",
      "transport": "streamable-http",
      "headers": {
        "Authorization": "Bearer <your-shared-token>"
      }
    }
  }
}
```

OpenClaw（需使用 `rejectUnauthorized` 字段，`mcp.servers` 块放在 `openclaw.json` 末尾）：
```json
{
  "mcp": {
    "servers": {
      "FortiGate": {
        "url": "https://<服务器IP>:8814/fortigate-mcp",
        "transport": "streamable-http",
        "rejectUnauthorized": false,
        "headers": {
          "Authorization": "Bearer <your-shared-token>"
        }
      }
    }
  }
}
```

---

## MCP 工具列表（279）

> 以下列出代表性工具，完整 279 个工具覆盖 1023+ FortiOS API 端点，含 CMDB 通用 CRUD、日志查询、监控等。

### 设备管理 (7)
`list_devices` `get_device_status` `test_device_connection` `add_device` `remove_device` `discover_vdoms` `list_vdoms`

### 防火墙策略 (53)
`list_firewall_policies` `create/update/delete_firewall_policy` `get_firewall_policy_detail`
`list_security_policies` `create/update/delete_security_policy` `get_security_policy_detail`
`list_proxy_policies` `create/update/delete_proxy_policy` `get_proxy_policy_detail`
`list_proxy_addresses` `create/update/delete_proxy_address` `list_proxy_addrgrps` `create/update/delete_proxy_addrgrp`
`list_dos_policies` `create/update/delete_dos_policy`
`list_local_in_policies` `create/update/delete_local_in_policy`
`list_interface_policies` `create/update/delete_interface_policy`
`list_multicast_policies` `create/update/delete_multicast_policy`
`list_multicast_addresses` `create/update/delete_multicast_address`
`list_shaping_policies` `create/update/delete_shaping_policy` `list_shaping_profiles` `create/update/delete_shaping_profile`
`get_firewall_global` `update_firewall_global`
`list_sniffers` `create/update/delete_sniffer`

### 地址和地址组 (17)
`list_address_objects` `create/update/delete_address_object`
`list_addrgrps` `create/update/delete_addrgrp` `get_addrgrp_detail`
`list_wildcard_fqdn_custom` `create/update/delete_wildcard_fqdn_custom`
`list_wildcard_fqdn_group` `create/update/delete_wildcard_fqdn_group`

### 服务和服务组 (8)
`list_service_objects` `create/update/delete_service_object`
`list_service_groups` `create/update/delete_service_group`

### 时间调度 (12)
`list_schedule_onetime` `create/update/delete_schedule_onetime`
`list_schedule_recurring` `create/update/delete_schedule_recurring`
`list_schedule_group` `create/update/delete_schedule_group`

### NAT/VIP/流量整形 (45)
`list_ippools` `create/update/delete_ippool`
`list_vipgrps` `create/update/delete_vipgrp`
`list_virtual_ips` `create/update/delete_virtual_ip` `get_virtual_ip_detail`
`list_central_snat_maps` `create/update/delete_central_snat_map` `get_central_snat_map_detail`
`list_traffic_shapers` `create/update/delete_traffic_shaper`
`list_per_ip_shapers` `create/update/delete_per_ip_shaper`
`list_ip_translations` `create/update/delete_ip_translation`
`list_dns_translations` `create/update/delete_dns_translation`
`list_ttl_policies` `create/update/delete_ttl_policy`
`list_decrypted_traffic_mirrors` `create/update/delete_decrypted_traffic_mirror`

### 安全 Profile (44)
`list_ssl_ssh_profiles` `create/update/delete_ssl_ssh_profile`
`list_ssl_servers` `create/update/delete_ssl_server`
`list_ips_sensors` `create/update/delete_ips_sensor` `get_ips_sensor_detail`
`list_profile_groups` `create/update/delete_profile_group`
`list_profile_protocol_options` `create/update/delete_profile_protocol_options`
`list_dnsfilter_profiles` `create_dnsfilter_profile` `list_dnsfilter_domain_filters`
`list_dlp_sensors` `list_dlp_profiles` `get_dlp_settings`
`list_emailfilter_profiles`
`list_antivirus_profiles` `get_antivirus_settings`
`list_webfilter_profiles` `list_webfilter_urlfilters`
`list_waf_profiles` `list_voip_profiles` `list_videofilter_profiles` `list_virtual_patch_profiles`
`list_application_groups` `list_application_lists`
`list_ssh_filter_profiles` `list_sctp_filter_profiles`
`list_casb_profiles` `list_web_proxy_profiles` `list_diameter_filter_profiles`

### VPN (4)
`list_vpn_ipsec_phase1_interfaces` `list_vpn_ipsec_phase2_interfaces`
`get_vpn_ssl_settings` `list_vpn_ssl_web_portals`

### 用户和认证 (10)
`list_user_locals` `list_user_groups` `list_user_ldaps` `list_user_radiuses`
`get_user_setting` `list_auth_rules` `create_auth_rule` `list_auth_schemes` `get_auth_setting`

### 证书 (2)
`get_certificate_ca` `get_certificate_local`

### 路由和接口 (9)
`list_static_routes` `create/update/delete_static_route` `get_static_route_detail` `get_routing_table`
`list_interfaces` `get_interface_status` `update_interface`
`list_identity_based_routes` `create/update/delete_identity_based_route`

### 系统管理 (3)
`list_system_dhcp_servers` `list_system_snmp_communities` `get_system_status`

### 交换机管理 (2)
`list_switch_acl_groups` `list_switch_8021x_policies`

### 日志 (12)
`get_log_setting` `update_log_setting` `get_log_disk_setting` `update_log_disk_setting` `get_log_fortianalyzer_setting` `update_log_fortianalyzer_setting` `get_log_syslogd_setting` `update_log_syslogd_setting` `get_logs` `get_logs_raw` `monitor_log_current_disk_usage` `monitor_log_fortianalyzer`

### 监控 (42)

**VPN 监控：** `monitor_vpn_ipsec` `monitor_vpn_ipsec_connection_count` `monitor_vpn_ssl` `monitor_vpn_ssl_stats`

**用户监控：** `monitor_user_firewall` `monitor_user_firewall_count` `monitor_user_banned` `monitor_user_fsso`

**SD-WAN：** `monitor_virtual_wan_health_check` `monitor_virtual_wan_members` `monitor_virtual_wan_sla_log`

**路由：** `monitor_router_ipv4` `monitor_router_ipv6` `monitor_router_bgp_neighbors` `monitor_router_bgp_paths`

**防火墙：** `monitor_firewall_policy` `monitor_firewall_sessions` `monitor_firewall_policy_lookup` `monitor_firewall_acl` `monitor_firewall_acl6`

**系统：** `monitor_system_status` `monitor_system_resource_usage` `monitor_system_performance_status` `monitor_system_interface` `monitor_system_current_admins` `monitor_system_firmware` `monitor_system_vm_information` `monitor_system_available_interfaces`
> `monitor_system_resource_usage` 支持 `scope` 参数：`"current"`（默认，仅最新快照）| `"global"`（全量历史）

**网络：** `monitor_network_arp` `monitor_network_lldp_neighbors` `monitor_network_dns_latency` `monitor_network_reverse_ip_lookup`

**安全：** `monitor_ips_rate_based` `monitor_ips_session_performance` `monitor_fortiguard_service_stats` `monitor_webfilter_fortiguard_categories` `monitor_fortiview_realtime_stats`

**许可/注册：** `monitor_license_status` `monitor_registration_forticloud_status`

**UTM/其他：** `monitor_utm_app_lookup` `monitor_utm_application_categories` `monitor_utm_applications` `monitor_geoip_query`

**通用：** `monitor_request` — 覆盖全部 39 个 `/api/v2/monitor/` GET/POST 端点

### CMDB 通用 CRUD (5)
`cmdb_list` `cmdb_get` `cmdb_create` `cmdb_update` `cmdb_delete`

### 其他 (4)
`health_check` `get_server_info` `get_alertemail_setting` `get_endpoint_control_settings`

---

## 架构

```
fortigate-mcp-server/
├── src/fortigate_mcp/
│   ├── auth_middleware.py        # Bearer Token 认证中间件
│   ├── server.py                 # STDIO MCP 服务器 (FastMCP)
│   ├── server_http.py            # HTTP MCP 服务器 (FastMCP)
│   ├── config/
│   │   ├── loader.py             # 配置文件加载
│   │   └── models.py             # Pydantic 配置模型
│   ├── core/
│   │   ├── fortigate.py          # 异步 API 客户端 + 设备管理器 (540+ 方法，2600+ 行)
│   │   └── logging.py            # 结构化日志
│   ├── tools/
│   │   ├── base.py               # 工具基类（错误处理、格式化）
│   │   ├── definitions.py        # 工具描述常量
│   │   ├── cmdb.py               # 通用 CMDB CRUD 工具（覆盖 1023+ 端点）
│   │   ├── device.py             # 设备管理工具
│   │   ├── firewall.py           # 防火墙策略工具
│   │   ├── network.py            # 地址/服务/FQDN 对象工具
│   │   ├── routing.py            # 路由和接口工具
│   │   ├── virtual_ip.py         # VIP 工具
│   │   ├── schedules.py          # 时间调度工具
│   │   ├── resources.py          # IP池/VIP组/SNAT/整形器工具
│   │   └── security.py           # 安全 Profile/用户/认证/VPN/系统工具
│   └── formatting/
│       ├── formatters.py         # MCP 内容格式化
│       └── templates.py          # 响应模板
├── config/
│   └── config.json               # 设备配置示例
├── tests/
├── README.md
└── LICENSE
```

### 设计原则

- **全异步**：所有 API 调用使用 `httpx.AsyncClient`，每设备持久化连接池
- **安全优先**：SSL 验证默认开启，CORS 默认空（`allowed_origins: []`），强制 Bearer Token 认证
- **清晰分层**：配置模型、API 客户端、工具逻辑、格式化独立
- **错误分类**：FortiGate API 错误映射为人类可读信息

---

## 安全

| 设置 | 默认值 | 说明 |
|------|--------|------|
| `verify_ssl` | `true` | SSL 证书验证 |
| `allowed_origins` | `[]` | 无 CORS（显式按需开启） |
| `require_auth` | `true` | MCP 服务器强制认证（所有客户端必须提供 Bearer Token） |

**生产环境建议：**
- 使用 **API Token** 而非用户名密码
- 保持 `verify_ssl: true`（自签证书测试除外）
- HTTP 模式下设置明确的 `allowed_origins`
- 在可信网络内或反向代理后运行
- 敏感配置使用环境变量

---

## 常见问题

**连接被拒绝**
- 确认 FortiGate 设备可达且 API 已启用
- 检查端口 443 未被防火墙拦截

**认证失败 (401)**
- 验证 API Token 有效且权限足够
- 用户名密码模式确认账号密码正确

**SSL 证书错误**
- 实验环境自签证书：设置 `verify_ssl: false`
- 生产环境：在 FortiGate 上安装有效证书

**VDOM 未找到**
- 使用 `discover_vdoms` 查看可用 VDOM
- VDOM 名称大小写敏感

**策略创建 500 错误**
- FortiOS 8.0 必需 `"schedule": "always"` 字段
- 地址/服务对象含 `/` 需 URL 编码（已内置处理）

---

## CI/CD

每次 push 到 `main` 分支自动运行（`.github/workflows/ci.yml`）：

| Job | 说明 |
|-----|------|
| Lint | `ruff check src/` 代码风格检查 |
| Build | `python -m build` 验证包结构 |
| Docker | `docker build` 验证镜像构建 |

---

## 许可

MIT License. 详见 [LICENSE](LICENSE)

## 致谢

- [alpadalar/fortigate-mcp-server](https://github.com/alpadalar/fortigate-mcp-server) — 原始项目
- [Model Context Protocol](https://modelcontextprotocol.io/) — 协议规范
- [FastMCP](https://gofastmcp.com/) — Python MCP 服务器框架
- [FortiGate 产品文档](https://docs.fortinet.com/) — FortiGate 官方文档
- [httpx](https://www.python-httpx.org/) — 异步 HTTP 客户端
