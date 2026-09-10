<!-- FortiGate MCP Server — FortiOS 7.4.12 / 7.6.7 / 8.0.0 REST API Management Server — 283 MCP Tools · 540+ API Methods · 1023+ CMDB Endpoints -->
<p align="center">
  <img src="https://img.shields.io/badge/FortiGate-MCP%20Server-blue?style=for-the-badge&logo=fortinet&logoColor=white" alt="FortiGate MCP Server"/>
</p>

<h1 align="center">FortiGate MCP Server</h1>

<p align="center">
  <a href="README.md">🇨🇳 中文</a> &nbsp;|&nbsp; <strong>🇺🇸 English</strong>
</p>

<p align="center">
  <strong>Firewall Management Server Based on Model Context Protocol (MCP)</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/MCP-1.0-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/API_Methods-540+-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/MCP_Tools-283+-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/CMDB_Endpoints-1023+-purple?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"/>
</p>

---

## Overview

FortiGate MCP Server wraps the FortiGate REST API as MCP tools, enabling AI assistants and MCP-compatible tools (Claude, ChatGPT, Hermes, Codex, Cursor, etc.) to query, troubleshoot, and manage FortiGate firewalls using natural language.

Built with fully asynchronous Python, featuring:

- **283+ MCP Tools**
- **540+ FortiOS API Methods**
- **1023+ CMDB Endpoints**
- Multi-FortiGate / Multi-VDOM support
- FortiGate API Token authentication
- MCP Server Bearer Token authentication
- STDIO / Streamable HTTP / SSE transports
- HTTP / HTTPS

Validated against:

- FortiOS 7.4.12
- FortiOS 7.6.7
- FortiOS 8.0.0

> Other FortiOS versions may have API differences. Verify in a test environment before production use.

---

## Key Capabilities

| Category | Capabilities |
|---|---|
| Firewall | Policy, Address, Service, VIP, IP Pool, Central SNAT |
| Security | IPS, AV, Web Filter, DNS Filter, DLP, SSL Inspection, Application Control |
| VPN | IPSec VPN, SSL VPN configuration & status |
| Network | Interface, Static Route, BGP, ARP, LLDP |
| SD-WAN | Health Check, Members, SLA Log |
| Authentication | Local User, User Group, LDAP, RADIUS, Authentication |
| System | System Status, HA, Sensor, Resource, Storage, NTP, License |
| Log | FortiGate Log, FortiAnalyzer / FortiCloud status |
| Generic API | CMDB CRUD, Monitor API generic calls |

---

## Quick Start

### Requirements

- Python 3.11+
- FortiGate with REST API enabled
- FortiGate API Token (recommended)

### Installation

```bash
git clone https://github.com/wzs8768/fortigate-mcp-server.git
cd fortigate-mcp-server

python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Or use `uv` (faster):

```bash
uv venv
source .venv/bin/activate
uv pip install -e .
```

---

## Configuration

Create `config/config.json` at `<project-root>/config/config.json`:

Complete multi-FortiGate / multi-MCP-Client example:

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

### Config Fields

| Field | Description |
|-------|-------------|
| `fortigate.devices` | Managed FortiGate devices, one named entry per device |
| `fortigate.devices.<name>.api_token` | FortiGate device API Token (generated on the FortiGate). **Takes precedence over username/password** when both are configured |
| `fortigate.devices.<name>.username` / `password` | Username/password auth (fallback; API token recommended) |
| `auth.api_tokens` | **MCP Server auth token list** — clients present these tokens; server validates them |
| `auth.api_tokens[].name` | Token name/label for identification (e.g., `hermes`, `chatgpt`, `claude`) |
| `auth.api_tokens[].token` | Token value. Generate with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`. ⚠️ This is the **MCP Server auth token** (generated locally) — do NOT confuse with the `api_token` above (FortiGate device API token) |
| `logging.file` | Log file path. Auth logs include client name |

---

## Starting the Server

### STDIO (local direct connection, no network)

Best when MCP Client and Server are on the same machine:

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

Endpoints:

```text
Streamable HTTP: http://<server>:8815/fortigate-mcp
SSE:             http://<server>:8815/fortigate-mcp-sse
```

### HTTPS

Generate a self-signed certificate for internal testing:

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

> **SAN note**: `subjectAltName` must match the actual access address
> - Access by IP: `subjectAltName=IP:192.168.1.10`
> - Access by domain: `subjectAltName=DNS:mcp.example.local`

Then start HTTPS:

```bash
python -m src.fortigate_mcp.server_http \
  --host 0.0.0.0 \
  --port 8814 \
  --transport all \
  --ssl-cert certs/server.crt \
  --ssl-key certs/server.key
```

Endpoints:

```text
Streamable HTTP: https://<server>:8814/fortigate-mcp
SSE:             https://<server>:8814/fortigate-mcp-sse
```

### Trusting Self-Signed Certificate in Test Environment

Test environments don't need to disable TLS certificate verification.

You can import the generated `certs/server.crt` into the MCP Client system's trusted root certificate store, then continue using HTTPS normally.

**Windows**

Double-click `server.crt`:

`Install Certificate` → `Local Machine` → `Trusted Root Certification Authorities`

**macOS**

Import `server.crt` into System Keychain and set to `Always Trust`.

**Ubuntu / Debian**

```bash
sudo cp certs/server.crt /usr/local/share/ca-certificates/fortigate-mcp.crt
sudo update-ca-certificates
```

> The IP address or FQDN in the certificate must match the address the MCP Client uses to access the MCP Server. For production, use a certificate issued by a trusted CA.

### systemd Service (auto-start on boot)

```bash
cp contrib/fortigate-mcp.service ~/.config/systemd/user/
# Edit the ExecStart line to set --transport / --ssl-cert / --ssl-key as needed
systemctl --user daemon-reload
systemctl --user enable --now fortigate-mcp

# To start on boot without user login
sudo loginctl enable-linger $USER
```

---

## Docker Deployment

No Python environment required — one command to start:

```bash
# 1. Clone and prepare config
git clone https://github.com/wzs8768/fortigate-mcp-server.git
cd fortigate-mcp-server

# 2. Create config/config.json (see [Configuration](#configuration) above)

# 3. Start (HTTP on :8815)
docker compose up -d
```

HTTPS mode requires generating certs on the host and mounting the `certs/` directory.

---

## MCP Client Integration

### Remote Connection (HTTPS)

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

### Local STDIO

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

Different MCP clients may have slightly different config formats.

---

## Common Tool Examples

```text
# Devices
list_devices
get_device_status
test_device_connection
get_system_status

# Firewall
list_firewall_policies
get_firewall_policy_detail
create_firewall_policy
update_firewall_policy
delete_firewall_policy

# Network
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

# System
monitor_system_status
monitor_system_resource_usage
monitor_system_sensors
monitor_system_ha_status
monitor_system_storage

# Generic API
cmdb_list
cmdb_get
cmdb_create
cmdb_update
cmdb_delete
monitor_request
```

Generic CMDB / Monitor tools provide access to many unsealed FortiOS API endpoints.

---

## Security Recommendations

- Use **FortiGate API Tokens** instead of admin passwords
- Keep **Bearer Token authentication** enabled on MCP Server
- Production: use a trusted CA certificate and keep client TLS verification enabled
- Run MCP Server only in trusted networks, behind VPN or secure reverse proxy
- FortiGate REST API admins should follow the principle of least privilege
- For production config write operations, add permission controls or human approval on the Agent side

> MCP tools include configuration write operations. Before connecting AI Agents to production FortiGate, verify calling permissions, approval workflows, and audit policies.

---

---

## License

MIT License.

## Acknowledgements

Special thanks to the original project and author:

- [alpadalar/fortigate-mcp-server](https://github.com/alpadalar/fortigate-mcp-server) — this project builds on and extends the original work

Also thanks to:

- [Model Context Protocol](https://modelcontextprotocol.io/)
- [FastMCP](https://github.com/jlowin/fastmcp)
- [Fortinet Documentation](https://docs.fortinet.com/)
- [httpx](https://www.python-httpx.org/)