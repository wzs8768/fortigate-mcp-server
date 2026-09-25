<!-- FortiGate MCP Server — FortiOS 7.4.12 / 7.6.7 / 8.0.0 / 8.0.1 REST API Management Server — 286 MCP Tools · 1650 API Endpoints -->
<p align="center">
  <img src="https://img.shields.io/badge/FortiGate-MCP%20Server-blue?style=for-the-badge&logo=fortinet&logoColor=white" alt="FortiGate MCP Server"/>
</p>

<h1 align="center">FortiGate MCP Server</h1>

<p align="center">
  <a href="README.md">🇨🇳 中文</a> &nbsp;|&nbsp; <strong>🇺🇸 English</strong>
</p>

<p align="center">
  <strong>Query and manage FortiGate from any MCP-compatible AI assistant</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/MCP_Tools-286+-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/Endpoints-1650+-purple?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"/>
</p>

---

## Overview

Wraps the FortiGate REST API as MCP tools, so Claude, ChatGPT, Hermes, Codex, Cursor and other MCP clients can query, troubleshoot and configure FortiGate in natural language.

- **286 MCP tools** covering **1650 FortiOS REST endpoints** (CMDB / Monitor / Log / Service)
- Multiple FortiGates / VDOMs, fully asynchronous
- STDIO / Streamable HTTP / SSE, HTTP / HTTPS
- FortiGate API Token authentication + MCP Server Bearer Token authentication

Validated against **FortiOS 7.4.12 / 7.6.7 / 8.0.0 / 8.0.1**; other releases may differ, so verify before production use.

The device's FortiOS version is auto-detected on first use — no manual configuration. Calling an endpoint a
build does not have says so (and names the releases that do) instead of returning FortiOS' bare
`404` / `500 -651`; `list_api_endpoints` / `get_api_endpoint_schema` / `check_api_compatibility` look up
endpoints, fields and version availability offline.

---

## Key Capabilities

| Category | Capabilities |
|---|---|
| Firewall | Policy, Address, Service, VIP, IP Pool, Central SNAT |
| Security | IPS, AV, Web Filter, DNS Filter, DLP, SSL Inspection, Application Control |
| VPN | IPSec VPN, SSL VPN configuration & status |
| Network | Interface, Static Route, BGP, ARP, LLDP |
| SD-WAN | Health Check, Members, SLA Log |
| Authentication | Local User, User Group, LDAP, RADIUS |
| System | Status, HA, Sensor, Resource, Storage, NTP, License |
| Log | FortiGate Log, FortiAnalyzer / FortiCloud status |
| Generic API | CMDB CRUD, generic Monitor API calls, API catalog lookups |

---

## Quick Start

Requirements: Python 3.11+, a FortiGate with the REST API enabled, and a FortiGate API Token (recommended)

```bash
git clone https://github.com/wzs8768/fortigate-mcp-server.git
cd fortigate-mcp-server

python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Faster with `uv`: `uv venv && source .venv/bin/activate && uv pip install -e .`

---

## Configuration

Create `config/config.json`:

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

Two different tokens, easy to confuse:

| Setting | Direction | Notes |
|---|---|---|
| `fortigate.devices.<name>.api_token` | MCP Server → FortiGate | Generated on the FortiGate |
| `auth.api_tokens[].token` | MCP Client → MCP Server | Generated locally: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` |

- Device auth accepts `api_token` (recommended) or `username` + `password`; if both are set, `api_token` wins
- `verify_ssl` controls **MCP Server → FortiGate** certificate checking — unrelated to whether your client trusts `server.crt`

---

## Starting the Server

### STDIO (local, no network)

```bash
export FORTIGATE_MCP_CONFIG=config/config.json
python -m src.fortigate_mcp.server
```

### HTTP / HTTPS

```bash
# HTTP
python -m src.fortigate_mcp.server_http --host 0.0.0.0 --port 8815 --transport all

# HTTPS: generate a self-signed certificate first, then start
mkdir -p certs
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/server.key -out certs/server.crt \
  -days 3650 -nodes \
  -subj "/CN=<server-ip>" -addext "subjectAltName=IP:<server-ip>"

python -m src.fortigate_mcp.server_http --host 0.0.0.0 --port 8814 --transport all \
  --ssl-cert certs/server.crt --ssl-key certs/server.key
```

`subjectAltName` must match the address clients actually use: `IP:192.168.1.10` when connecting by IP,
`DNS:mcp.example.local` when connecting by hostname.
Have the client trust `certs/server.crt` (import it into the system trust store — on Windows install to
"Trusted Root Certification Authorities", on macOS import into System Keychain and set Always Trust, on
Ubuntu `cp certs/server.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`).
Production should use a certificate from a trusted CA.

Endpoints:

```text
Streamable HTTP: http(s)://<server>:8814/fortigate-mcp
SSE:             http(s)://<server>:8814/fortigate-mcp-sse
```

### systemd (auto-start on boot)

```bash
cp contrib/fortigate-mcp.service ~/.config/systemd/user/
# edit the ExecStart line for --transport / --ssl-cert / --ssl-key
systemctl --user daemon-reload
systemctl --user enable --now fortigate-mcp

# start without a user login after reboot
sudo loginctl enable-linger $USER
```

### Docker

```bash
git clone https://github.com/wzs8768/fortigate-mcp-server.git
cd fortigate-mcp-server
# create config/config.json (see Configuration above)
docker compose up -d
```

HTTPS mode needs certificates generated on the host and the `certs/` directory mounted.

---

## Updating

```bash
cd fortigate-mcp-server
git pull
```

Then restart according to how you deployed it:

| Deployment | Restart command |
|---|---|
| systemd | `systemctl --user restart fortigate-mcp` (restart every unit you deployed) |
| Docker | `docker compose up -d --build` |
| Foreground / manual | Ctrl-C, then re-run the start command |

- Reinstall only if dependencies changed: run `git diff ORIG_HEAD HEAD -- pyproject.toml` — if it prints anything, run `uv pip install -e .`
- Use `git clone`, not a ZIP download: a ZIP has no `.git`, so it cannot be updated incrementally
- New FortiOS version support ships with the repository — `git pull` is enough, no need to download Fortinet's docs
- `config/config.json`, `certs/` and `logs/` are untouched by `git pull` (they are in `.gitignore`)

Verify:

```bash
curl -s http://localhost:8815/health
```

---

## MCP Client Integration

### Remote (HTTPS)

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
      "args": ["-m", "src.fortigate_mcp.server"],
      "env": {
        "FORTIGATE_MCP_CONFIG": "/path/to/config/config.json"
      }
    }
  }
}
```

Different MCP clients may use slightly different config formats.

---

## Common Tools

```text
# Devices
list_devices  get_device_status  test_device_connection  get_system_status

# Firewall
list_firewall_policies  get_firewall_policy_detail
create_firewall_policy  update_firewall_policy  delete_firewall_policy

# Network / VPN / System
list_interfaces  get_routing_table  monitor_network_arp  monitor_network_lldp_neighbors
monitor_vpn_ipsec  monitor_vpn_ssl
monitor_virtual_wan_health_check  monitor_virtual_wan_members  monitor_virtual_wan_sla_log
monitor_system_status  monitor_system_resource_usage  monitor_system_sensors
monitor_system_ha_status  monitor_system_storage

# Generic API — reaches any endpoint not wrapped individually
cmdb_list  cmdb_get  cmdb_create  cmdb_update  cmdb_delete  monitor_request

# API catalog — offline lookups, no device I/O
list_api_endpoints        # find endpoints, e.g. module="router", version="8.0.1"
get_api_endpoint_schema   # check fields before writing, avoiding -651 / -56
check_api_compatibility   # 404 triage: does this build have the endpoint?
```

---

## Security Recommendations

- Use **FortiGate API Tokens** instead of admin passwords
- Keep **Bearer Token authentication** enabled on MCP Server
- Use trusted CA certificates and keep client certificate verification on in production
- Expose MCP Server only on trusted networks, VPNs or behind a secure reverse proxy
- Give FortiGate REST API administrators least privilege
- Add permission controls or human approval on the agent side for production config writes

> MCP tools include configuration write operations. Before pointing an agent at a production FortiGate,
> confirm the permission model, approval flow and audit policy.

---

## License

MIT License.

## Acknowledgements

- [alpadalar/fortigate-mcp-server](https://github.com/alpadalar/fortigate-mcp-server) — this project builds on and extends that work
- [Model Context Protocol](https://modelcontextprotocol.io/) · [FastMCP](https://github.com/jlowin/fastmcp) · [Fortinet Documentation](https://docs.fortinet.com/) · [httpx](https://www.python-httpx.org/)
