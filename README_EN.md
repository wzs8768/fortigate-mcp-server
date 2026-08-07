<!-- FortiGate MCP Server — FortiOS 7.6.7 / 8.0.0 REST API Management Server — 279 MCP Tools · 540+ API Methods · 1023+ CMDB Endpoints -->
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
  <img src="https://img.shields.io/badge/MCP_Tools-279+-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/Modules-129+-purple?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"/>
</p>

---

## Overview

FortiGate MCP Server exposes FortiGate firewall management capabilities via the [Model Context Protocol](https://modelcontextprotocol.io/), enabling AI assistants and MCP-compatible tools to programmatically manage firewall policies, network objects, routing, VPN, security profiles, user authentication, logging, monitoring, and more.

Built with **fully asynchronous Python**, featuring persistent HTTP connection pooling and security-first defaults.

**Covers all four FortiOS 7.6.7 / 8.0.0 API categories:**

| API Category | Path | Methods |
|-------------|------|---------|
| Configuration | `/api/v2/cmdb/` | 480+ |
| Monitor | `/api/v2/monitor/` | 39 |
| Log | `/api/v2/log/` | 8 |
| Service | `/api/v2/service/` | 9 |

---

## Features

### Device Management
- Multi-device concurrent management
- API Token / Username-Password dual authentication
- Connection testing and health monitoring
- VDOM discovery and per-VDOM operations

### Firewall Policies
- Full CRUD: IPv4/IPv6 Policy, Security Policy, Proxy Policy, Multicast Policy, DoS Policy, Local-in Policy, Interface Policy, Shaping Policy, TTL Policy
- Policy details with resolved address/service objects
- UTM Profile binding (IPS/AV/WF/DLP/SSL, etc.)

### Network Objects
- Address objects (IP subnet, IP range, FQDN, wildcard FQDN), address groups
- Service objects (TCP/UDP/SCTP), service groups
- Time schedules (one-time, recurring, schedule groups)
- IPv6 addresses and address groups

### NAT & Traffic Management
- VIP/port mapping, VIP groups
- IP pools, Central SNAT Map
- IP translation, DNS translation
- Traffic shaping (shared + per-IP)

### Security Profiles
- IPS Sensor, DLP Sensor/Profile, Antivirus, Web Filter, DNS Filter, Email Filter
- SSL/SSH deep inspection, WAF, VoIP, Video Filter, Virtual Patch
- Application Control, CASB, SSH Filter, SCTP Filter
- Profile Group, Protocol Options

### VPN
- IPSec Phase1/Phase2 Interface (CRUD)
- SSL VPN Settings / Portal
- Monitoring: IPSec/SSL VPN status, connection counts

### Users & Authentication
- Local users, user groups (CRUD)
- LDAP / RADIUS servers
- Authentication rules and schemes

### System & Network
- DHCP Server, SNMP Community
- Certificate management (CA/local)
- Firewall global settings, log settings
- Alert emails

### Routing & Interfaces
- Static route CRUD
- Routing table, BGP Neighbors/Paths monitoring
- Interface configuration updates
- ARP table, LLDP neighbors

### Monitoring
- IPSec/SSL VPN status and statistics
- SD-WAN Health Check / Members / SLA Log
- Firewall users, online user count
- License status
- Log disk usage, FortiAnalyzer/FortiCloud status
- IPS performance statistics, FortiGuard communication stats
- FortiView real-time statistics, GeoIP query
- UTM application categories and lookup

### Utilities
- Packet Sniffer: list/create/update/delete

---

## Quick Start

### Requirements

- Python 3.11+
- FortiGate device with API enabled
- API Token (recommended) or admin credentials

### Installation

```bash
git clone https://github.com/wzs8768/fortigate-mcp-server.git
cd fortigate-mcp-server

# Option 1: pip
python -m venv .venv
source .venv/bin/activate
pip install -e .

# Option 2: uv (recommended, faster)
uv venv
source .venv/bin/activate
uv pip install -e .
```

### Configuration

Create `config/config.json` (path: `<project-root>/config/config.json`):

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

> Developed for FortiOS 7.6.7 / 8.0.0 with automatic version detection. Other versions may differ — verify before use.

### Config Fields

| Field | Description |
|-------|-------------|
| `fortigate.devices` | Managed FortiGate devices, one named entry per device |
| `fortigate.devices.<name>.api_token` | FortiGate device API Token (generated on the FortiGate). **Takes precedence over username/password** when both are configured |
| `fortigate.devices.<name>.os_version` | (Optional) FortiOS version, e.g. `"7.6.7"`. Auto-detected and cached on first connection if omitted |
| `fortigate.devices.<name>.username` / `password` | Username/password auth (fallback; API token recommended) |
| `auth.api_tokens` | **MCP Server auth token list** — clients present these tokens; server validates them |
| `auth.api_tokens[].name` | Token name/label for identification (e.g. `hermes-local`, `john-claude`) |
| `auth.api_tokens[].token` | Token value. Generate with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`. ⚠️ This is the **MCP Server auth token** (generated locally) — do NOT confuse with the `api_token` above (FortiGate device API token) |
| `logging.file` | Log file path. Auth logs include client name (e.g. `Auth OK — client=hermes-local`) |

### Starting the Server

**STDIO** (local direct connection, no network) → `server.py`

```bash
export FORTIGATE_MCP_CONFIG=config/config.json
python -m src.fortigate_mcp.server
```

**HTTP / HTTPS** (network access) → `server_http.py`

```bash
# HTTPS · SSE + Streamable HTTP simultaneously (requires self-signed certs, see below)
python -m src.fortigate_mcp.server_http --host 0.0.0.0 --port 8814 \
  --transport all --ssl-cert certs/server.crt --ssl-key certs/server.key

# HTTP · SSE + Streamable HTTP simultaneously
python -m src.fortigate_mcp.server_http --host 0.0.0.0 --port 8815 --transport all
```

| `--transport` | Endpoint |
|---------------|----------|
| `all` (recommended) | `/fortigate-mcp` + `/fortigate-mcp-sse` |
| `streamable-http` (CLI default) | `/fortigate-mcp` |
| `sse` | `/fortigate-mcp-sse` |

> `server_http.py` defaults to HTTP. Add `--ssl-cert` + `--ssl-key` for HTTPS — this is independent of `--transport`. To serve both HTTP and HTTPS simultaneously, run two processes on different ports.

**Self-signed certificate (internal network testing):**

```bash
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key \
  -out certs/server.crt -days 3650 -nodes \
  -subj "/CN=<your-server-ip>" -addext "subjectAltName=IP:<your-server-ip>"
```

**systemd service (auto-start on boot):**

```bash
cp contrib/fortigate-mcp.service ~/.config/systemd/user/
# Edit the ExecStart line to set --transport / --ssl-cert / --ssl-key as needed
systemctl --user daemon-reload
systemctl --user enable --now fortigate-mcp
```

### Docker Deployment

No Python environment required — one command to start:

```bash
# 1. Clone and prepare config
git clone https://github.com/wzs8768/fortigate-mcp-server.git
cd fortigate-mcp-server

# 2. Create config/config.json (see [Configuration](#configuration) above)

# 3. Start (HTTP on :8815)
docker compose up -d
```

**HTTPS mode:**

```bash
# 1. Generate self-signed cert
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key \
  -out certs/server.crt -days 3650 -nodes \
  -subj "/CN=<server-ip>" -addext "subjectAltName=IP:<server-ip>"

# 2. Edit docker-compose.yml — uncomment HTTPS port mapping, add startup args:
#    command: [..., "--ssl-cert", "/app/certs/server.crt", "--ssl-key", "/app/certs/server.key", "--port", "8814"]

docker compose up -d
```

**Container features:**

| Feature | Description |
|---------|-------------|
| Multi-stage build | builder + runtime, minimal image |
| Secure runtime | Non-root user `fgtmcp` |
| Health check | `GET /health` every 30s |
| Resource limits | CPU 1 core / Memory 512M |
| Log persistence | `./logs` directory mount |
| Config mounts | `config/`, `certs/` read-only mounts |

### MCP Client Integration

#### Scenario 1: Client & Server on Same Machine (STDIO)

Client launches the process directly — no pre-running server needed:

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

Works with Claude Desktop, OpenCode, Codex CLI, and other STDIO transport clients.

#### Scenario 2: Client & Server on Different Machines (HTTP/HTTPS) ⭐

> **Need both HTTP and HTTPS?** Start two processes on different ports (e.g. HTTPS→8814, HTTP→8815) and use the corresponding URL below.

```json
// HTTPS · Streamable HTTP
{ "url": "https://<server-ip>:8814/fortigate-mcp",           "transport": "streamable-http" }

// HTTPS · SSE
{ "url": "https://<server-ip>:8814/fortigate-mcp-sse",       "transport": "sse" }

// HTTP · Streamable HTTP
{ "url": "http://<server-ip>:8815/fortigate-mcp",            "transport": "streamable-http" }

// HTTP · SSE
{ "url": "http://<server-ip>:8815/fortigate-mcp-sse",        "transport": "sse" }
```

> ⚠️ Claude Desktop **only supports STDIO transport**. Remote connections require `mcp-remote` relay (see Windows config below) over HTTPS.

Client config file locations:

| Client | Config File |
|--------|-------------|
| Claude Desktop (macOS/Linux) | `~/.claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%LOCALAPPDATA%\Packages\Claude_<random>\LocalCache\Roaming\Claude\claude_desktop_config.json` |
| OpenCode | `~/.opencode/config.json` or `--mcp-config` flag |
| Cursor | `~/.cursor/mcp_servers.json` |
| Codex CLI | `~/.codex/mcp_servers.json` |
| Hermes | `~/.hermes/config.yaml` → `mcp_servers` section |
| OpenClaw | `~/.openclaw/openclaw.json` → `mcp.servers` section |

#### Windows Claude Desktop (Self-signed cert / TLS skip verify)

Windows Claude Desktop doesn't support `ssl_verify: false` in config directly. Use `mcp-remote` relay with an environment variable to bypass certificate verification:

**Prerequisite: Install Node.js**

```powershell
# PowerShell (Administrator)
winget install OpenJS.NodeJS.LTS
```

**Claude Desktop config (`claude_desktop_config.json`):**

> Config file path example: `C:\Users\<username>\AppData\Local\Packages\Claude_<random>\LocalCache\Roaming\Claude\` (Windows Store version). Navigate to `%LOCALAPPDATA%\Packages\` and locate the `Claude_*` directory.

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://<server-ip>:8814/fortigate-mcp",
        "--transport",
        "streamable-http",
        "--header",
        "Authorization:***"
      ],
      "env": {
        "NODE_TLS_REJECT_UNAUTHORIZED": "0",
        "FORTIGATE_AUTH": "Bearer <your-shared-token>"
      }
    }
  },
  "coworkUserFilesPath": "C:\\Users\\<username>\\Claude",
  "preferences": { "...": "..." }
}
```

> In an existing `claude_desktop_config.json`, merge the `mcpServers` block — keep the rest unchanged.

> `NODE_TLS_REJECT_UNAUTHORIZED=0` skips TLS certificate verification for self-signed cert environments. For production, import the certificate into the system trusted root store.

#### Remote Access Security

The `auth` configuration is fully shown in [Configuration](#configuration) above (`config/config.json` → `auth.api_tokens`). Here are the operational steps:

**1. Generate a token:**
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

**2. Add to `config/config.json` under `auth.api_tokens`** (see the full config example above).

**3. Multi-client token naming example:**
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

> Also backward-compatible with the old format (bare strings): `"api_tokens": ["token1", "token2"]` — auto-labeled as `(unnamed)`.

**4. Restart to apply:** `systemctl --user restart fortigate-mcp`

**5. Claude Desktop client config — see the [Windows Claude Desktop](#windows-claude-desktop-self-signed-cert--tls-skip-verify) section above for the complete `claude_desktop_config.json` example.**

> In `--header "Authorization:***"`, no space between `:` and `Bearer` — avoids a Windows Claude Desktop parameter-space bug.

Hermes Agent config (YAML, `~/.hermes/config.yaml`):

```yaml
mcp_servers:
  fortigate:
    url: https://<server-ip>:8814/fortigate-mcp
    enabled: true
    ssl_verify: false
    connect_timeout: 30
    headers:
      Authorization: "Bearer <your-shared-token>"
```

> Hermes HTTP config (no cert needed): change `url` to `http://<server-ip>:8815/fortigate-mcp` and remove the `ssl_verify` line.

Codex CLI config (TOML, `~/.codex/config.toml` or project `.codex.toml`):

```toml
[mcp_servers.fortigate]
enabled = true
url = "http://<server-ip>:8815/fortigate-mcp"

[mcp_servers.fortigate.http_headers]
Authorization = "Bearer <your-shared-token>"
Accept = "application/json, text/event-stream"
```

> ⚠️ Codex **must use HTTP (port 8815)** — Codex cannot skip self-signed cert verification; HTTPS connections will fail on cert errors.

Cursor / OpenCode / OpenClaw JSON config (**HTTPS**):

Cursor / OpenCode:
```json
{
  "mcpServers": {
    "fortigate": {
      "url": "https://<server-ip>:8814/fortigate-mcp",
      "transport": "streamable-http",
      "headers": {
        "Authorization": "Bearer <your-shared-token>"
      }
    }
  }
}
```

OpenClaw (use `rejectUnauthorized` field; `mcp.servers` block at end of `openclaw.json`):
```json
{
  "mcp": {
    "servers": {
      "FortiGate": {
        "url": "https://<server-ip>:8814/fortigate-mcp",
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

## MCP Tools (279)

> Representative tools listed below. All 279 tools cover 1023+ FortiOS API endpoints, including generic CMDB CRUD, log queries, monitoring, etc.

### Device Management (7)
`list_devices` `get_device_status` `test_device_connection` `add_device` `remove_device` `discover_vdoms` `list_vdoms`

### Firewall Policies (53)
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

### Addresses & Groups (17)
`list_address_objects` `create/update/delete_address_object`
`list_addrgrps` `create/update/delete_addrgrp` `get_addrgrp_detail`
`list_wildcard_fqdn_custom` `create/update/delete_wildcard_fqdn_custom`
`list_wildcard_fqdn_group` `create/update/delete_wildcard_fqdn_group`
`list_proxy_addresses` `create/update/delete_proxy_address` `list_proxy_addrgrps` `create/update/delete_proxy_addrgrp`

### Services & Schedules (22)
`list_service_objects` `create/update/delete_service_object`
`list_service_groups` `create/update/delete_service_group`
`list_schedule_onetime` `create/update/delete_schedule_onetime`
`list_schedule_recurring` `create/update/delete_schedule_recurring`
`list_schedule_group` `create/update/delete_schedule_group`

### NAT & Traffic (29)
`list_virtual_ips` `create/update/delete_virtual_ip` `get_virtual_ip_detail`
`list_vipgrps` `create/update/delete_vipgrp`
`list_ippools` `create/update/delete_ippool`
`list_ip_translations` `create/update/delete_ip_translation`
`list_dns_translations` `create/update/delete_dns_translation`
`list_central_snat_maps` `create/update/delete_central_snat_map` `get_central_snat_map_detail`
`create/delete/update_traffic_shaper` `list_traffic_shapers`
`create/delete/update_per_ip_shaper` `list_per_ip_shapers`

### Security Profiles (38)
`list_ips_sensors` `create/update/delete_ips_sensor` `get_ips_sensor_detail`
`list_antivirus_profiles` `get_antivirus_settings`
`list_webfilter_profiles` `list_webfilter_urlfilters`
`list_dnsfilter_profiles` `list_dnsfilter_domain_filters` `create/delete_dnsfilter_profile`
`list_emailfilter_profiles`
`list_dlp_sensors` `list_dlp_profiles` `get_dlp_settings`
`list_ssl_ssh_profiles` `create/update/delete_ssl_ssh_profile`
`list_waf_profiles` `list_voip_profiles` `list_casb_profiles` `list_sctp_filter_profiles` `list_ssh_filter_profiles`
`list_profile_groups` `create/delete_profile_group` `list_profile_protocol_options` `create/delete_profile_protocol_options`
`list_application_lists` `list_application_groups`
`list_switch_8021x_policies` `list_switch_acl_groups` `list_decrypted_traffic_mirrors` `create/delete_decrypted_traffic_mirror`

### VPN (12)
`list_vpn_ipsec_phase1_interfaces` `list_vpn_ipsec_phase2_interfaces`
`get_vpn_ssl_settings` `list_vpn_ssl_web_portals`
`monitor_vpn_ipsec` `monitor_vpn_ipsec_connection_count` `monitor_vpn_ssl` `monitor_vpn_ssl_stats`

### Users & Authentication (19)
`list_user_locals` `list_user_groups` `list_user_ldaps` `list_user_radiuses`
`list_auth_rules` `create/delete_auth_rule` `list_auth_schemes`
`get_auth_setting` `get_user_setting`
`monitor_user_firewall` `monitor_user_firewall_count` `monitor_user_fsso` `monitor_user_banned`

### System & Network (12)
`list_system_dhcp_servers` `list_system_snmp_communities`
`get_certificate_ca` `get_certificate_local`
`get_log_setting` `update_log_setting` `get_log_disk_setting` `update_log_disk_setting`
`get_log_fortianalyzer_setting` `update_log_fortianalyzer_setting`
`get_log_syslogd_setting` `update_log_syslogd_setting`
`get_alertemail_setting` `get_firewall_global` `update_firewall_global`
`get_endpoint_control_settings`

### Routing & Interfaces (12)
`list_static_routes` `create/update/delete_static_route` `get_static_route_detail`
`get_routing_table` `list_identity_based_routes` `create/delete_identity_based_route`
`monitor_router_ipv4` `monitor_router_ipv6` `monitor_router_bgp_neighbors` `monitor_router_bgp_paths`

### Monitoring (20)
`monitor_system_status` `monitor_system_resource_usage` `monitor_system_performance_status` `monitor_system_firmware`
`monitor_system_interface` `monitor_system_available_interfaces` `monitor_system_current_admins` `monitor_system_vm_information`
`monitor_license_status` `monitor_registration_forticloud_status` `monitor_fortiguard_service_stats`
`monitor_fortiview_realtime_stats` `monitor_geoip_query` `monitor_network_reverse_ip_lookup`
`monitor_network_dns_latency` `monitor_network_arp` `monitor_network_lldp_neighbors`
`monitor_utm_applications` `monitor_utm_app_lookup` `monitor_utm_application_categories`
`monitor_webfilter_fortiguard_categories`

### Generic CMDB Tools (4)
`cmdb_list` `cmdb_get` `cmdb_create` `cmdb_update` `cmdb_delete` — Covers ALL 1023+ FortiOS CMDB endpoints

> Path format: Most modules use `/` separator (e.g. `firewall/addrgrp`, `router/bgp`, `system/global`). **A few composite modules require `.`** (e.g. `system.snmp/sysinfo`, `firewall.service/custom`, `vpn.ipsec/phase1-interface`, `log.disk/filter`). The MCP server auto-normalizes paths: slash-style input (e.g. `system/snmp/sysinfo`) is converted to the correct dot-style path automatically — both notations work. The full list of 43 dot-path composite modules lives in `DOT_PATH_MODULES` in `fortigate.py`.

### Firewall Monitoring (6)
`monitor_firewall_policy` `monitor_firewall_policy_lookup` `monitor_firewall_sessions` `monitor_firewall_acl` `monitor_firewall_acl6`
`monitor_ips_session_performance` `monitor_ips_rate_based`

---

## Troubleshooting

**SSL connection failed**
- Lab self-signed cert: set `verify_ssl: false`
- Production: install a valid certificate on the FortiGate

**VDOM not found**
- Use `discover_vdoms` to see available VDOMs
- VDOM names are case-sensitive

**Policy creation returns 500**
- FortiOS 8.0.0 requires `"schedule": "always"` field
- Address/service objects containing `/` need URL encoding (built-in)

---

## CI/CD

Runs automatically on every push to `main` (`.github/workflows/ci.yml`):

| Job | Description |
|-----|-------------|
| Lint | `ruff check src/` code style check |

---

## License

MIT License. See [LICENSE](LICENSE)

## Acknowledgments

- [alpadalar/fortigate-mcp-server](https://github.com/alpadalar/fortigate-mcp-server) — Original project
- [Model Context Protocol](https://modelcontextprotocol.io/) — Protocol specification
- [FastMCP](https://gofastmcp.com/) — Python MCP server framework
- [FortiGate Product Docs](https://docs.fortinet.com/) — Official FortiGate documentation
- [httpx](https://www.python-httpx.org/) — Async HTTP client
