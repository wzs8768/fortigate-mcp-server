"""Regression tests for key fixes — covers schedule, utm, cmdb, errors, tools, health, env."""

import copy
import os
import pathlib
from unittest.mock import AsyncMock, MagicMock

import pytest

ROOT = pathlib.Path(__file__).parent.parent


# ════════════════════════════════════════════════════════════════════════════
# 1. Schedule day conversion
# ════════════════════════════════════════════════════════════════════════════
class TestScheduleDayConversion:

    @pytest.mark.asyncio
    async def test_day_list_converted(self):
        from src.fortigate_mcp.config.models import FortiGateDeviceConfig
        from src.fortigate_mcp.core.fortigate import FortiGateAPI

        captured = {}
        config = FortiGateDeviceConfig(host="x", api_token="x")
        api = FortiGateAPI(device_id="t", config=config)
        api._client = MagicMock()
        api._client.request = AsyncMock()
        api._client.request.return_value.json.return_value = {"status": "ok"}
        api._client.request.return_value.status_code = 200

        orig = api._make_request
        async def spy(m, e, data=None, vdom=None):
            if data: captured.update(data)
            return await orig(m, e, data=data, vdom=vdom)
        api._make_request = spy

        await api.create_schedule_recurring({
            "name": "t", "start": "08:00", "end": "18:00",
            "day": ["monday", "friday"],
        })
        assert captured.get("day") == "monday friday"

    @pytest.mark.asyncio
    async def test_day_string_passthrough(self):
        from src.fortigate_mcp.config.models import FortiGateDeviceConfig
        from src.fortigate_mcp.core.fortigate import FortiGateAPI

        captured = {}
        config = FortiGateDeviceConfig(host="x", api_token="x")
        api = FortiGateAPI(device_id="t", config=config)
        api._client = MagicMock()
        api._client.request = AsyncMock()
        api._client.request.return_value.json.return_value = {"status": "ok"}
        api._client.request.return_value.status_code = 200

        orig = api._make_request
        async def spy(m, e, data=None, vdom=None):
            if data: captured.update(data)
            return await orig(m, e, data=data, vdom=vdom)
        api._make_request = spy

        await api.create_schedule_recurring({
            "name": "t", "start": "08:00", "end": "18:00",
            "day": "monday friday",
        })
        assert captured["day"] == "monday friday"

    @pytest.mark.asyncio
    async def test_no_mutation(self):
        from src.fortigate_mcp.config.models import FortiGateDeviceConfig
        from src.fortigate_mcp.core.fortigate import FortiGateAPI

        data = {"name": "t", "start": "08:00", "end": "18:00", "day": ["monday"]}
        saved = copy.deepcopy(data)

        config = FortiGateDeviceConfig(host="x", api_token="x")
        api = FortiGateAPI(device_id="t", config=config)
        api._client = MagicMock()
        api._client.request = AsyncMock()
        api._client.request.return_value.json.return_value = {"status": "ok"}
        api._client.request.return_value.status_code = 200
        await api.create_schedule_recurring(data)

        assert data == saved
        assert data["day"] == ["monday"]


# ════════════════════════════════════════════════════════════════════════════
# 2. UTM app lookup param
# ════════════════════════════════════════════════════════════════════════════
class TestUTMAppLookupParam:

    def test_uses_hosts_param(self):
        fpath = ROOT / "src" / "fortigate_mcp" / "core" / "fortigate.py"
        content = fpath.read_text()
        idx = content.find("def monitor_utm_app_lookup")
        assert idx > 0
        # Look at 300 chars after the method def
        section = content[idx:idx + 300]
        assert content.find("def monitor_utm_application_categories") > 0  # verify other method exists
        assert "hosts" in section


# ════════════════════════════════════════════════════════════════════════════
# 3. CMDB paths
# ════════════════════════════════════════════════════════════════════════════
class TestCmdBPathFormat:

    @pytest.mark.asyncio
    async def test_list_dot_path(self):
        from src.fortigate_mcp.config.models import FortiGateDeviceConfig
        from src.fortigate_mcp.core.fortigate import FortiGateAPI

        captured = None
        config = FortiGateDeviceConfig(host="x", api_token="x")
        api = FortiGateAPI(device_id="t", config=config)
        api._client = MagicMock()
        api._client.request = AsyncMock()
        api._client.request.return_value.json.return_value = {"results": []}
        api._client.request.return_value.status_code = 200

        orig = api._make_request
        async def spy(m, e, data=None, vdom=None):
            nonlocal captured; captured = e
            return await orig(m, e, data=data, vdom=vdom)
        api._make_request = spy

        await api.cmdb_request("GET", "firewall.addrgrp")
        assert "cmdb/firewall.addrgrp" in captured

    @pytest.mark.asyncio
    async def test_delete_slash_path(self):
        from src.fortigate_mcp.config.models import FortiGateDeviceConfig
        from src.fortigate_mcp.core.fortigate import FortiGateAPI

        captured = None
        config = FortiGateDeviceConfig(host="x", api_token="x")
        api = FortiGateAPI(device_id="t", config=config)
        api._client = MagicMock()
        api._client.request = AsyncMock()
        api._client.request.return_value.json.return_value = {"status": "ok"}
        api._client.request.return_value.status_code = 200

        orig = api._make_request
        async def spy(m, e, data=None, vdom=None):
            nonlocal captured; captured = e
            return await orig(m, e, data=data, vdom=vdom)
        api._make_request = spy

        await api.cmdb_request("DELETE", "firewall/addrgrp", name="grp1")
        assert "firewall/addrgrp/grp1" in captured.replace("cmdb/", "")

    @pytest.mark.asyncio
    async def test_delete_requires_name(self):
        from src.fortigate_mcp.tools.cmdb import CmdbTools

        # Need a manager where get_device returns a valid mock with cmdb_request
        api_client = AsyncMock()
        api_client.cmdb_request = AsyncMock()
        manager = MagicMock()
        manager.devices = {"d": MagicMock()}
        manager.get_device.return_value = api_client

        tools = CmdbTools(manager)
        # name=None should be rejected by validation before ever calling the API
        result = await tools.cmdb_delete("d", "firewall/addrgrp", name=None)
        assert "required" in result[0].text.lower()


# ════════════════════════════════════════════════════════════════════════════
# 4. Error classification
# ════════════════════════════════════════════════════════════════════════════
class TestErrorClassification:

    @pytest.mark.asyncio
    async def test_acl_404_hardware(self):
        from src.fortigate_mcp.tools.resources import ResourceTools
        from src.fortigate_mcp.core.fortigate import FortiGateAPIError

        # Properly mock the API client chain
        api = AsyncMock()
        api.monitor_firewall_acl = AsyncMock(
            side_effect=FortiGateAPIError("Not found", status_code=404, device_id="d")
        )
        mgr = MagicMock()
        mgr.devices = {"d": MagicMock()}
        mgr.get_device.return_value = api

        tools = ResourceTools(mgr)
        r = await tools.monitor_firewall_acl("d")
        t = r[0].text
        assert "unsupported" in t.lower() or "hardware" in t.lower()

    @pytest.mark.asyncio
    async def test_faz_424_disabled(self):
        from src.fortigate_mcp.tools.resources import ResourceTools
        from src.fortigate_mcp.core.fortigate import FortiGateAPIError

        api = AsyncMock()
        api.monitor_log_fortianalyzer = AsyncMock(
            side_effect=FortiGateAPIError("Failed", status_code=424, device_id="d")
        )
        mgr = MagicMock()
        mgr.devices = {"d": MagicMock()}
        mgr.get_device.return_value = api

        tools = ResourceTools(mgr)
        r = await tools.monitor_log_fortianalyzer("d")
        t = r[0].text
        assert "424" in t or "unavailable" in t.lower() or "disabled" in t.lower()

    @pytest.mark.asyncio
    async def test_500_internal(self):
        from src.fortigate_mcp.tools.firewall import FirewallTools
        from src.fortigate_mcp.core.fortigate import FortiGateAPIError

        api = AsyncMock()
        api.list_firewall_policies = AsyncMock(
            side_effect=FortiGateAPIError("Internal error", status_code=500, device_id="d")
        )
        mgr = MagicMock()
        mgr.devices = {"d": MagicMock()}
        mgr.get_device.return_value = api

        tools = FirewallTools(mgr)
        r = await tools.list_policies("d")
        t = r[0].text
        assert "500" in t or "Internal" in t or "internal" in t.lower() or "error" in t.lower()

    @pytest.mark.asyncio
    async def test_400_app_lookup(self):
        from src.fortigate_mcp.tools.resources import ResourceTools
        from src.fortigate_mcp.core.fortigate import FortiGateAPIError

        api = AsyncMock()
        api.monitor_utm_app_lookup = AsyncMock(
            side_effect=FortiGateAPIError("Bad", status_code=400, device_id="d")
        )
        mgr = MagicMock()
        mgr.devices = {"d": MagicMock()}
        mgr.get_device.return_value = api

        tools = ResourceTools(mgr)
        r = await tools.monitor_utm_app_lookup("d", "youtube.com")
        t = r[0].text
        assert "400" in t or "unavailable" in t.lower() or "endpoint" in t.lower()


# ════════════════════════════════════════════════════════════════════════════
# 5. Tool count
# ════════════════════════════════════════════════════════════════════════════
class TestToolCount:

    def test_279_tools(self):
        c = (ROOT / "src" / "fortigate_mcp" / "tool_registry.py").read_text()
        assert c.count("@mcp.tool(") >= 279

    def test_both_servers_use_registry(self):
        for n in ["server.py", "server_http.py"]:
            assert "register_all_tools" in (ROOT / "src" / "fortigate_mcp" / n).read_text()


# ════════════════════════════════════════════════════════════════════════════
# 6. _make_request params/data
# ════════════════════════════════════════════════════════════════════════════
class TestMakeRequest:

    def test_copies_params(self):
        c = (ROOT / "src" / "fortigate_mcp" / "core" / "fortigate.py").read_text()
        idx = c.find("async def _make_request")
        assert "dict(params)" in c[idx:idx + 2000]

    def test_is_not_none(self):
        c = (ROOT / "src" / "fortigate_mcp" / "core" / "fortigate.py").read_text()
        idx = c.find("async def _make_request")
        section = c[idx:idx + 2000]
        assert "data is not None" in section
        assert "data if data else None" not in section


# ════════════════════════════════════════════════════════════════════════════
# 7. Health endpoint
# ════════════════════════════════════════════════════════════════════════════
class TestHealthEndpoint:

    def test_exists(self):
        c = (ROOT / "src" / "fortigate_mcp" / "server_http.py").read_text()
        assert '"/health"' in c
        assert "async def _health_endpoint" in c
        assert '"status": "ok"' in c
        assert "server_version" in c
        assert "registered_devices" in c


# ════════════════════════════════════════════════════════════════════════════
# 8. Docker env fallback
# ════════════════════════════════════════════════════════════════════════════
class TestDockerEnv:

    def test_no_unconditional_raise(self):
        c = (ROOT / "src" / "fortigate_mcp" / "config" / "loader.py").read_text()
        # Between except FileNotFoundError and except json.JSONDecodeError,
        # there should be exactly ONE raise
        start = c.find("except FileNotFoundError:")
        end = c.find("except json.JSONDecodeError", start)
        block = c[start:end]
        assert block.count("raise FileNotFoundError") == 1

    def test_env_override(self):
        from src.fortigate_mcp.config.loader import load_config
        config_path = str(ROOT / "config" / "config.json")
        old_h = os.environ.get("FORTIGATE_HOST")
        old_t = os.environ.get("FORTIGATE_API_TOKEN")
        try:
            os.environ["FORTIGATE_HOST"] = "10.99.99.99"
            os.environ["FORTIGATE_API_TOKEN"] = "ovr-tok"
            config = load_config(config_path)
            dev = next(iter(config.fortigate.devices.values()))
            assert dev.host == "10.99.99.99"
            assert dev.api_token == "ovr-tok"
        finally:
            for k, v in [("FORTIGATE_HOST", old_h), ("FORTIGATE_API_TOKEN", old_t)]:
                if v is not None: os.environ[k] = v
                else: os.environ.pop(k, None)


# ════════════════════════════════════════════════════════════════════════════
# 9. CLI entry point
# ════════════════════════════════════════════════════════════════════════════
class TestCLI:

    def test_main_importable(self):
        from src.main import main
        assert callable(main)
