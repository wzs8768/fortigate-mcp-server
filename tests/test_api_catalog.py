"""Tests for the version-aware FortiOS API catalog.

Covers the 8.0.1 update:
- the shipped catalog lists 8.0.1 and its composite CMDB modules;
- every endpoint hardcoded in the server is available on 8.0.1;
- the one real API difference, the removed ``llm`` module, is recorded and
  stays reachable on 8.0.0 through the catalog union;
- path normalisation and version verdicts behave;
- the three catalog MCP tools answer correctly.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.fortigate_mcp.core import api_catalog
from src.fortigate_mcp.core.fortigate import FortiGateAPI

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "fortigate_mcp"

# Endpoints hardcoded in the server that 8.0.1 does not have. Empty: the four
# documents that were initially missing from the 8.0.1 bundle (Configuration
# ssh-filter / telemetry-controller / wanopt, Service topology) have been added,
# so nothing the server calls is missing from 8.0.1 any more. Keep this set —
# a new entry means a genuine 8.0.1 API removal, not a download gap.
ABSENT_FROM_8_0_1 = set()

# ``llm`` is genuinely gone in 8.0.1 (Fortinet publishes no llm document for it),
# unlike the four modules above. It stays in the catalog so 8.0.0 devices work.
LLM_MODULE_ENDPOINTS = ("llm/profile", "llm/server", "llm/proxy")

# Literal → namespace for every helper the API client uses to build a URL.
_CALL_PATTERNS = (
    (re.compile(r"_make_monitor_request\(\s*([\"'])(?P<p>[^\"']+)\1"), "monitor"),
    (re.compile(r"_make_log_request\(\s*([\"'])(?P<p>[^\"']+)\1"), "log"),
    (re.compile(r"_make_service_request\(\s*[\"'][A-Z]+[\"']\s*,\s*([\"'])(?P<p>[^\"']+)\1"), "service"),
    (re.compile(r"_make_request\(\s*[\"'][A-Z]+[\"']\s*,\s*[fr]?([\"'])(?P<p>[^\"']+)\1"), None),
)
_QUOTED_ENDPOINT = re.compile(r"^[rf]?([\"'])(?P<p>(?:cmdb|monitor|log|service)/[^\"']+)\1")


def _hardcoded_endpoints() -> dict[str, str]:
    """Every REST path the server hardcodes, as ``/api/v2/...`` → source file."""
    found: dict[str, str] = {}
    for path in sorted(SRC.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for pattern, kind in _CALL_PATTERNS:
            for match in pattern.finditer(text):
                raw = match.group("p")
                found[_as_api_path(raw, kind)] = path.name
        # Endpoints passed as a whole literal, e.g. cmdb_request("GET", "firewall/address")
        for match in _QUOTED_ENDPOINT.finditer(text):
            found.setdefault(_as_api_path(match.group("p"), None), path.name)
    return found


def _as_api_path(raw: str, kind: str | None) -> str:
    raw = re.sub(r"\{[^}]+\}", "{key}", raw.strip().strip("/").rstrip("/"))
    if kind is None:
        # ``_make_request`` takes the full path, e.g. "cmdb/firewall/policy".
        return f"/api/v2/{raw}"
    # The helper's own namespace always prefixes the literal — so
    # ``_make_monitor_request("log/stats")`` means /api/v2/monitor/log/stats.
    return f"/api/v2/{kind}/{raw}"


def _matches_catalog(candidate: str, known: set[str]) -> bool:
    """Templated paths (``/api/v2/log/{key}/virus/archive``) match by wildcard."""
    if candidate in known:
        return True
    if "{key}" not in candidate:
        return False
    regex = re.compile("^" + re.escape(candidate).replace(re.escape("{key}"), "[^/]+") + "$")
    return any(regex.match(k) for k in known)


class TestCatalogData:
    """The generated data files are present, current, and cover 8.0.1."""

    def test_data_files_exist(self):
        assert Path(api_catalog.CATALOG_PATH).is_file()
        assert Path(api_catalog.FIELDS_PATH).is_file()

    def test_supported_versions(self):
        versions = api_catalog.supported_versions()
        assert "8.0.1" in versions
        assert versions[-1] == "8.0.1", "8.0.1 must be the newest catalogued release"
        assert {"7.4.12", "7.6.7", "8.0.0"} <= set(versions)

    def test_stats_sane(self):
        stats = api_catalog.catalog_stats()
        assert stats["endpoints"] > 1500
        assert stats["endpoints_by_kind"]["cmdb"] > 1000
        assert stats["composite_modules"] >= 40

    def test_801_has_its_own_composite_modules(self):
        modules = api_catalog.composite_modules("8.0.1")
        assert "system.snmp" in modules
        assert "firewall.service" in modules
        assert "vpn.ssl.web" in modules
        # telemetry-controller is a composite module; it only appears once the
        # 8.0.1 telemetry-controller document is present.
        assert "telemetry-controller.application" in modules

    def test_801_composite_modules_match_8_0_0(self):
        assert api_catalog.composite_modules("8.0.1") == api_catalog.composite_modules("8.0.0")

    def test_dot_path_modules_cover_every_version(self):
        """DOT_PATH_MODULES drives path normalisation and must never lag the
        catalog — a missing entry means slash-style calls break silently."""
        for version in api_catalog.supported_versions():
            missing = api_catalog.composite_modules(version) - FortiGateAPI.DOT_PATH_MODULES
            assert not missing, f"{version} composite modules missing: {sorted(missing)}"

    def test_801_new_endpoints_present(self):
        """Endpoints 8.0.1 introduced must be in the catalog."""
        for path in (
            "/api/v2/cmdb/router/vrf",
            "/api/v2/cmdb/router/largecommunity-list",
            "/api/v2/cmdb/system/openid-connect",
            "/api/v2/cmdb/icap/local-server",
            "/api/v2/cmdb/gui-notifications/event-alerts",
            "/api/v2/monitor/system/cellular-modem/status",
        ):
            assert path in api_catalog.endpoints_map(), path
            assert "8.0.1" in api_catalog.endpoint_versions(path), path


class TestHardcodedEndpointCompatibility:
    """Every endpoint the server calls must exist in a documented release."""

    def test_extractor_finds_a_realistic_number(self):
        found = _hardcoded_endpoints()
        assert len(found) > 200

    def test_all_hardcoded_endpoints_are_documented(self):
        known = api_catalog.endpoints_map()
        undocumented = {
            path: src for path, src in _hardcoded_endpoints().items()
            if not _matches_catalog(path, known)
        }
        assert not undocumented, f"endpoints absent from every Swagger bundle: {undocumented}"

    def test_every_hardcoded_endpoint_is_available_on_8_0_1(self):
        """The 8.0.1 bundle is complete, so every endpoint the server calls on
        behalf of a user must resolve on 8.0.1. A failure here means either a
        new API removal (record it in ABSENT_FROM_8_0_1) or a missing document.
        """
        not_in_801 = {
            path for path in _hardcoded_endpoints()
            if path in api_catalog.endpoints_map()  # templated paths: wildcard test above
            and "8.0.1" not in api_catalog.endpoint_versions(path)
        }
        assert not_in_801 == ABSENT_FROM_8_0_1, (
            f"unexpected 8.0.1 coverage gap: {sorted(not_in_801 - ABSENT_FROM_8_0_1)}"
        )

    @pytest.mark.parametrize(("path", "oldest"), [
        ("ssh-filter/profile", "7.4.12"),
        ("telemetry-controller/profile", "7.6.7"),
        ("wanopt/profile", "7.6.7"),
        ("service/topology/report", "8.0.0"),
    ])
    def test_restored_modules_are_available_on_8_0_1(self, path, oldest):
        """Documents that were initially missing from the 8.0.1 bundle."""
        versions = api_catalog.endpoint_versions(path)
        assert oldest in versions, path
        assert "8.0.1" in versions, path

    def test_llm_removed_in_8_0_1_but_kept_for_8_0_0(self):
        """llm is a real 8.0.1 removal: absent there, still documented in 8.0.0.

        The union keeps it in the catalog so 8.0.0 devices keep working, while a
        version check against 8.0.1 answers honestly.
        """
        for path in LLM_MODULE_ENDPOINTS:
            assert api_catalog.endpoint_entry(path) is not None, path
            assert "8.0.1" not in api_catalog.endpoint_versions(path), path
            assert "8.0.0" in api_catalog.endpoint_versions(path), path
            assert api_catalog.check_endpoint(path, "8.0.1")["supported"] is False, path
            assert api_catalog.check_endpoint(path, "8.0.0")["supported"] is True, path

    def test_llm_reported_as_documented_in_8_0_0_only(self):
        verdict = api_catalog.check_endpoint("llm/profile", version="8.0.1")
        assert verdict["known_versions"] == ["8.0.0"]
        assert "not present in FortiOS 8.0.1" in verdict["reason"]


class TestPathNormalisation:
    """Callers write paths in several styles; all must resolve correctly."""

    @pytest.mark.parametrize(("given", "expected"), [
        ("firewall/policy", "/api/v2/cmdb/firewall/policy"),
        ("/api/v2/cmdb/firewall/policy", "/api/v2/cmdb/firewall/policy"),
        ("cmdb/firewall/policy", "/api/v2/cmdb/firewall/policy"),
        ("system/snmp/sysinfo", "/api/v2/cmdb/system.snmp/sysinfo"),
        ("system.snmp/community", "/api/v2/cmdb/system.snmp/community"),
        ("firewall.service/custom", "/api/v2/cmdb/firewall.service/custom"),
        ("vpn/ssl/web/portal", "/api/v2/cmdb/vpn.ssl.web/portal"),
        ("monitor/system/status", "/api/v2/monitor/system/status"),
        ("service/security-rating/report", "/api/v2/service/security-rating/report"),
        ("firewall/policy/{policyid}", "/api/v2/cmdb/firewall/policy/{key}"),
    ])
    def test_canonical_endpoint(self, given, expected):
        assert api_catalog.canonical_endpoint(given) == expected

    def test_empty_path_rejected(self):
        with pytest.raises(ValueError):
            api_catalog.canonical_endpoint("   ")

    def test_cmdb_normalisation_is_unchanged(self):
        """The pre-8.0.1 normaliser behaviour must be preserved."""
        assert FortiGateAPI.normalize_cmdb_path("system/snmp/sysinfo") == "system.snmp/sysinfo"
        assert FortiGateAPI.normalize_cmdb_path("firewall/addrgrp") == "firewall/addrgrp"
        assert FortiGateAPI.normalize_cmdb_path("vpn/ssl/web/portal") == "vpn.ssl.web/portal"


class TestVersionCompatibility:
    """Version verdicts, including the 8.0.1-only endpoints."""

    def test_new_in_801(self):
        assert api_catalog.endpoint_versions("router/vrf") == ["8.0.1"]
        assert api_catalog.check_endpoint("router/vrf", "8.0.1")["supported"] is True
        assert api_catalog.check_endpoint("router/vrf", "8.0.0")["supported"] is False

    def test_long_standing_endpoint(self):
        for version in api_catalog.supported_versions():
            assert api_catalog.check_endpoint("firewall/policy", version)["supported"] is True

    def test_unknown_endpoint_is_advisory_only(self):
        verdict = api_catalog.check_endpoint("definitely/not-real", "8.0.1")
        assert verdict["supported"] is None
        assert "not in the shipped catalog" in verdict["reason"]

    def test_unknown_endpoint_suggests_matches(self):
        verdict = api_catalog.check_endpoint("system/snmp/communitie", "8.0.1")
        assert "/api/v2/cmdb/system.snmp/community" in verdict["similar_endpoints"]

    def test_suggestion_for_same_namespace_wins(self):
        assert api_catalog.suggest_endpoints("firewall/security-policie")[0].startswith("/api/v2/cmdb/")

    def test_method_level_verdict(self):
        # The table path accepts GET/POST; updates go to the {key} variant.
        assert api_catalog.check_endpoint("firewall/policy", "8.0.1", "post")["supported"] is True
        assert api_catalog.check_endpoint("firewall/policy", "8.0.1", "put")["supported"] is False


class TestEndpointSchema:
    """Field lookups that keep agents away from opaque -651 / -56 errors."""

    def test_get_schema_from_response(self):
        schema = api_catalog.endpoint_schema("router/vrf", "get")
        assert schema["fields_source"] == "response"
        assert "name" in schema["fields"]
        assert schema["fields"]["name"]["type"] == "string"

    def test_post_schema_from_body(self):
        schema = api_catalog.endpoint_schema("router/vrf", "post")
        assert schema["fields_source"] == "body"
        assert set(schema["fields"]) == {"id", "name"}

    def test_query_params_included(self):
        schema = api_catalog.endpoint_schema("router/vrf", "get")
        assert "filter" in schema["query_params"]

    def test_field_metadata_carries_enums(self):
        schema = api_catalog.endpoint_schema("firewall/policy", "get")
        assert schema["fields"]["action"]["enum"] == ["accept", "deny", "ipsec"]

    def test_unknown_method_reports_documented_ones(self):
        schema = api_catalog.endpoint_schema("firewall/policy", "delete")
        assert "error" in schema
        assert "get" in schema["documented_methods"]


class TestCatalogTools:
    """The three MCP tools, against a mocked 8.0.1 device."""

    @pytest.fixture
    def tools(self):
        from src.fortigate_mcp.core.fortigate import FortiGateManager
        from src.fortigate_mcp.tools.catalog import CatalogTools

        api = MagicMock()
        api.version = "8.0.1"
        api._version_detected = True
        manager = MagicMock(spec=FortiGateManager)
        manager.devices = {"FGT-LAB": api}
        manager.get_device.return_value = api
        return CatalogTools(manager)

    @pytest.mark.asyncio
    async def test_list_all(self, tools):
        text = (await tools.list_api_endpoints())[0].text
        assert "matches" in text
        assert "cmdb:firewall" in text  # per-module census
        assert "7.4.12, 7.6.7, 8.0.0, 8.0.1" in text  # catalog provenance line

    @pytest.mark.asyncio
    async def test_list_8_0_1_only(self, tools):
        text = (await tools.list_api_endpoints(module="router", version="8.0.1"))[0].text
        assert "/api/v2/cmdb/router/vrf" in text
        assert "8.0.1" in text

    @pytest.mark.asyncio
    async def test_list_no_matches(self, tools):
        text = (await tools.list_api_endpoints(module="nothing-here"))[0].text
        assert "no matches" in text

    @pytest.mark.asyncio
    async def test_list_uses_device_version(self, tools):
        text = (await tools.list_api_endpoints(search="vrf", device_id="FGT-LAB"))[0].text
        assert "8.0.1" in text
        assert "/api/v2/cmdb/router/vrf" in text

    @pytest.mark.asyncio
    async def test_list_unknown_device(self, tools):
        text = (await tools.list_api_endpoints(device_id="NOPE"))[0].text
        assert "NOPE" in text

    @pytest.mark.asyncio
    async def test_schema(self, tools):
        text = (await tools.get_api_endpoint_schema("router/vrf", "post"))[0].text
        assert "id" in text and "name" in text
        assert "request body schema" in text

    @pytest.mark.asyncio
    async def test_schema_unknown_endpoint_suggests(self, tools):
        text = (await tools.get_api_endpoint_schema("system/snmp/communitie"))[0].text
        assert "did you mean" in text

    @pytest.mark.asyncio
    async def test_compat_with_device_version(self, tools):
        text = (await tools.check_api_compatibility("router/vrf", device_id="FGT-LAB"))[0].text
        assert "✅" in text
        assert "8.0.1" in text

    @pytest.mark.asyncio
    async def test_compat_new_endpoint_on_old_version(self, tools):
        text = (await tools.check_api_compatibility("router/vrf", version="8.0.0"))[0].text
        assert "❌" in text
        assert "8.0.1" in text

    @pytest.mark.asyncio
    async def test_compat_detects_missing_version(self, tools):
        tools.fortigate_manager.devices["FGT-LAB"].version = None
        tools.fortigate_manager.devices["FGT-LAB"].detect_version = AsyncMock(return_value="8.0.1")
        tools.fortigate_manager.get_device.return_value.detect_version = AsyncMock(return_value="8.0.1")
        text = (await tools.check_api_compatibility("router/vrf", device_id="FGT-LAB"))[0].text
        assert "8.0.1" in text


class TestVersionHintOnErrors:
    """A version mismatch should say so instead of leaking a bare 404."""

    def _api(self, version):
        api = FortiGateAPI.__new__(FortiGateAPI)
        api.device_id = "d"
        api.version = version
        return api

    def test_hint_added_for_endpoint_missing_from_version(self):
        api = self._api("8.0.0")
        msg = api._with_version_hint("API request failed: 404", "cmdb/router/vrf", "GET")
        assert "[version]" in msg
        assert "8.0.1" in msg

    def test_no_hint_when_endpoint_exists(self):
        api = self._api("8.0.1")
        msg = api._with_version_hint("API request failed: 404", "cmdb/router/vrf", "GET")
        assert msg == "API request failed: 404"

    def test_no_hint_without_detected_version(self):
        api = self._api(None)
        assert api._with_version_hint("boom", "cmdb/router/vrf", "GET") == "boom"

    def test_no_hint_for_unknown_endpoint(self):
        api = self._api("8.0.1")
        assert api._with_version_hint("boom", "who/knows", "GET") == "boom"


class TestVersionDeclarations:
    """The documented supported-version list must match reality."""

    def test_readme_lists_supported_versions(self):
        """Both READMEs must document every FortiOS release the catalog claims."""
        for name in ("README.md", "README_EN.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            assert "FortiOS" in text, name
            for version in api_catalog.supported_versions():
                assert version in text, f"{name} does not mention FortiOS {version}"

    def test_readme_tool_count_matches_registry(self):
        actual = (SRC / "tool_registry.py").read_text(encoding="utf-8").count("@mcp.tool(")
        for name in ("README.md", "README_EN.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            assert str(actual) in text, f"{name} does not mention {actual} tools"

    def test_health_endpoint_exposes_versions(self):
        text = (SRC / "server_http.py").read_text(encoding="utf-8")
        assert "supported_fortios_versions" in text

    def test_ui_import_ok(self):
        """Importing the package must not require the data files to be parsed."""
        import src.fortigate_mcp

        assert src.fortigate_mcp.__version__ == "2.1.0"
