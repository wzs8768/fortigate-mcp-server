"""API catalog tools — version-aware FortiOS endpoint discovery.

These tools never touch a FortiGate device; they answer from the catalog
generated out of Fortinet's Swagger bundles (see
``scripts/build_fortios_api_catalog.py``). They exist so an agent can:

* find which endpoint covers a task, and on which FortiOS releases it exists;
* read an endpoint's field names, enums and query parameters before writing a
  payload — the usual cause of FortiOS' opaque ``-651`` / ``-56`` errors;
* check a device's *detected* version against an endpoint instead of guessing.
"""

from __future__ import annotations

from typing import Any

from mcp.types import TextContent as Content

from ..core import api_catalog
from .base import FortiGateTool

# list_api_endpoints renders text, not JSON: 1600+ endpoints of raw JSON is
# unreadable in a chat transcript.
DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


class CatalogTools(FortiGateTool):
    """Browse and validate the FortiOS REST API surface."""

    def _resolve_version(self, device_id: str | None, version: str | None) -> tuple[str | None, str | None]:
        """Return (version, note). An explicit ``version`` wins over the device's.

        Never performs I/O — a device whose version has not been detected yet
        reports ``None`` plus an explanatory note.
        """
        if version:
            return version, None
        if not device_id:
            return None, None
        if device_id not in self.fortigate_manager.devices:
            raise ValueError(
                f"Device '{device_id}' not found. Available devices: "
                f"{list(self.fortigate_manager.devices.keys())}"
            )
        api = self.fortigate_manager.get_device(device_id)
        if api.version:
            return api.version, f"version {api.version} reported by device '{device_id}'"
        return None, (
            f"device '{device_id}' version not yet detected — call get_device_status "
            f"or pass version explicitly"
        )

    async def _async_detect(self, api) -> str | None:
        try:
            return await api.detect_version()
        except Exception as exc:
            api.logger.warning(f"version detection failed: {exc}")
            return None

    async def list_api_endpoints(
        self,
        kind: str | None = None,
        module: str | None = None,
        version: str | None = None,
        method: str | None = None,
        search: str | None = None,
        device_id: str | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
    ) -> list[Content]:
        """List FortiOS REST endpoints, optionally filtered.

        Args:
            kind: cmdb / monitor / log / service
            module: first path segment, e.g. "firewall" (matches composites too)
            version: FortiOS release, e.g. "8.0.1" — only endpoints present there
            method: only endpoints accepting this HTTP method
            search: case-insensitive substring match on path or summary
            device_id: resolve ``version`` from this device when omitted
            limit: maximum rows to print (default 100, max 500)
        """
        try:
            resolved, note = self._resolve_version(device_id, version)
            limit = max(1, min(int(limit or DEFAULT_LIST_LIMIT), MAX_LIST_LIMIT))

            matches = api_catalog.endpoints(
                kind=kind, module=module, version=resolved, method=method, search=search,
            )
            if not matches:
                return [Content(type="text", text=self._empty_result_message(
                    kind, module, resolved, method, search, note))]

            stats = api_catalog.catalog_stats()
            plural = "" if len(matches) == 1 else "es"
            lines = [f"📚 **FortiOS API endpoints** — {len(matches)} match{plural}"]
            filters = []
            if kind:
                filters.append(f"kind={kind}")
            if module:
                filters.append(f"module={module}")
            if method:
                filters.append(f"method={method.upper()}")
            if search:
                filters.append(f"search={search!r}")
            filters.append(f"version={resolved}" if resolved else "all versions")
            lines.append(f"  filters: {', '.join(filters)}")
            if note:
                lines.append(f"  ℹ️  {note}")
            lines.append("")

            if not (search or module) and kind is None:
                # Overview mode: a per-module census is more useful than 1600 rows.
                by_module: dict[str, int] = {}
                for entry in matches:
                    key = f"{entry['kind']}:{entry['module']}"
                    by_module[key] = by_module.get(key, 0) + 1
                lines.append(f"  {len(by_module)} modules — pass `module` or `search` to narrow down:")
                for key in sorted(by_module):
                    lines.append(f"    • {key} ({by_module[key]})")
                lines.append("")
                lines.append(
                    f"  Catalog: {stats['endpoints']} endpoints across "
                    f"{', '.join(stats['supported_versions'])} "
                    f"(generated {stats['generated_at']})"
                )
                return [Content(type="text", text="\n".join(lines))]

            shown = matches[:limit]
            for entry in shown:
                methods = ",".join(m.upper() for m in entry["methods"])
                versions = ",".join(entry["versions"])
                summary = entry["summary"] or ""
                lines.append(
                    f"  {entry['endpoint']}\n"
                    f"      {methods}  ·  {versions}"
                    + (f"\n      {summary}" if summary else "")
                )
            if len(matches) > len(shown):
                lines.append("")
                lines.append(
                    f"  … {len(matches) - len(shown)} more (raise `limit` up to {MAX_LIST_LIMIT}, "
                    f"or narrow with `module` / `search`)"
                )
            return [Content(type="text", text="\n".join(lines))]
        except Exception as e:
            return self._handle_error("list_api_endpoints", device_id or "catalog", e)

    @staticmethod
    def _empty_result_message(kind, module, version, method, search, note) -> str:
        lines = ["📚 **FortiOS API endpoints** — no matches", ""]
        criteria = []
        if kind:
            criteria.append(f"kind={kind}")
        if module:
            criteria.append(f"module={module}")
        if method:
            criteria.append(f"method={method}")
        if search:
            criteria.append(f"search={search!r}")
        if version:
            criteria.append(f"version={version}")
        if criteria:
            lines.append(f"  filters applied: {', '.join(criteria)}")
        if note:
            lines.append(f"  ℹ️  {note}")
        lines.append("")
        lines.append("  Try a broader search, e.g. module='firewall', or search='vpn'.")
        return "\n".join(lines)

    async def get_api_endpoint_schema(self, endpoint: str, method: str = "get") -> list[Content]:
        """Return the field definitions and query parameters for one operation.

        Use this before cmdb_create / cmdb_update / monitor_request to learn the
        exact field names FortiOS expects (prevents -651/-56 rejections).

        Args:
            endpoint: e.g. "firewall/policy", "router/vrf", "monitor/system/status"
            method: get (default), post, put or delete
        """
        try:
            data = api_catalog.endpoint_schema(endpoint, method)
            availability = api_catalog.check_endpoint(endpoint, method=method)
            data["versions"] = availability.get("known_versions", [])
            data["kind"] = availability.get("kind")
            data["summary"] = availability.get("summary")
            return [Content(type="text", text=_render_schema(data))]
        except Exception as e:
            return self._handle_error(f"get_api_endpoint_schema {endpoint}", "catalog", e)

    async def check_api_compatibility(
        self,
        endpoint: str,
        device_id: str | None = None,
        version: str | None = None,
        method: str | None = None,
    ) -> list[Content]:
        """Check whether an endpoint exists on a FortiOS release.

        Answers "why did this return 404?" without guesswork: the reply says
        which releases do document the endpoint.

        Args:
            endpoint: e.g. "router/vrf", "cmdb/firewall/policy", "/api/v2/monitor/system/status"
            device_id: use this device's FortiOS version
            version: explicit version, e.g. "8.0.0" (overrides device_id)
            method: optional HTTP method to check
        """
        target = device_id or "catalog"
        try:
            resolved, note = self._resolve_version(device_id, version)
            if device_id and resolved is None:
                # One real API call is worth it here — the answer depends on it.
                api = self.fortigate_manager.get_device(device_id)
                resolved = await self._async_detect(api)
                if resolved:
                    note = f"version {resolved} detected on device '{device_id}'"

            verdict = api_catalog.check_endpoint(endpoint, version=resolved, method=method)
            verdict["checked_against"] = resolved or "the whole catalog"
            if note:
                verdict["note"] = note
            supported = verdict.get("supported")
            icon = {True: "✅", False: "❌", None: "❔"}[supported]
            verdict["verdict"] = f"{icon} {verdict['reason']}"
            return [Content(type="text", text=_render_verdict(verdict))]
        except Exception as e:
            return self._handle_error(f"check_api_compatibility {endpoint}", target, e)


def _render_verdict(verdict: dict[str, Any]) -> str:
    lines = [
        f"{verdict['verdict']}",
        "",
        f"  endpoint : {verdict['endpoint']}",
        f"  checked  : {verdict.get('checked_against')}",
    ]
    if verdict.get("module"):
        lines.append(f"  module   : {verdict['kind']}/{verdict['module']}")
    if verdict.get("summary"):
        lines.append(f"  purpose  : {verdict['summary']}")
    if verdict.get("known_versions"):
        lines.append(f"  available in: {', '.join(verdict['known_versions'])}")
    if verdict.get("methods"):
        lines.append(
            "  methods  : " + ", ".join(
                f"{m.upper()}({'/'.join(v)})" for m, v in sorted(verdict["methods"].items())
            )
        )
    if verdict.get("similar_endpoints"):
        lines.append(f"  did you mean: {', '.join(verdict['similar_endpoints'])}")
    return "\n".join(lines)


def _render_schema(data: dict[str, Any]) -> str:
    if data.get("error"):
        lines = [f"❌ {data['error']}", "", f"  endpoint : {data.get('endpoint', '?')}"]
        if data.get("documented_methods"):
            lines.append(f"  methods  : {', '.join(m.upper() for m in data['documented_methods'])}")
        if data.get("similar_endpoints"):
            lines.append(f"  did you mean: {', '.join(data['similar_endpoints'])}")
        return "\n".join(lines)

    lines = [f"📄 **{data['endpoint']}**  [{data['method'].upper()}]"]
    if data.get("summary"):
        lines.append(f"  {data['summary']}")
    if data.get("kind"):
        lines.append(f"  kind     : {data['kind']}")
    if data.get("versions"):
        lines.append(f"  available in: {', '.join(data['versions'])}")
    if data.get("query_params"):
        lines.append(f"  query params: {', '.join(data['query_params'])}")
    lines.append("")

    fields = data.get("fields") or {}
    if not fields:
        lines.append("  (no fields documented for this operation)")
        return "\n".join(lines)

    source = {
        "body": "request body schema published by Fortinet",
        "response": "returned object representation",
    }.get(str(data.get("fields_source") or ""), str(data.get("fields_source") or "unknown"))
    lines.append(f"  {len(fields)} fields — source: {source}")
    if data.get("fields_source_note"):
        lines.append(f"  ⚠️  {data['fields_source_note']}")
    for name in sorted(fields):
        spec = fields[name]
        bits = [spec.get("type") or "?"]
        if spec.get("enum"):
            bits.append("one of " + "|".join(str(v) for v in spec["enum"]))
        for bound in ("minimum", "maximum", "minLength", "maxLength"):
            if spec.get(bound) is not None:
                bits.append(f"{bound}={spec[bound]}")
        desc = f" — {spec['desc']}" if spec.get("desc") else ""
        lines.append(f"    • {name} ({', '.join(bits)}){desc}")
    return "\n".join(lines)
