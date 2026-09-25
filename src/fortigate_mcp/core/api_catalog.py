"""FortiOS REST API catalog — version-aware endpoint knowledge.

The server ships a catalog generated from Fortinet's published Swagger 2.0
bundles (see ``scripts/build_fortios_api_catalog.py``)::

    src/fortigate_mcp/data/fortios_api_catalog.json   endpoint -> versions/methods
    src/fortigate_mcp/data/fortios_api_fields.json    endpoint#method -> fields

Two jobs:

1. Tell the transport layer which CMDB modules are "composite" (dot-separated,
   e.g. ``system.snmp/sysinfo``) so paths normalise correctly on every release.
2. Answer "does this endpoint exist on FortiOS X.Y.Z?" so a version mismatch
   produces a clear message instead of FortiOS' opaque ``404``/``500 -651``.

The field index is loaded lazily — it is only needed when an caller asks for an
endpoint's schema.
"""

from __future__ import annotations

import difflib
import json
import os
import re
from functools import lru_cache
from typing import Any

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
CATALOG_PATH = os.path.join(DATA_DIR, "fortios_api_catalog.json")
FIELDS_PATH = os.path.join(DATA_DIR, "fortios_api_fields.json")


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version)) or (0,)


@lru_cache(maxsize=1)
def _catalog() -> dict[str, Any]:
    with open(CATALOG_PATH, encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def _fields() -> dict[str, Any]:
    with open(FIELDS_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def supported_versions() -> list[str]:
    """Every FortiOS release the shipped catalog was generated from."""
    return list(_catalog()["supported_versions"])


def latest_version() -> str:
    """Newest documented release (drives which schema is authoritative)."""
    return _catalog()["latest_version"]


def catalog_sources() -> dict[str, Any]:
    """Per-version provenance: document count and endpoint count."""
    return dict(_catalog()["sources"])


def composite_modules(version: str | None = None) -> frozenset[str]:
    """CMDB modules whose URL uses a dot between module and sub-module.

    With ``version=None`` returns the union across all documented releases,
    which is what path normalisation should use: a caller has no way to know
    a device's build before the first request.
    """
    data = _catalog()
    if version is None:
        return frozenset(data["union_composite_modules"])
    return frozenset(data["composite_modules"].get(version, []))


KINDS = ("cmdb", "monitor", "log", "service")
# Inference order for bare paths: CMDB is what callers mean most of the time.
KIND_INFERENCE_ORDER = ("cmdb", "monitor", "log", "service")

_EXPLICIT_PREFIX = re.compile(r"^/?api/v2/(cmdb|monitor|log|service)/(.+)$")


def _build_endpoint(kind: str, rest: str) -> str:
    rest = re.sub(r"\{[^}]+\}", "{key}", rest.strip("/"))
    if kind == "cmdb":
        rest = normalize_cmdb_path(rest)
    return f"/api/v2/{kind}/{rest}" if rest else f"/api/v2/{kind}"


def canonical_endpoint(path: str, kind: str | None = None) -> str:
    """Normalise any accepted spelling into ``/api/v2/<kind>/<path>``.

    Accepts what callers actually type::

        firewall/policy                     -> /api/v2/cmdb/firewall/policy
        cmdb/firewall/policy                -> /api/v2/cmdb/firewall/policy
        /api/v2/cmdb/firewall/policy        -> /api/v2/cmdb/firewall/policy
        monitor/system/status               -> /api/v2/monitor/system/status
        system/snmp/sysinfo                 -> /api/v2/cmdb/system.snmp/sysinfo
        system.snmp/sysinfo                 -> /api/v2/cmdb/system.snmp/sysinfo

    ``monitor``, ``log`` and ``service`` are also CMDB module names, so when a
    bare path is ambiguous (``log/setting``) the catalog decides: whichever
    namespace documents the endpoint wins. The resolved path is always returned
    to the caller, never silently kept private.
    """
    raw = path.strip()
    if not raw:
        raise ValueError("endpoint path must not be empty")

    explicit = kind
    match = _EXPLICIT_PREFIX.match(raw)
    if match:
        explicit, raw = match.group(1), match.group(2)
    elif explicit is None:
        first, sep, rest = raw.strip("/").partition("/")
        if sep and first in KINDS:
            explicit, raw = first, rest

    if explicit:
        resolved = _build_endpoint(explicit, raw)
        if resolved in _catalog()["endpoints"]:
            return resolved
        # The namespace prefix may be wrong (``log/setting`` -> cmdb).
        for other in KIND_INFERENCE_ORDER:
            if other == explicit:
                continue
            candidate = _build_endpoint(other, raw)
            if candidate in _catalog()["endpoints"]:
                return candidate
        return resolved

    for candidate_kind in KIND_INFERENCE_ORDER:
        candidate = _build_endpoint(candidate_kind, raw)
        if candidate in _catalog()["endpoints"]:
            return candidate
    # Undocumented endpoint: assume CMDB, which is the common case.
    return _build_endpoint("cmdb", raw)


def normalize_cmdb_path(path: str) -> str:
    """Convert slash-style CMDB paths to the exact URL FortiOS expects.

    FortiOS uses ``/`` for most modules (``firewall/addrgrp``) but a dot for a
    fixed set of composite modules (``system.snmp/sysinfo``,
    ``firewall.service/custom``). Both spellings are accepted.
    """
    clean = path.strip("/")
    if not clean:
        return clean
    parts = clean.split("/")
    modules = composite_modules()
    # Match the LONGEST composite module first (most specific):
    # vpn/ssl/web/portal -> vpn.ssl.web (3 segments), not vpn.ssl (2 segments)
    if len(parts) >= 3:
        candidate3 = f"{parts[0]}.{parts[1]}.{parts[2]}"
        if candidate3 in modules:
            return f"{candidate3}/{'/'.join(parts[3:])}"
    if len(parts) >= 2:
        candidate = f"{parts[0]}.{parts[1]}"
        if candidate in modules:
            return f"{candidate}/{'/'.join(parts[2:])}"
    return clean


def endpoint_entry(path: str) -> dict[str, Any] | None:
    """Raw catalog record for an endpoint, or None if undocumented."""
    return _catalog()["endpoints"].get(canonical_endpoint(path))


def endpoint_versions(path: str, method: str | None = None) -> list[str]:
    """Releases in which an endpoint (optionally for a method) exists."""
    entry = endpoint_entry(path)
    if not entry:
        return []
    methods = entry["methods"]
    if method:
        return list(methods.get(method.lower(), []))
    versions = {v for vs in methods.values() for v in vs}
    return sorted(versions, key=_version_key)


def endpoint_methods(path: str, version: str | None = None) -> list[str]:
    """HTTP methods an endpoint accepts, optionally restricted to a release."""
    entry = endpoint_entry(path)
    if not entry:
        return []
    if version is None:
        return sorted(entry["methods"])
    return sorted(m for m, vs in entry["methods"].items() if version in vs)


def check_endpoint(path: str, version: str | None = None,
                   method: str | None = None) -> dict[str, Any]:
    """Report whether an endpoint is expected to work on a FortiOS release.

    Returns a dict with ``supported`` set to True / False, or None when the
    catalog has no record (an undocumented or brand-new endpoint — the server
    still forwards those, it just cannot vouch for them).
    """
    try:
        canonical = canonical_endpoint(path)
    except ValueError as exc:
        return {"supported": None, "endpoint": path, "reason": str(exc)}

    entry = endpoint_entry(canonical)
    if entry is None:
        result = {
            "supported": None,
            "endpoint": canonical,
            "reason": "endpoint is not in the shipped catalog; request is forwarded as-is",
        }
        similar = suggest_endpoints(path)
        if similar:
            result["similar_endpoints"] = similar
        return result

    known = endpoint_versions(canonical, method)
    result: dict[str, Any] = {
        "endpoint": canonical,
        "kind": entry["kind"],
        "module": entry["module"],
        "summary": entry["summary"],
        "methods": entry["methods"],
        "known_versions": known,
        "introduced_in": known[0] if known else None,
    }
    if version is None:
        result["supported"] = None
        result["reason"] = "no target version given; reporting catalog facts only"
        return result

    if version in known:
        result["supported"] = True
        result["reason"] = f"available in FortiOS {version}"
        return result

    result["supported"] = False
    if not known:
        result["reason"] = f"no documented release exposes this endpoint for method {method!r}"
    elif version not in supported_versions():
        result["reason"] = (
            f"FortiOS {version} is outside the documented range "
            f"({', '.join(supported_versions())}); endpoint exists in {', '.join(known)}"
        )
    else:
        result["reason"] = (
            f"endpoint is not present in FortiOS {version} "
            f"(documented in: {', '.join(known)})"
        )
    return result


def endpoint_schema(path: str, method: str = "get") -> dict[str, Any]:
    """Field definitions and query parameters for one operation.

    Schemas come from the newest release that documents the operation, so an
    endpoint dropped from a newer Swagger bundle still reports its schema.

    ``fields_source`` says where the field list came from: ``body`` is the
    request payload schema FortiOS itself publishes, ``response`` is the object
    representation (which uses the same field names for writes).
    """
    try:
        canonical = canonical_endpoint(path)
    except ValueError:
        return {"endpoint": path, "error": "endpoint path must not be empty"}

    verb = method.lower()
    key = f"{canonical}#{verb}"
    slot = _fields().get(key)
    if slot is None:
        response: dict[str, Any] = {
            "endpoint": canonical,
            "method": verb,
            "error": "no documented schema for this endpoint/method",
            "documented_methods": endpoint_methods(canonical),
        }
        similar = suggest_endpoints(path)
        if similar:
            response["similar_endpoints"] = similar
        return response

    wants_body = verb in ("post", "put")
    body = slot.get("write")
    read = slot.get("read")
    if wants_body and body:
        fields, fields_source = body, "body"
    elif not wants_body and read:
        fields, fields_source = read, "response"
    elif body:
        fields, fields_source = body, "body"
    elif read:
        fields, fields_source = read, "response"
    else:
        fields, fields_source = {}, "none"

    result: dict[str, Any] = {
        "endpoint": canonical,
        "method": verb,
        "available_in": endpoint_versions(canonical, verb),
        "query_params": slot.get("params", []),
        "fields": fields,
        "fields_source": fields_source,
        "field_count": len(fields),
    }
    if wants_body and fields_source == "response" and read:
        result["fields_source_note"] = (
            "Fortinet publishes no separate body schema for this operation; the "
            "object representation below uses the same field names FortiOS accepts."
        )
    return result


def endpoints_map() -> dict[str, Any]:
    """The raw ``endpoint -> {kind, module, summary, methods}`` mapping."""
    return _catalog()["endpoints"]


def endpoints(kind: str | None = None, module: str | None = None,
              version: str | None = None, method: str | None = None,
              search: str | None = None, include_singletons: bool = True) -> list[dict[str, Any]]:
    """Filter the catalog.

    Args:
        kind: ``cmdb`` / ``monitor`` / ``log`` / ``service``.
        module: first path segment, e.g. ``firewall`` (also matches composite
            modules such as ``firewall.service``).
        version: only endpoints that exist in this FortiOS release.
        method: only endpoints accepting this HTTP method.
        search: case-insensitive substring match on the path or summary.
        include_singletons: set False to hide ``{key}`` variants.
    """
    out = []
    needle = search.lower() if search else None
    wanted_method = method.lower() if method else None

    for path, entry in _catalog()["endpoints"].items():
        methods = entry["methods"]
        if kind and entry["kind"] != kind:
            continue
        if module and not (entry["module"] == module or entry["module"].split(".")[0] == module):
            continue
        if not include_singletons and "{key}" in path:
            continue
        if wanted_method and wanted_method not in methods:
            continue
        if version:
            for_this_version = [m for m in methods if not wanted_method or m == wanted_method]
            if not any(version in methods[m] for m in for_this_version):
                continue
        if needle and needle not in path.lower() and needle not in (entry["summary"] or "").lower():
            continue
        out.append({
            "endpoint": path,
            "kind": entry["kind"],
            "module": entry["module"],
            "summary": entry["summary"],
            "methods": sorted(methods),
            "versions": sorted({v for vs in methods.values() for v in vs}, key=_version_key),
        })
    return out


def suggest_endpoints(path: str, limit: int = 8) -> list[str]:
    """Close matches for a path the catalog does not know.

    Turns "endpoint not found" into something actionable: tail segments are
    matched exactly first, then fuzzily, so ``firewall/security-policie`` still
    finds ``firewall/security-policy``.
    """
    resolved = canonical_endpoint_loose(path)
    parts = [s for s in resolved.split("/") if s not in ("api", "v2", "")]
    if not parts:
        return []
    kind = parts[0]
    tail = "/".join(parts[-2:])
    leaf = parts[-1]
    known = _catalog()["endpoints"]

    def rank(candidate: str, base: int) -> int:
        """Prefer candidates from the same API namespace, then deeper matches."""
        same_kind = 0 if candidate.split("/")[3:4] == [kind] else 1
        shared = sum(1 for a, b in zip(candidate.split("/")[3:], parts[1:]) if a == b)
        return base * 10 - shared + same_kind

    scored: list[tuple[int, str]] = []
    for candidate in known:
        if candidate == resolved:
            continue
        if candidate.endswith("/" + tail):
            scored.append((rank(candidate, 0), candidate))
        elif f"/{tail}/" in candidate:
            scored.append((rank(candidate, 1), candidate))
        elif candidate.endswith("/" + leaf):
            scored.append((rank(candidate, 2), candidate))

    if not scored:
        # Nothing shares a suffix — fall back to fuzzy matching on the leaf,
        # keeping every namespace that defines it.
        leaves: dict[str, list[str]] = {}
        for candidate in known:
            leaves.setdefault(candidate.rsplit("/", 1)[-1], []).append(candidate)
        for match in difflib.get_close_matches(leaf, list(leaves), n=limit, cutoff=0.8):
            for candidate in leaves[match]:
                scored.append((rank(candidate, 3), candidate))
        if not scored:
            for match in difflib.get_close_matches(resolved, list(known), n=limit, cutoff=0.75):
                scored.append((rank(match, 4), match))

    seen: set[str] = set()
    out: list[str] = []
    for _, candidate in sorted(scored):
        if candidate in seen:
            continue
        seen.add(candidate)
        out.append(candidate)
        if len(out) == limit:
            break
    return out


def canonical_endpoint_loose(path: str) -> str:
    """Normalise without consulting the catalog — safe for unknown paths."""
    raw = path.strip().strip("/")
    match = _EXPLICIT_PREFIX.match(raw)
    if match:
        return _build_endpoint(match.group(1), match.group(2))
    first, sep, rest = raw.partition("/")
    if sep and first in KINDS:
        return _build_endpoint(first, rest)
    return _build_endpoint("cmdb", raw)


def catalog_stats() -> dict[str, Any]:
    """Headline numbers, for health/status output."""
    data = _catalog()
    by_kind: dict[str, int] = {}
    for entry in data["endpoints"].values():
        by_kind[entry["kind"]] = by_kind.get(entry["kind"], 0) + 1
    return {
        "supported_versions": data["supported_versions"],
        "latest_version": data["latest_version"],
        "endpoints": len(data["endpoints"]),
        "endpoints_by_kind": dict(sorted(by_kind.items())),
        "composite_modules": len(data["union_composite_modules"]),
        "generated_at": data["generated_at"],
    }
