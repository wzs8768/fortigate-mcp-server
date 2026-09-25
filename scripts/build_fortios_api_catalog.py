#!/usr/bin/env python3
"""Build the FortiOS REST API catalog shipped with the MCP server.

The FortiGate MCP server needs to know, for a given FortiOS release:

* which REST endpoints exist (``/api/v2/cmdb/...``, ``/api/v2/monitor/...``, ...)
* which HTTP methods each endpoint accepts
* which CMDB "composite" modules use a DOT separator (``system.snmp/sysinfo``)
* which fields each endpoint accepts/returns (so agents don't get opaque
  FortiOS ``-651`` / ``-56`` errors)

Fortinet publishes one Swagger 2.0 document per module. Point this script at a
directory tree of those documents and it emits two compact JSON files consumed
by ``fortigate_mcp.core.api_catalog``:

    src/fortigate_mcp/data/fortios_api_catalog.json
    src/fortigate_mcp/data/fortios_api_fields.json

Usage:
    python scripts/build_fortios_api_catalog.py \
        --docs 7.4.12=/path/to/FortiOSAPI7.4.12 \
        --docs 8.0.1=/path/to/FortiOSAPI8.0.1

    # or discover every documented version under a parent directory:
    python scripts/build_fortios_api_catalog.py --auto /path/to/FortiGateAPI

Adding support for a future release therefore needs no code change: download
the Swagger bundle, re-run this script, commit the regenerated data files.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import glob
import json
import os
import re
import sys
from collections import defaultdict
from typing import Any

# Sub-directory names Fortinet has used for the Swagger bundles over time.
CONFIG_DIRS = ("Configuration", "config")
OTHER_DIRS = ("Monitor", "monitor", "Log", "log", "Service", "service")

METHODS = ("get", "post", "put", "delete")
# Descriptions are truncated to keep the shipped schema index small; the full
# text lives in Fortinet's Swagger bundles.
MAX_DESCRIPTION = 70
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(REPO_ROOT, "src", "fortigate_mcp", "data")

KIND_BY_BASE = {
    "/api/v2/cmdb": "cmdb",
    "/api/v2/monitor": "monitor",
    "/api/v2/log": "log",
    "/api/v2/service": "service",
}
# Sub-directory each kind is normally filed under (Fortinet renamed
# Configuration/ to config/ in some bundles).
DIRS_BY_KIND = {
    "cmdb": {"configuration", "config"},
    "monitor": {"monitor"},
    "log": {"log"},
    "service": {"service"},
}


def _params_as_list(op: dict) -> list[dict]:
    """Fortinet emits ``parameters`` sometimes as a list, sometimes as an
    object keyed by numeric strings. Normalise to a list of dicts."""
    raw = op.get("parameters")
    if isinstance(raw, dict):
        return [v for v in raw.values() if isinstance(v, dict)]
    if isinstance(raw, list):
        return [v for v in raw if isinstance(v, dict)]
    return []


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version)) or (0,)


def _iter_doc_files(root: str):
    """Yield every Swagger document under ``root``.

    Fortinet's bundles are normally split across Configuration / Monitor / Log /
    Service sub-directories, but documents get filed in the wrong one in
    practice (a Service document dropped into ``Configuration/``). Since each
    document carries its own ``basePath``, the directory is not authoritative —
    so walk the whole tree and let ``basePath`` decide. Files in the expected
    directories come first, so the common case stays deterministic.
    """
    seen: set[str] = set()
    for sub in CONFIG_DIRS + OTHER_DIRS:
        for path in sorted(glob.glob(os.path.join(root, sub, "*.json"))):
            seen.add(os.path.realpath(path))
            yield path
    for path in sorted(glob.glob(os.path.join(root, "**", "*.json"), recursive=True)):
        real = os.path.realpath(path)
        if real not in seen:
            seen.add(real)
            yield path


def _load_swagger(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def build(version_dirs: dict[str, str]) -> tuple[dict, dict]:
    """Parse every Swagger document and return (catalog, field_index)."""
    endpoints: dict[str, dict] = {}
    details: dict[str, dict] = {}
    versions = sorted(version_dirs, key=_version_key)
    sources: dict[str, dict] = {}
    composite: dict[str, list[str]] = {}

    for version in versions:
        root = version_dirs[version]
        files = list(_iter_doc_files(root))
        if not files:
            raise SystemExit(f"No Swagger documents found under {root!r} for {version}")
        path_count = 0
        composite_mods: set[str] = set()
        # Documents are classified by their own basePath, so a module doc filed
        # in the wrong sub-directory still lands in the right namespace. Track
        # any mismatch so a misplaced file is reported rather than silently
        # tolerated.
        docs: list[tuple[str, dict, str]] = []
        misfiled: list[str] = []
        skipped: list[str] = []

        for file_path in files:
            doc = _load_swagger(file_path)
            base = (doc.get("basePath") or "").rstrip("/")
            if base not in KIND_BY_BASE:
                skipped.append(f"{os.path.basename(file_path)} (basePath {base!r})")
                continue
            kind = KIND_BY_BASE[base]
            docs.append((file_path, doc, kind))
            actual_dir = os.path.basename(os.path.dirname(file_path)).lower()
            if actual_dir not in DIRS_BY_KIND[kind]:
                misfiled.append(f"{os.path.basename(file_path)} is a {kind} document "
                                f"filed under {actual_dir}/")

        for file_path, doc, kind in docs:
            base = {v: k for k, v in KIND_BY_BASE.items()}[kind]

            for raw_path, item in (doc.get("paths") or {}).items():
                if not isinstance(item, dict):
                    continue
                full = f"{base}/{raw_path.strip('/')}"
                # Placeholders vary per module ({name}, {id}, {policyid}, ...).
                # Collapse them so lookups match whatever a caller typed.
                full = re.sub(r"\{[^}]+\}", "{key}", full)
                path_count += 1

                if kind == "cmdb":
                    first = raw_path.strip("/").split("/")[0]
                    if "." in first:
                        composite_mods.add(first)

                entry = endpoints.setdefault(full, {
                    "kind": kind,
                    "module": raw_path.strip("/").split("/")[0],
                    "summary": "",
                    "methods": defaultdict(list),
                })
                # Newest version wins for human-readable metadata.
                summary = ""
                for method in METHODS:
                    op = item.get(method)
                    if not isinstance(op, dict):
                        continue
                    entry["methods"][method].append(version)
                    summary = summary or (op.get("summary") or "")
                if summary and (version == versions[-1] or not entry["summary"]):
                    entry["summary"] = summary[:MAX_DESCRIPTION].replace("\n", " ").strip()

                for method in METHODS:
                    op = item.get(method)
                    if not isinstance(op, dict):
                        continue
                    key = f"{full}#{method}"
                    slot = details.setdefault(key, {})
                    # Older releases only fill gaps; the newest release that
                    # defines this operation wins. Version availability itself
                    # lives in fortios_api_catalog.json, not here.
                    extracted = _extract_op_schema(op)
                    if version == versions[-1] or not any(slot.values()):
                        slot.update(extracted)

        sources[version] = {"dir": os.path.basename(root.rstrip("/")),
                            "files": len(docs), "paths": path_count}
        composite[version] = sorted(composite_mods)
        for note in skipped:
            print(f"  ! {version}: skipped {note} — unrecognised basePath", file=sys.stderr)
        for note in misfiled:
            print(f"  ~ {version}: {note} (classified by its own basePath, which is correct)")

    union_composite = sorted({m for mods in composite.values() for m in mods})

    catalog = {
        "schema_version": 1,
        "generated_at": _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
        "supported_versions": versions,
        "latest_version": versions[-1],
        "sources": sources,
        "composite_modules": composite,
        "union_composite_modules": union_composite,
        "endpoints": {
            path: {
                "kind": entry["kind"],
                "module": entry["module"],
                "summary": entry["summary"],
                "methods": {m: sorted(v, key=_version_key) for m, v in sorted(entry["methods"].items())},
            }
            for path, entry in sorted(endpoints.items())
        },
    }
    return catalog, details


def _describe_properties(props: Any) -> dict[str, dict]:
    """Compress a Swagger ``properties`` map into the shipped field index."""
    fields: dict[str, dict] = {}
    if not isinstance(props, dict):
        return fields
    for name, spec in props.items():
        if not isinstance(spec, dict):
            continue
        field: dict = {}
        if spec.get("type"):
            field["type"] = spec["type"]
        if spec.get("enum"):
            field["enum"] = spec["enum"]
        if spec.get("description"):
            field["desc"] = " ".join(str(spec["description"]).split())[:MAX_DESCRIPTION]
        for bound in ("minimum", "maximum", "maxLength", "minLength"):
            if spec.get(bound) is not None:
                field[bound] = spec[bound]
        fields[name] = field
    return fields


def _extract_op_schema(op: dict) -> dict:
    """Return the schema record for one operation.

    Keys (empty ones omitted, to keep the shipped file small):

    ``read``    fields the endpoint returns (``responses.200.schema``)
    ``write``   fields the endpoint accepts in the request body
    ``params``  accepted query parameters

    Path parameters are omitted — they are already visible in the path itself.
    """
    responses = op.get("responses") or {}
    schema = ((responses.get("200") or {}).get("schema")) or {}
    read = _describe_properties(schema.get("properties") if isinstance(schema, dict) else None)

    write: dict[str, dict] = {}
    query_params: list[str] = []
    for param in _params_as_list(op):
        if param.get("in") == "query" and param.get("name"):
            query_params.append(param["name"])
        elif param.get("in") == "body" and isinstance(param.get("schema"), dict):
            write = _describe_properties(param["schema"].get("properties")) or write

    record: dict = {}
    if read:
        record["read"] = read
    # FortiOS bodies use the same field names as the returned object, so an
    # identical ``write`` map is pure duplication — drop it and let readers
    # fall back to ``read``.
    if write and write != read:
        record["write"] = write
    elif write and write == read:
        record["write_matches_read"] = True
    if query_params:
        record["params"] = sorted(set(query_params))
    return record


def _auto_discover(parent: str) -> dict[str, str]:
    """Map version -> directory for every ``*<version>*`` doc tree under parent."""
    found: dict[str, str] = {}
    for entry in sorted(glob.glob(os.path.join(parent, "*"))):
        if not os.path.isdir(entry):
            continue
        has_docs = any(glob.glob(os.path.join(entry, sub, "*.json")) for sub in CONFIG_DIRS + OTHER_DIRS)
        if not has_docs:
            continue
        match = re.search(r"(\d+\.\d+\.\d+)", os.path.basename(entry))
        if match:
            found[match.group(1)] = entry
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--docs", action="append", default=[], metavar="VERSION=DIR",
                        help="e.g. --docs 8.0.1=/srv/FortiOSAPI8.0.1 (repeatable)")
    parser.add_argument("--auto", metavar="PARENT_DIR",
                        help="auto-discover *<version>* document trees under this directory")
    parser.add_argument("--out", default=DATA_DIR, help=f"output directory (default: {DATA_DIR})")
    args = parser.parse_args()

    version_dirs: dict[str, str] = {}
    if args.auto:
        version_dirs.update(_auto_discover(args.auto))
    for spec in args.docs:
        if "=" not in spec:
            parser.error(f"--docs needs VERSION=DIR, got {spec!r}")
        version, directory = spec.split("=", 1)
        version_dirs[version.strip()] = directory.strip()

    if not version_dirs:
        parser.error("nothing to do: pass --docs and/or --auto")
    missing = [d for d in version_dirs.values() if not os.path.isdir(d)]
    if missing:
        parser.error(f"not a directory: {', '.join(missing)}")

    print("Building FortiOS API catalog from:")
    for version in sorted(version_dirs, key=_version_key):
        print(f"  {version:<8} {version_dirs[version]}")

    catalog, details = build(version_dirs)

    os.makedirs(args.out, exist_ok=True)
    catalog_path = os.path.join(args.out, "fortios_api_catalog.json")
    fields_path = os.path.join(args.out, "fortios_api_fields.json")
    with open(catalog_path, "w", encoding="utf-8") as fh:
        json.dump(catalog, fh, ensure_ascii=False, indent=1, sort_keys=False)
        fh.write("\n")
    with open(fields_path, "w", encoding="utf-8") as fh:
        # Compact: this file is machine-read only, and the pretty-printed
        # variant is several times larger.
        json.dump(details, fh, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        fh.write("\n")

    print(f"\n  endpoints : {len(catalog['endpoints']):>5}  -> {catalog_path} "
          f"({os.path.getsize(catalog_path) / 1024:.0f} KB)")
    print(f"  schemas   : {len(details):>5}  -> {fields_path} "
          f"({os.path.getsize(fields_path) / 1024:.0f} KB)")
    for version in catalog["supported_versions"]:
        src = catalog["sources"][version]
        print(f"  {version:<8} {src['files']:>3} files, {src['paths']:>5} paths, "
              f"{len(catalog['composite_modules'][version])} composite modules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
