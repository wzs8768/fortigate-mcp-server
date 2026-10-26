#!/usr/bin/env python3
"""Build the FortiOS REST API catalog shipped with the MCP server.

The FortiGate MCP server needs to know, for a given FortiOS release:

* which REST endpoints exist (``/api/v2/cmdb/...``, ``/api/v2/monitor/...``, ...)
* which HTTP methods each endpoint accepts
* which CMDB "composite" modules use a DOT separator (``system.snmp/sysinfo``)

Only that path/method/version index is emitted. Endpoint summaries and field
schemas are intentionally not extracted: the Swagger bundles are FNDN material
and the published catalog must not become a substitute for them.

Fortinet publishes one Swagger 2.0 document per module. Point this script at a
directory tree of those documents and it emits one compact JSON file consumed
by ``fortigate_mcp.core.api_catalog``:

    src/fortigate_mcp/data/fortios_api_catalog.json

Usage:
    python scripts/build_fortios_api_catalog.py \
        --docs 7.4.12=/path/to/FortiOSAPI7.4.12 \
        --docs 8.0.2=/path/to/FortiOSAPI8.0.2

    # or discover every documented version under a parent directory:
    python scripts/build_fortios_api_catalog.py --auto /path/to/FortiGateAPI

Adding support for a future release therefore needs no code change: download
the Swagger bundle, re-run this script, commit the regenerated data file.
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

# Sub-directory names Fortinet has used for the Swagger bundles over time.
CONFIG_DIRS = ("Configuration", "config")
OTHER_DIRS = ("Monitor", "monitor", "Log", "log", "Service", "service")

METHODS = ("get", "post", "put", "delete")
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


def build(version_dirs: dict[str, str]) -> dict:
    """Parse every Swagger document and return the path/method catalog."""
    endpoints: dict[str, dict] = {}
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
                    "methods": defaultdict(list),
                })
                # Only method/version availability is recorded — no summaries,
                # descriptions or field schemas.
                for method in METHODS:
                    if isinstance(item.get(method), dict):
                        entry["methods"][method].append(version)

        sources[version] = {"dir": os.path.basename(root.rstrip("/")),
                            "files": len(docs), "paths": path_count}
        composite[version] = sorted(composite_mods)
        for note in skipped:
            print(f"  ! {version}: skipped {note} — unrecognised basePath", file=sys.stderr)
        for note in misfiled:
            print(f"  ~ {version}: {note} (classified by its own basePath, which is correct)")

    union_composite = sorted({m for mods in composite.values() for m in mods})

    catalog = {
        "schema_version": 2,
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
                "methods": {m: sorted(v, key=_version_key) for m, v in sorted(entry["methods"].items())},
            }
            for path, entry in sorted(endpoints.items())
        },
    }
    return catalog


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

    catalog = build(version_dirs)

    os.makedirs(args.out, exist_ok=True)
    catalog_path = os.path.join(args.out, "fortios_api_catalog.json")
    with open(catalog_path, "w", encoding="utf-8") as fh:
        json.dump(catalog, fh, ensure_ascii=False, indent=1, sort_keys=False)
        fh.write("\n")

    print(f"\n  endpoints : {len(catalog['endpoints']):>5}  -> {catalog_path} "
          f"({os.path.getsize(catalog_path) / 1024:.0f} KB)")
    for version in catalog["supported_versions"]:
        src = catalog["sources"][version]
        print(f"  {version:<8} {src['files']:>3} files, {src['paths']:>5} paths, "
              f"{len(catalog['composite_modules'][version])} composite modules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
