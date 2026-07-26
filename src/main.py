"""FortiGate MCP Server — unified CLI entry point."""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def main() -> None:
    """Launch FortiGate MCP Server in STDIO or HTTP mode."""
    parser = argparse.ArgumentParser(
        prog="fortigate-mcp-server",
        description="FortiGate MCP Server — manage FortiGate firewalls via MCP",
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # STDIO subcommand
    stdio_p = sub.add_parser("stdio", help="Start STDIO MCP server")
    stdio_p.add_argument("--config", default="config/config.json", help="Config file path")

    # HTTP subcommand
    http_p = sub.add_parser("http", help="Start HTTP/HTTPS MCP server")
    http_p.add_argument("--config", default="config/config.json", help="Config file path")
    http_p.add_argument("--host", default="0.0.0.0")
    http_p.add_argument("--port", type=int, default=None)
    http_p.add_argument("--transport", default="all",
                        choices=["all", "streamable-http", "sse"])
    http_p.add_argument("--ssl-cert", default=None)
    http_p.add_argument("--ssl-key", default=None)

    args = parser.parse_args()

    # Ensure config dir is in path for relative imports
    config_dir = str(Path(args.config).parent.resolve())
    if config_dir not in sys.path:
        sys.path.insert(0, config_dir)

    if args.mode == "stdio":
        from src.fortigate_mcp.server import run_stdio_server

        asyncio.run(run_stdio_server(args.config))
    elif args.mode == "http":
        from src.fortigate_mcp.server_http import run_http_server

        asyncio.run(run_http_server(
            config_path=args.config,
            host=args.host,
            port=args.port,
            transport=args.transport,
            ssl_cert=args.ssl_cert,
            ssl_key=args.ssl_key,
        ))


if __name__ == "__main__":
    main()
