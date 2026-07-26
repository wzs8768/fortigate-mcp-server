"""
HTTP-based MCP server implementation for FortiGate MCP.

This module provides an HTTP transport layer for the MCP server,
supporting HTTP transport for web-based integrations and external access.
"""

import asyncio
import os
import signal
import sys

try:
    from fastmcp import FastMCP
    FASTMCP_AVAILABLE = True
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP
        FASTMCP_AVAILABLE = True
    except ImportError:
        FASTMCP_AVAILABLE = False


from .auth_middleware import make_auth_middleware
from .config.loader import load_config
from .core.fortigate import FortiGateManager
from .core.logging import setup_logging
from .tools.cmdb import CmdbTools
from .tools.device import DeviceTools
from .tools.firewall import FirewallTools
from .tools.network import NetworkTools
from .tools.resources import ResourceTools
from .tools.routing import RoutingTools
from .tools.schedules import ScheduleTools
from .tools.security import SecurityTools
from .tools.virtual_ip import VirtualIPTools


class FortiGateMCPHTTPServer:
    """
    HTTP-based MCP server for FortiGate management.
    
    Supports three transport modes:
    - streamable-http: Modern MCP transport with session management
    - sse: Legacy SSE transport
    - all: Both SSE and streamable-http on the same port
    
    All modes support HTTPS when SSL cert/key are provided.
    """

    def __init__(self,
                 config_path: str | None = None,
                 host: str = "0.0.0.0",
                 port: int = 8814,
                 path: str = "/fortigate-mcp",
                 ssl_cert: str | None = None,
                 ssl_key: str | None = None,
                 transport: str = "streamable-http",
                 sse_path: str = "/fortigate-mcp-sse"):
        """
        Initialize the HTTP MCP server.

        Args:
            config_path: Path to configuration file
            host: Server host address
            port: Server port
            path: HTTP path for streamable-http endpoint
            ssl_cert: Path to SSL certificate file (.crt/.pem) for HTTPS
            ssl_key: Path to SSL private key file (.key) for HTTPS
            transport: "sse", "streamable-http", or "all"
            sse_path: SSE endpoint path (default: /fortigate-mcp-sse)
        """
        if not FASTMCP_AVAILABLE:
            raise RuntimeError("FastMCP is not available. Please install fastmcp package.")

        # Load and validate configuration
        self.config = load_config(config_path)

        # Setup logging
        self.logger = setup_logging(self.config.logging)

        self.host = host
        self.port = port
        self.path = path
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.transport = transport
        self.sse_path = sse_path

        # Initialize core components
        self.fortigate_manager = FortiGateManager(
            self.config.fortigate.devices,
            self.config.auth
        )

        # Initialize tools
        self.device_tools = DeviceTools(self.fortigate_manager)
        self.firewall_tools = FirewallTools(self.fortigate_manager)
        self.network_tools = NetworkTools(self.fortigate_manager)
        self.routing_tools = RoutingTools(self.fortigate_manager)
        self.virtual_ip_tools = VirtualIPTools(self.fortigate_manager)
        self.schedule_tools = ScheduleTools(self.fortigate_manager)
        self.resource_tools = ResourceTools(self.fortigate_manager)
        self.security_tools = SecurityTools(self.fortigate_manager)
        self.cmdb_tools = CmdbTools(self.fortigate_manager)
        self._tests_passed: bool | None = None

        # Initialize FastMCP with appropriate path settings
        mcp_kwargs = {
            "host": self.host,
            "port": self.port,
        }
        if self.transport in ("sse", "all"):
            mcp_kwargs["sse_path"] = self.sse_path
            mcp_kwargs["message_path"] = "/messages/"
        if self.transport in ("streamable-http", "all"):
            mcp_kwargs["streamable_http_path"] = self.path
        self.mcp = FastMCP("FortiGateMCP-HTTP", **mcp_kwargs)

        # Setup tools
        self._setup_tools()

    def _setup_tools(self) -> None:
        """Register MCP tools via the shared tool registry."""
        from .tool_registry import _ToolNamespace, register_all_tools

        t = _ToolNamespace(
            device=self.device_tools,
            firewall=self.firewall_tools,
            network=self.network_tools,
            routing=self.routing_tools,
            virtual_ip=self.virtual_ip_tools,
            schedule=self.schedule_tools,
            security=self.security_tools,
            resource=self.resource_tools,
            cmdb=self.cmdb_tools,
        )
        t.tests_passed = self._tests_passed
        t.manager = self.fortigate_manager
        t.config = self.config
        register_all_tools(self.mcp, t)

    def run(self) -> None:
        """
        Start the HTTP MCP server.

        Runs the server with the configured transport(s) on the configured host
        and port. When transport="all", both SSE and streamable-http are served
        simultaneously. If SSL certificate and key are provided, runs with HTTPS
        (TLS).

        Auth middleware is applied when ``config.auth.require_auth`` is True.
        """

        import uvicorn
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        # Fast health check — no FortiGate connection needed
        async def _health_endpoint(request):
            devices = self.fortigate_manager.list_devices()
            return JSONResponse({
                "status": "ok",
                "server_version": self.config.server.version,
                "registered_devices": len(devices),
                "devices": [{
                    "device_id": d["device_id"],
                    "os_version": d.get("os_version"),
                    "version_detected": d.get("version_detected", False),
                } for d in devices],
            })

        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown HTTP server...")
            import asyncio as _asyncio
            try:
                loop = _asyncio.get_event_loop()
                if loop.is_running():
                    _asyncio.ensure_future(self.fortigate_manager.close_all())
                else:
                    loop.run_until_complete(self.fortigate_manager.close_all())
            except Exception:
                pass
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Build auth middleware from config
        auth_cls = make_auth_middleware(
            require_auth=getattr(self.config.auth, "require_auth", False),
            api_tokens=getattr(self.config.auth, "api_tokens", []),
        )

        try:
            protocol = "HTTPS" if self.ssl_cert else "HTTP"
            if self.transport == "all":
                self.logger.info(
                    f"Starting FortiGate MCP {protocol} server "
                    f"(SSE + streamable-http) on {self.host}:{self.port}\n"
                    f"  SSE:            {protocol.lower()}://{self.host}:{self.port}{self.sse_path}\n"
                    f"  Streamable HTTP: {protocol.lower()}://{self.host}:{self.port}{self.path}"
                )
            else:
                display_path = self.sse_path if self.transport == "sse" else self.path
                self.logger.info(
                    f"Starting FortiGate MCP {protocol} server "
                    f"({self.transport}) on {self.host}:{self.port}{display_path}"
                )
            self.logger.info(f"Registered devices: {len(self.fortigate_manager.devices)}")
            if getattr(self.config.auth, "require_auth", False):
                self.logger.info(
                    f"Auth enabled — {len(getattr(self.config.auth, 'api_tokens', []))} token(s) configured"
                )
            else:
                self.logger.info("Auth disabled — server is open")

            if self.transport == "all":
                # Combine both apps into a single uvicorn server by merging routes.
                # We must carry over the streamable_http_app's lifespan so the
                # session manager's async task group is properly initialized.
                sse_app = self.mcp.sse_app()
                sh_app = self.mcp.streamable_http_app()
                all_routes = list(sse_app.routes) + list(sh_app.routes)
                all_routes.append(Route("/health", _health_endpoint, methods=["GET"]))
                lifespan = sh_app.router.lifespan_context
                combined = Starlette(debug=False, routes=all_routes, lifespan=lifespan)
                combined.add_middleware(auth_cls)

                config = uvicorn.Config(
                    combined,
                    host=self.host,
                    port=self.port,
                    ssl_certfile=self.ssl_cert,
                    ssl_keyfile=self.ssl_key,
                    log_level=self.config.logging.level.lower(),
                )
                server = uvicorn.Server(config)
                asyncio.run(server.serve())
            elif self.ssl_cert:
                # Single-transport HTTPS mode: run uvicorn directly with SSL
                if self.transport == "sse":
                    starlette_app = self.mcp.sse_app()
                else:
                    starlette_app = self.mcp.streamable_http_app()

                starlette_app.add_middleware(auth_cls)
                starlette_app.routes.append(Route("/health", _health_endpoint, methods=["GET"]))

                config = uvicorn.Config(
                    starlette_app,
                    host=self.host,
                    port=self.port,
                    ssl_certfile=self.ssl_cert,
                    ssl_keyfile=self.ssl_key,
                    log_level=self.config.logging.level.lower(),
                )
                server = uvicorn.Server(config)
                asyncio.run(server.serve())
            else:
                # Single-transport plain HTTP mode: build Starlette app with uvicorn
                # (replaces FastMCP.run so we can inject auth middleware)
                if self.transport == "sse":
                    starlette_app = self.mcp.sse_app()
                else:
                    starlette_app = self.mcp.streamable_http_app()

                starlette_app.add_middleware(auth_cls)
                starlette_app.routes.append(Route("/health", _health_endpoint, methods=["GET"]))
                
                config = uvicorn.Config(
                    starlette_app,
                    host=self.host,
                    port=self.port,
                    log_level=self.config.logging.level.lower(),
                )
                server = uvicorn.Server(config)
                asyncio.run(server.serve())
        except Exception as e:
            self.logger.error(f"Server error: {e}")
            sys.exit(1)


class FortiGateMCPCommand:
    """
    Command runner for FortiGate MCP HTTP server.
    
    This class can be used as a standalone command runner.
    """
    
    help = "FortiGate MCP HTTP Server"
    
    def __init__(self):
        self.server = None
    
    def add_arguments(self, parser):
        """Add command line arguments."""
        parser.add_argument(
            '--host',
            type=str,
            default='0.0.0.0',
            help='Server host (default: 0.0.0.0)'
        )
        parser.add_argument(
            '--port',
            type=int,
            default=8814,
            help='Server port (default: 8814)'
        )
        parser.add_argument(
            '--path',
            type=str,
            default='/fortigate-mcp',
            help='HTTP path (default: /fortigate-mcp)'
        )
        parser.add_argument(
            '--transport',
            type=str,
            default='streamable-http',
            choices=['sse', 'streamable-http', 'all'],
            help='Transport protocol: sse, streamable-http, or all (default: streamable-http)'
        )
        parser.add_argument(
            '--sse-path',
            type=str,
            default='/fortigate-mcp-sse',
            help='Mount path for SSE transport (default: /fortigate-mcp-sse)'
        )
        parser.add_argument(
            '--ssl-cert',
            type=str,
            default=None,
            help='SSL certificate file path for HTTPS (e.g., certs/server.crt)'
        )
        parser.add_argument(
            '--ssl-key',
            type=str,
            default=None,
            help='SSL private key file path for HTTPS (e.g., certs/server.key)'
        )
        parser.add_argument(
            '--config',
            type=str,
            help='Configuration file path'
        )
    
    def handle(self, *args, **options):
        """Handle the command execution."""
        config_path = options.get('config') or os.getenv('FORTIGATE_MCP_CONFIG')
        
        self.server = FortiGateMCPHTTPServer(
            config_path=config_path,
            host=options.get('host', '0.0.0.0'),
            port=options.get('port', 8814),
            path=options.get('path', '/fortigate-mcp'),
            ssl_cert=options.get('ssl_cert'),
            ssl_key=options.get('ssl_key'),
            transport=options.get('transport', 'streamable-http'),
            sse_path=options.get('sse_path', '/fortigate-mcp-sse'),
        )
        
        self.server.run()


def main():
    """Main entry point for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description='FortiGate MCP HTTP Server')
    command = FortiGateMCPCommand()
    command.add_arguments(parser)
    
    args = parser.parse_args()
    options = vars(args)
    
    try:
        command.handle(**options)
    except KeyboardInterrupt:
        print("\nShutting down gracefully...", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
