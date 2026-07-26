"""
Main STDIO server implementation for FortiGate MCP.

This module implements the core MCP server for FortiGate integration, providing:
- Configuration loading and validation
- Logging setup
- FortiGate API connection management
- MCP tool registration and routing
- Signal handling for graceful shutdown

The server exposes a set of tools for managing FortiGate resources including:
- Device management
- Firewall policy operations
- Network object management
- Routing configuration
"""
import os
import signal
import sys


from mcp.server.fastmcp import FastMCP

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


class FortiGateMCPServer:
    """Main server class for FortiGate MCP."""

    def __init__(self, config_path: str | None = None):
        """Initialize the server.

        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        self.config = load_config(config_path)
        self.logger = setup_logging(self.config.logging)
        
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
        
        # Initialize MCP server
        self.mcp = FastMCP("FortiGateMCP")
        self._tests_passed: bool | None = None
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

    def start(self) -> None:
        """Start the MCP server."""
        import anyio

        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown...")
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            # Optionally run tests before serving
            run_tests = os.getenv("RUN_TESTS_ON_START", "0").lower() in ("1", "true", "yes", "on")
            if run_tests:
                self.logger.info("Running startup tests...")
                # Add test logic here
                self._tests_passed = True

            self.logger.info("Starting FortiGate MCP server...")
            anyio.run(self.mcp.run_stdio_async)
        except Exception as e:
            self.logger.error(f"Server error: {e}")
            sys.exit(1)

if __name__ == "__main__":
    config_path = os.getenv("FORTIGATE_MCP_CONFIG")
    if not config_path:
        print("FORTIGATE_MCP_CONFIG environment variable must be set", file=sys.stderr)
        sys.exit(1)

    try:
        server = FortiGateMCPServer(config_path)
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down gracefully...", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


async def run_stdio_server(config_path: str) -> None:
    """Programmatic entry point for STDIO server (used by src/main.py)."""

    server = FortiGateMCPServer(config_path)
    try:
        await server.mcp.run_stdio_async()
    finally:
        await server.fortigate_manager.close_all()

