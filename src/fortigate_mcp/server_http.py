"""
HTTP-based MCP server implementation for FortiGate MCP.

This module provides an HTTP transport layer for the MCP server,
supporting HTTP transport for web-based integrations and external access.
"""

import asyncio
import json
import os
import sys
import signal
from typing import Optional, Dict, Any
from datetime import datetime

try:
    from fastmcp import FastMCP
    FASTMCP_AVAILABLE = True
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP
        FASTMCP_AVAILABLE = True
    except ImportError:
        FASTMCP_AVAILABLE = False


from .config.loader import load_config
from .core.logging import setup_logging
from .core.fortigate import FortiGateManager
from .tools.device import DeviceTools
from .tools.firewall import FirewallTools
from .tools.network import NetworkTools
from .auth_middleware import make_auth_middleware
from .tools.routing import RoutingTools
from .tools.virtual_ip import VirtualIPTools
from .tools.schedules import ScheduleTools
from .tools.resources import ResourceTools
from .tools.security import SecurityTools
from .tools.cmdb import CmdbTools
from .tools.definitions import (
    LIST_DEVICES_DESC, GET_DEVICE_STATUS_DESC, TEST_DEVICE_CONNECTION_DESC,
    ADD_DEVICE_DESC, REMOVE_DEVICE_DESC, DISCOVER_VDOMS_DESC,
    LIST_FIREWALL_POLICIES_DESC, CREATE_FIREWALL_POLICY_DESC,
    UPDATE_FIREWALL_POLICY_DESC, DELETE_FIREWALL_POLICY_DESC,
    LIST_ADDRESS_OBJECTS_DESC, CREATE_ADDRESS_OBJECT_DESC,
    LIST_SERVICE_OBJECTS_DESC, CREATE_SERVICE_OBJECT_DESC,
    LIST_STATIC_ROUTES_DESC, CREATE_STATIC_ROUTE_DESC,
    GET_ROUTING_TABLE_DESC, LIST_INTERFACES_DESC, GET_INTERFACE_STATUS_DESC,
    UPDATE_STATIC_ROUTE_DESC, DELETE_STATIC_ROUTE_DESC,
    GET_STATIC_ROUTE_DETAIL_DESC,
    LIST_VIRTUAL_IPS_DESC, CREATE_VIRTUAL_IP_DESC, UPDATE_VIRTUAL_IP_DESC,
    GET_VIRTUAL_IP_DETAIL_DESC, DELETE_VIRTUAL_IP_DESC,
)

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
                 config_path: Optional[str] = None,
                 host: str = "0.0.0.0",
                 port: int = 8814,
                 path: str = "/fortigate-mcp",
                 ssl_cert: Optional[str] = None,
                 ssl_key: Optional[str] = None,
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
        """Register MCP tools with the server."""
        
        # Device management tools
        @self.mcp.tool(description=LIST_DEVICES_DESC)
        async def list_devices():
            return await self.device_tools.list_devices()

        @self.mcp.tool(description=GET_DEVICE_STATUS_DESC)
        async def get_device_status(
            device_id: str
        ):
            return await self.device_tools.get_device_status(device_id)

        @self.mcp.tool(description=TEST_DEVICE_CONNECTION_DESC)
        async def test_device_connection(
            device_id: str
        ):
            return await self.device_tools.test_device_connection(device_id)

        @self.mcp.tool(description=DISCOVER_VDOMS_DESC)
        async def discover_vdoms(
            device_id: str
        ):
            return await self.device_tools.discover_vdoms(device_id)

        @self.mcp.tool(description=ADD_DEVICE_DESC)
        async def add_device(
            device_id: str,
            host: str,
            port: int = 443,
            username: Optional[str] = None,
            password: Optional[str] = None,
            api_token: Optional[str] = None,
            vdom: str = "root",
            verify_ssl: bool = True,
            timeout: int = 30
        ):
            return await self.device_tools.add_device(
                device_id, host, port, username, password, api_token, vdom, verify_ssl, timeout
            )

        @self.mcp.tool(description=REMOVE_DEVICE_DESC)
        async def remove_device(
            device_id: str
        ):
            return await self.device_tools.remove_device(device_id)

        # Firewall policy tools
        @self.mcp.tool(description=LIST_FIREWALL_POLICIES_DESC)
        async def list_firewall_policies(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.firewall_tools.list_policies(device_id, vdom)

        @self.mcp.tool(description=CREATE_FIREWALL_POLICY_DESC)
        async def create_firewall_policy(
            device_id: str,
            policy_data: dict,
            vdom: Optional[str] = None
        ):
            return await self.firewall_tools.create_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description=UPDATE_FIREWALL_POLICY_DESC)
        async def update_firewall_policy(
            device_id: str,
            policy_id: str,
            policy_data: dict,
            vdom: Optional[str] = None
        ):
            return await self.firewall_tools.update_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Get detailed information for a specific firewall policy")
        async def get_firewall_policy_detail(
            device_id: str,
            policy_id: str,
            vdom: Optional[str] = None
        ):
            return await self.firewall_tools.get_policy_detail(device_id, policy_id, vdom)

        @self.mcp.tool(description=DELETE_FIREWALL_POLICY_DESC)
        async def delete_firewall_policy(
            device_id: str,
            policy_id: str,
            vdom: Optional[str] = None
        ):
            return await self.firewall_tools.delete_policy(device_id, policy_id, vdom)

        # Network object tools
        @self.mcp.tool(description=LIST_ADDRESS_OBJECTS_DESC)
        async def list_address_objects(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.list_address_objects(device_id, vdom)

        @self.mcp.tool(description=CREATE_ADDRESS_OBJECT_DESC)
        async def create_address_object(
            device_id: str,
            name: str,
            address_type: str,
            address: str,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.create_address_object(device_id, name, address_type, address, vdom)

        @self.mcp.tool(description=LIST_SERVICE_OBJECTS_DESC)
        async def list_service_objects(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.list_service_objects(device_id, vdom)

        @self.mcp.tool(description=CREATE_SERVICE_OBJECT_DESC)
        async def create_service_object(
            device_id: str,
            name: str,
            service_type: str,
            protocol: str,
            port: Optional[str] = None,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.create_service_object(device_id, name, service_type, protocol, port, vdom)

        # Routing tools
        @self.mcp.tool(description=LIST_STATIC_ROUTES_DESC)
        async def list_static_routes(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.routing_tools.list_static_routes(device_id, vdom)

        @self.mcp.tool(description=CREATE_STATIC_ROUTE_DESC)
        async def create_static_route(
            device_id: str,
            dst: str,
            gateway: str,
            device: Optional[str] = None,
            vdom: Optional[str] = None
        ):
            return await self.routing_tools.create_static_route(device_id, dst, gateway, device, vdom)

        @self.mcp.tool(description=GET_ROUTING_TABLE_DESC)
        async def get_routing_table(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.routing_tools.get_routing_table(device_id, vdom)

        @self.mcp.tool(description=LIST_INTERFACES_DESC)
        async def list_interfaces(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.routing_tools.list_interfaces(device_id, vdom)

        @self.mcp.tool(description=GET_INTERFACE_STATUS_DESC)
        async def get_interface_status(
            device_id: str,
            interface_name: str,
            vdom: Optional[str] = None
        ):
            return await self.routing_tools.get_interface_status(device_id, interface_name, vdom)

        @self.mcp.tool(description=UPDATE_STATIC_ROUTE_DESC)
        async def update_static_route(
            device_id: str,
            route_id: str,
            route_data: dict,
            vdom: Optional[str] = None
        ):
            return await self.routing_tools.update_static_route(device_id, route_id, route_data, vdom)

        @self.mcp.tool(description=DELETE_STATIC_ROUTE_DESC)
        async def delete_static_route(
            device_id: str,
            route_id: str,
            vdom: Optional[str] = None
        ):
            return await self.routing_tools.delete_static_route(device_id, route_id, vdom)

        @self.mcp.tool(description=GET_STATIC_ROUTE_DETAIL_DESC)
        async def get_static_route_detail(
            device_id: str,
            route_id: str,
            vdom: Optional[str] = None
        ):
            return await self.routing_tools.get_static_route_detail(device_id, route_id, vdom)

        # Virtual IP tools
        @self.mcp.tool(description=LIST_VIRTUAL_IPS_DESC)
        async def list_virtual_ips(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.virtual_ip_tools.list_virtual_ips(device_id, vdom)

        @self.mcp.tool(description=CREATE_VIRTUAL_IP_DESC)
        async def create_virtual_ip(
            device_id: str,
            name: str,
            extip: str,
            mappedip: str,
            extintf: str,
            portforward: str = "disable",
            protocol: str = "tcp",
            extport: Optional[str] = None,
            mappedport: Optional[str] = None,
            vdom: Optional[str] = None
        ):
            return await self.virtual_ip_tools.create_virtual_ip(
                device_id, name, extip, mappedip, extintf, portforward, protocol, extport, mappedport, vdom
            )

        @self.mcp.tool(description=UPDATE_VIRTUAL_IP_DESC)
        async def update_virtual_ip(
            device_id: str,
            name: str,
            vip_data: dict,
            vdom: Optional[str] = None
        ):
            return await self.virtual_ip_tools.update_virtual_ip(device_id, name, vip_data, vdom)

        @self.mcp.tool(description=GET_VIRTUAL_IP_DETAIL_DESC)
        async def get_virtual_ip_detail(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.virtual_ip_tools.get_virtual_ip_detail(device_id, name, vdom)

        @self.mcp.tool(description=DELETE_VIRTUAL_IP_DESC)
        async def delete_virtual_ip(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.virtual_ip_tools.delete_virtual_ip(device_id, name, vdom)

        # ============================================================
        # Address object update/delete tools (existing API, new MCP tools)
        # ============================================================
        @self.mcp.tool(description="""Update an existing address object on a FortiGate device.

Required params:
  - device_id: FortiGate device identifier
  - name: Name of the address object to update (from list_address_objects output)
  - address_data: JSON object with updated fields. Examples by type:
    ipmask: {"subnet": "192.168.1.0 255.255.255.0", "comment": "Updated"}
    iprange: {"start-ip": "10.0.0.1", "end-ip": "10.0.0.100"}
    fqdn: {"fqdn": "example.com"}
    geography: {"country": "CN"}
    wildcard-fqdn/custom: SSL exemption only, use update_wildcard_fqdn_custom instead
  - vdom: Virtual Domain (optional)

Returns: Update confirmation.""")

        async def update_address_object(
            device_id: str,
            name: str,
            address_data: dict,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.update_address_object(device_id, name, address_data, vdom)

        @self.mcp.tool(description="Delete an address object")
        async def delete_address_object(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.delete_address_object(device_id, name, vdom)

        @self.mcp.tool(description="""Update an existing firewall service object.

Required params:
  - name: Service name (from list_service_objects output)
  - service_data: JSON with updated fields. Examples:
    TCP: {"tcp-portrange": "8080-8090"}
    UDP: {"udp-portrange": "53"}
    ICMP: {"protocol-number": "1"}

Returns: Update confirmation.""")
        async def update_service_object(
            device_id: str,
            name: str,
            service_data: dict,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.update_service_object(device_id, name, service_data, vdom)

        @self.mcp.tool(description="Delete a service object")
        async def delete_service_object(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.delete_service_object(device_id, name, vdom)

        # ============================================================
        # Address Group tools
        # ============================================================
        @self.mcp.tool(description="List all address groups")
        async def list_addrgrps(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.list_addrgrps(device_id, vdom)

        @self.mcp.tool(description="""Create a new address group.

Address groups combine multiple address objects into a single reference for firewall policies.

Required fields in addrgrp_data:
  - name: Group name (string)
  - member: Array of address object references in [{name: "..."}] format, e.g.:
    [{name: "LAN_10.0.0.0_24"}, {name: "DMZ_192.168.1.0_24"}]

Returns: Creation confirmation with group details.""")
        async def create_addrgrp(
            device_id: str,
            addrgrp_data: dict,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.create_addrgrp(device_id, addrgrp_data, vdom)

        @self.mcp.tool(description="""Update an existing address group.

Required params:
  - name: Name of the address group to update (string, from list_addrgrps output)
  - addrgrp_data: JSON object with updated fields, e.g.:
    {member: [{name: "NEW-HOST"}, {name: "OLD-HOST"}]}

Note: addrgrp_data must contain the 'member' field even for partial updates.

Returns: Update confirmation with new group details.""")
        async def update_addrgrp(
            device_id: str,
            name: str,
            addrgrp_data: dict,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.update_addrgrp(device_id, name, addrgrp_data, vdom)

        @self.mcp.tool(description="Delete an address group")
        async def delete_addrgrp(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.delete_addrgrp(device_id, name, vdom)

        @self.mcp.tool(description="Get detailed information for an address group")
        async def get_addrgrp_detail(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.get_addrgrp_detail(device_id, name, vdom)

        # ============================================================
        # Service Group tools
        # ============================================================
        @self.mcp.tool(description="List all service groups")
        async def list_service_groups(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.list_service_groups(device_id, vdom)

        @self.mcp.tool(description="""Create a service group combining multiple service objects.

Required fields in data:
  - name: Group name (string)
  - member: Array of service references in [{"name": "HTTP"}, {"name": "HTTPS"}] format

Returns: Creation confirmation.""")

        async def create_service_group(
            device_id: str,
            service_group_data: dict,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.create_service_group(device_id, service_group_data, vdom)

        @self.mcp.tool(description="""Update an existing service group.

Required params:
  - name: Group name (string)
  - data: JSON with updated fields, e.g. {"member": [{"name": "NEW-SVC"}, {"name": "OLD-SVC"}]}

Returns: Update confirmation.""")

        async def update_service_group(
            device_id: str,
            name: str,
            service_group_data: dict,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.update_service_group(device_id, name, service_group_data, vdom)

        @self.mcp.tool(description="Delete a service group")
        async def delete_service_group(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.delete_service_group(device_id, name, vdom)

        # ============================================================
        # Schedule tools
        # ============================================================
        @self.mcp.tool(description="List all onetime schedules")
        async def list_schedule_onetime(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.schedule_tools.list_schedule_onetime(device_id, vdom)

        @self.mcp.tool(description="""Create a one-time schedule. Defines a single date/time window for firewall policies.

Required fields in data:
  - name: Schedule name (string)
  - start: Start datetime in "HH:MM YYYY/MM/DD" format (e.g. "08:00 2025/01/01")
  - end: End datetime in "HH:MM YYYY/MM/DD" format (e.g. "18:00 2025/01/01")

Returns: Creation confirmation.""")
        async def create_schedule_onetime(
            device_id: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.schedule_tools.create_schedule_onetime(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing one-time schedule.

Required params:
  - name: Schedule name to update (string)
  - data: JSON with updated fields, e.g. {"start": "09:00 2025/01/01", "end": "17:00 2025/01/01"}

Returns: Update confirmation.""")
        async def update_schedule_onetime(
            device_id: str,
            name: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.schedule_tools.update_schedule_onetime(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete an onetime schedule")
        async def delete_schedule_onetime(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.schedule_tools.delete_schedule_onetime(device_id, name, vdom)

        @self.mcp.tool(description="List all recurring schedules")
        async def list_schedule_recurring(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.schedule_tools.list_schedule_recurring(device_id, vdom)

        @self.mcp.tool(description="""Create a new recurring schedule.

Defines a time window for firewall policies.

Required fields in data:
  - name: Schedule name (string)
  - start: Start time in "HH:MM" format (string, e.g. "08:00")
  - end: End time in "HH:MM" format (string, e.g. "18:00")
  - day: Days of week, array of strings: ["sunday","monday","tuesday","wednesday","thursday","friday","saturday"]

Returns: Creation confirmation.""")
        async def create_schedule_recurring(
            device_id: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.schedule_tools.create_schedule_recurring(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing recurring schedule.

Required params:
  - name: Schedule name to update (string)
  - data: JSON object with fields to update, e.g.:
    {start: "09:00", end: "17:00", day: ["monday","tuesday","wednesday","thursday","friday"]}

Returns: Update confirmation.""")
        async def update_schedule_recurring(
            device_id: str,
            name: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.schedule_tools.update_schedule_recurring(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete a recurring schedule")
        async def delete_schedule_recurring(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.schedule_tools.delete_schedule_recurring(device_id, name, vdom)

        @self.mcp.tool(description="List all schedule groups")
        async def list_schedule_group(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.schedule_tools.list_schedule_group(device_id, vdom)

        @self.mcp.tool(description="""Create a schedule group combining multiple schedule objects.

Required fields in data:
  - name: Group name (string)
  - member: Array of schedule name strings: ["work-hours", "after-hours"]

Returns: Creation confirmation.""")
        async def create_schedule_group(
            device_id: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.schedule_tools.create_schedule_group(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing schedule group.

Required params:
  - name: Group name to update (string)
  - data: JSON with updated fields, e.g. {"member": ["work-hours", "weekend"]}

Returns: Update confirmation.""")
        async def update_schedule_group(
            device_id: str,
            name: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.schedule_tools.update_schedule_group(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete a schedule group")
        async def delete_schedule_group(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.schedule_tools.delete_schedule_group(device_id, name, vdom)

        # ============================================================
        # Resource tools (IP pools, VIP groups, shapers, SNAT, etc.)
        # ============================================================
        @self.mcp.tool(description="List all IP pools")
        async def list_ippools(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.resource_tools.list_ippools(device_id, vdom)

        @self.mcp.tool(description="""Create an IP pool for source NAT.

Required fields in data:
  - name: Pool name (string)
  - startip: Starting IP address
  - endip: Ending IP address
  - type: "overload", "one-to-one", etc.

Returns: Creation confirmation.""")
        async def create_ippool(
            device_id: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.resource_tools.create_ippool(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing IP pool (source NAT).

Required params:
  - name: Pool name to update (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_ippool(
            device_id: str,
            name: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.resource_tools.update_ippool(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete an IP pool")
        async def delete_ippool(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.resource_tools.delete_ippool(device_id, name, vdom)

        @self.mcp.tool(description="List all VIP groups")
        async def list_vipgrps(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.resource_tools.list_vipgrps(device_id, vdom)

        @self.mcp.tool(description="""Create a virtual IP group combining multiple VIPs.

Required fields in data:
  - name: Group name (string)
  - member: Array of VIP name strings: ["VIP-WEB", "VIP-DB"]
  - interface: Interface name (use "any" for all interfaces)

Returns: Creation confirmation.""")
        async def create_vipgrp(
            device_id: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.resource_tools.create_vipgrp(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing virtual IP group.

Required params:
  - name: Group name to update (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_vipgrp(
            device_id: str,
            name: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.resource_tools.update_vipgrp(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete a VIP group")
        async def delete_vipgrp(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.resource_tools.delete_vipgrp(device_id, name, vdom)

        @self.mcp.tool(description="List all traffic shapers")
        async def list_traffic_shapers(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.resource_tools.list_traffic_shapers(device_id, vdom)

        @self.mcp.tool(description="List all central SNAT maps")
        async def list_central_snat_maps(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.resource_tools.list_central_snat_maps(device_id, vdom)

        # ============================================================
        # Security Policy tools
        # ============================================================
        @self.mcp.tool(description="List all NGFW security policies")
        async def list_security_policies(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.firewall_tools.list_security_policies(device_id, vdom)

        @self.mcp.tool(description="""Create a new NGFW security policy on a FortiGate device.

Parameters:
- device_id: FortiGate device identifier
- policy_data: Policy configuration as JSON object
- vdom: Virtual Domain name (optional)

Policy data must include:
- name: Policy name (required)
- srcintf: Source interface(s) as [{"name": "port2"}] (required, object array)
- dstintf: Destination interface(s) as [{"name": "port1"}] (required, object array)
- srcaddr: Source address object(s) as [{"name": "all"}] (required, object array)
- dstaddr: Destination address object(s) as [{"name": "all"}] (required, object array)
- service: Service object(s) as [{"name": "HTTP"}] (required, object array)
- schedule: "always" (REQUIRED — FortiOS returns 500/-56 if omitted)
- action: accept or deny (required)
- status: enable or disable
- utm-status: enable (REQUIRED before binding any security profiles)

Optional security profiles (require utm-status: enable):
- ips-sensor, av-profile, ssl-ssh-profile, webfilter-profile, dnsfilter-profile

CRITICAL: All multi-value fields MUST use [{"name": "..."}] format. Plain strings are NOT accepted.
schedule is mandatory — omitting it causes 500/-56. utm-status: enable is mandatory when binding
any security profile — without it profiles are silently ignored.""")
        async def create_security_policy(
            device_id: str,
            policy_data: dict,
            vdom: Optional[str] = None
        ):
            return await self.firewall_tools.create_security_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description="List all proxy policies")
        async def list_proxy_policies(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.firewall_tools.list_proxy_policies(device_id, vdom)

        @self.mcp.tool(description="Create a new proxy policy. All multi-value fields (interface, address, service references) MUST use [{'name': '...'}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM and will cause 500 errors. schedule may be required — check FortiOS API docs.")
        async def create_proxy_policy(
            device_id: str,
            policy_data: dict,
            vdom: Optional[str] = None
        ):
            return await self.firewall_tools.create_proxy_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description="List all proxy addresses")
        async def list_proxy_addresses(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.firewall_tools.list_proxy_addresses(device_id, vdom)

        @self.mcp.tool(description="List all DoS policies")
        async def list_dos_policies(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.firewall_tools.list_dos_policies(device_id, vdom)

        @self.mcp.tool(description="List all local-in policies")
        async def list_local_in_policies(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.firewall_tools.list_local_in_policies(device_id, vdom)

        # ============================================================
        # Wildcard FQDN tools
        # ============================================================
        @self.mcp.tool(description="List all wildcard FQDN entries")
        async def list_wildcard_fqdn_custom(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.list_wildcard_fqdn_custom(device_id, vdom)

        @self.mcp.tool(description="""Create a wildcard FQDN address. IMPORTANT: Can ONLY be used in SSL exemption policies — NOT regular firewall policies.

Required fields in data:
  - name: FQDN name (string)
  - wildcard-fqdn: Wildcard pattern (e.g. "*.example.com")

Returns: Creation confirmation.""")

        async def create_wildcard_fqdn_custom(
            device_id: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.create_wildcard_fqdn_custom(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing wildcard FQDN address.

Required params:
  - name: FQDN name (string)
  - data: JSON with updated fields (e.g. {"wildcard-fqdn": "*.newexample.com"})

Returns: Update confirmation.""")

        async def update_wildcard_fqdn_custom(
            device_id: str,
            name: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.update_wildcard_fqdn_custom(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete a wildcard FQDN entry")
        async def delete_wildcard_fqdn_custom(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.delete_wildcard_fqdn_custom(device_id, name, vdom)

        @self.mcp.tool(description="List all wildcard FQDN groups")
        async def list_wildcard_fqdn_group(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.list_wildcard_fqdn_group(device_id, vdom)

        @self.mcp.tool(description="""Create a wildcard FQDN group.

Required fields in data:
  - name: Group name (string)
  - member: Array of wildcard FQDN references in [{"name": "*.example.com"}] format

Returns: Creation confirmation.""")

        async def create_wildcard_fqdn_group(
            device_id: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.create_wildcard_fqdn_group(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing wildcard FQDN group.

Required params:
  - name: Group name (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")

        async def update_wildcard_fqdn_group(
            device_id: str,
            name: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.update_wildcard_fqdn_group(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete a wildcard FQDN group")
        async def delete_wildcard_fqdn_group(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.network_tools.delete_wildcard_fqdn_group(device_id, name, vdom)

        # ============================================================
        # Security profile tools (SSL/SSH, IPS, profile groups, log settings)
        # ============================================================
        @self.mcp.tool(description="List all SSL/SSH inspection profiles")
        async def list_ssl_ssh_profiles(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_ssl_ssh_profiles(device_id, vdom)

        @self.mcp.tool(description="List all IPS sensors")
        async def list_ips_sensors(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_ips_sensors(device_id, vdom)

        @self.mcp.tool(description="List all profile groups")
        async def list_profile_groups(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_profile_groups(device_id, vdom)

        @self.mcp.tool(description="Get firewall global settings")
        async def get_firewall_global(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.get_firewall_global(device_id, vdom)

        @self.mcp.tool(description="""Update global firewall settings.

Common updatable fields in data:
  - block-session-timer: Integer (seconds)
  - tcp-halfclose-timer: Integer (seconds)
  - tcp-halfopen-timer: Integer (seconds)
  - tcp-timewait-timer: Integer (seconds)
  - udp-idle-timer: Integer (seconds)

Returns: Update confirmation.""")
        async def update_firewall_global(
            device_id: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.update_firewall_global(device_id, data, vdom)

        @self.mcp.tool(description="Get log settings")
        async def get_log_setting(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.get_log_setting(device_id, vdom)

        # ============================================================
        # Authentication tools
        # ============================================================
        @self.mcp.tool(description="List all authentication rules")
        async def list_auth_rules(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_auth_rules(device_id, vdom)

        @self.mcp.tool(description="""Create a firewall authentication rule.

Required fields in data:
  - name: Rule name (string)
  - srcintf: Source interface in [{"name": "..."}] format
  - srcaddr: Source address in [{"name": "..."}] format
  - dstaddr: Destination address in [{"name": "..."}] format
  - protocol: Auth protocol ("http", "ftp", "socks")

Returns: Creation confirmation.""")
        async def create_auth_rule(
            device_id: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.create_auth_rule(device_id, data, vdom)

        @self.mcp.tool(description="Delete an authentication rule by name")
        async def delete_auth_rule(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.delete_auth_rule(device_id, name, vdom)

        @self.mcp.tool(description="List all authentication schemes")
        async def list_auth_schemes(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_auth_schemes(device_id, vdom)

        @self.mcp.tool(description="Get authentication settings")
        async def get_auth_setting(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.get_auth_setting(device_id, vdom)

        # ============================================================
        # DNS Filter tools
        # ============================================================
        @self.mcp.tool(description="List all DNS filter profiles")
        async def list_dnsfilter_profiles(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_dnsfilter_profiles(device_id, vdom)

        @self.mcp.tool(description="""Create a DNS filter profile.

Required fields in data:
  - name: Profile name (string)
  - block-botnet: "enable" or "disable"

Optional: block-action, log-all-domain, redirect-portal, etc.

Returns: Creation confirmation.""")

        async def create_dnsfilter_profile(
            device_id: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.create_dnsfilter_profile(device_id, data, vdom)

        @self.mcp.tool(description="Delete a DNS filter profile by name")
        async def delete_dnsfilter_profile(
            device_id: str,
            name: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.delete_dnsfilter_profile(device_id, name, vdom)

        @self.mcp.tool(description="List all DNS domain filters")
        async def list_dnsfilter_domain_filters(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_dnsfilter_domain_filters(device_id, vdom)

        # ============================================================
        # DLP tools
        # ============================================================
        @self.mcp.tool(description="List all DLP sensors")
        async def list_dlp_sensors(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_dlp_sensors(device_id, vdom)

        @self.mcp.tool(description="List all DLP profiles")
        async def list_dlp_profiles(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_dlp_profiles(device_id, vdom)

        @self.mcp.tool(description="Get DLP settings")
        async def get_dlp_settings(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.get_dlp_settings(device_id, vdom)

        # ============================================================
        # Email Filter tools
        # ============================================================
        @self.mcp.tool(description="List all email filter profiles")
        async def list_emailfilter_profiles(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_emailfilter_profiles(device_id, vdom)

        # ============================================================
        # Certificate tools
        # ============================================================
        @self.mcp.tool(description="List all CA certificates")
        async def get_certificate_ca(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.get_certificate_ca(device_id, vdom)

        @self.mcp.tool(description="List all local certificates")
        async def get_certificate_local(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.get_certificate_local(device_id, vdom)

        # ============================================================
        # CASB tools
        # ============================================================
        @self.mcp.tool(description="List all CASB profiles")
        async def list_casb_profiles(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_casb_profiles(device_id, vdom)

        # ============================================================
        # Endpoint Control tools
        # ============================================================
        @self.mcp.tool(description="Get endpoint control settings")
        async def get_endpoint_control_settings(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.get_endpoint_control_settings(device_id, vdom)

        # ============================================================
        # Application Control tools
        # ============================================================
        @self.mcp.tool(description="List all application groups")
        async def list_application_groups(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_application_groups(device_id, vdom)

        @self.mcp.tool(description="List all application control lists")
        async def list_application_lists(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_application_lists(device_id, vdom)

        # ============================================================
        # Antivirus tools
        # ============================================================
        @self.mcp.tool(description="List all antivirus profiles")
        async def list_antivirus_profiles(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_antivirus_profiles(device_id, vdom)

        @self.mcp.tool(description="Get antivirus settings")
        async def get_antivirus_settings(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.get_antivirus_settings(device_id, vdom)

        # ============================================================
        # Alert Email tools
        # ============================================================
        @self.mcp.tool(description="Get alert email settings")
        async def get_alertemail_setting(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.get_alertemail_setting(device_id, vdom)

        # ============================================================
        # SSH Filter tools
        # ============================================================
        @self.mcp.tool(description="List all SSH filter profiles")
        async def list_ssh_filter_profiles(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_ssh_filter_profiles(device_id, vdom)

        # ============================================================
        # SCTP Filter tools
        # ============================================================
        @self.mcp.tool(description="List all SCTP filter profiles")
        async def list_sctp_filter_profiles(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_sctp_filter_profiles(device_id, vdom)

        # ============================================================
        # Switch Controller tools
        # ============================================================
        @self.mcp.tool(description="List all switch ACL groups")
        async def list_switch_acl_groups(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_switch_acl_groups(device_id, vdom)

        @self.mcp.tool(description="List all switch 802.1X policies")
        async def list_switch_8021x_policies(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_switch_8021x_policies(device_id, vdom)

        # ============================================================
        # User tools
        # ============================================================
        @self.mcp.tool(description="List all local users")
        async def list_user_locals(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_user_locals(device_id, vdom)

        @self.mcp.tool(description="List all user groups")
        async def list_user_groups(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_user_groups(device_id, vdom)

        @self.mcp.tool(description="List all LDAP servers")
        async def list_user_ldaps(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_user_ldaps(device_id, vdom)

        @self.mcp.tool(description="List all RADIUS servers")
        async def list_user_radiuses(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_user_radiuses(device_id, vdom)

        @self.mcp.tool(description="Get user authentication settings")
        async def get_user_setting(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.get_user_setting(device_id, vdom)

        # ============================================================
        # WebFilter tools
        # ============================================================
        @self.mcp.tool(description="List all web filter profiles")
        async def list_webfilter_profiles(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_webfilter_profiles(device_id, vdom)

        @self.mcp.tool(description="List all web filter URL filters")
        async def list_webfilter_urlfilters(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_webfilter_urlfilters(device_id, vdom)

        # ============================================================
        # Web Proxy tools
        # ============================================================
        @self.mcp.tool(description="List all web proxy profiles")
        async def list_web_proxy_profiles(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_web_proxy_profiles(device_id, vdom)

        # ============================================================
        # WAF tools
        # ============================================================
        @self.mcp.tool(description="List all WAF profiles")
        async def list_waf_profiles(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_waf_profiles(device_id, vdom)

        # ============================================================
        # VoIP tools
        # ============================================================
        @self.mcp.tool(description="List all VoIP profiles")
        async def list_voip_profiles(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_voip_profiles(device_id, vdom)

        # ============================================================
        # VPN - IPSec tools
        # ============================================================
        @self.mcp.tool(description="List all IPSec phase1 interfaces")
        async def list_vpn_ipsec_phase1_interfaces(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_vpn_ipsec_phase1_interfaces(device_id, vdom)

        @self.mcp.tool(description="List all IPSec phase2 interfaces")
        async def list_vpn_ipsec_phase2_interfaces(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_vpn_ipsec_phase2_interfaces(device_id, vdom)

        # ============================================================
        # VPN - SSL VPN tools
        # ============================================================
        @self.mcp.tool(description="Get SSL VPN settings")
        async def get_vpn_ssl_settings(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.get_vpn_ssl_settings(device_id, vdom)

        @self.mcp.tool(description="List all SSL VPN web portals")
        async def list_vpn_ssl_web_portals(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_vpn_ssl_web_portals(device_id, vdom)

        # ============================================================
        # System - DHCP tools
        # ============================================================
        @self.mcp.tool(description="List all DHCP servers")
        async def list_system_dhcp_servers(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_system_dhcp_servers(device_id, vdom)

        # ============================================================
        # System - SNMP tools
        # ============================================================
        @self.mcp.tool(description="List all SNMP communities")
        async def list_system_snmp_communities(
            device_id: str,
            vdom: Optional[str] = None
        ):
            return await self.security_tools.list_system_snmp_communities(device_id, vdom)


        # ============================================================
        # Firewall tools (auto-registered - 43 methods)
        # ============================================================

        @self.mcp.tool(description='Update an existing security policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_security_policy(
            device_id: str,
            policy_id: str,
            policy_data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.update_security_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Delete Security Policy")
        async def delete_security_policy(
            device_id: str,
            policy_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.delete_security_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="Get Security Policy Detail")
        async def get_security_policy_detail(
            device_id: str,
            policy_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.get_security_policy_detail(device_id, policy_id, vdom)

        @self.mcp.tool(description='Update an existing proxy policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_proxy_policy(
            device_id: str,
            policy_id: str,
            policy_data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.update_proxy_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Delete Proxy Policy")
        async def delete_proxy_policy(
            device_id: str,
            policy_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.delete_proxy_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="Get Proxy Policy Detail")
        async def get_proxy_policy_detail(
            device_id: str,
            policy_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.get_proxy_policy_detail(device_id, policy_id, vdom)

        @self.mcp.tool(description="""Create a proxy address object (used in proxy policies).

Required fields in data:
  - name: Address name (string)
  - type: "host_regex", "url_regex", "method", "header", etc.
  - host: Host pattern (for host_regex/url_regex types)

Returns: Creation confirmation.""")
        async def create_proxy_address(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.create_proxy_address(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing proxy address.

Required params:
  - name: Address name to update (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_proxy_address(
            device_id: str,
            name: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.update_proxy_address(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Proxy Address")
        async def delete_proxy_address(
            device_id: str,
            name: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.delete_proxy_address(device_id, name, vdom)

        @self.mcp.tool(description="List Proxy Addrgrps")
        async def list_proxy_addrgrps(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.list_proxy_addrgrps(device_id, vdom)

        @self.mcp.tool(description="""Create a proxy address group.

Required fields in data:
  - name: Group name (string)
  - member: Array of proxy address references in [{"name": "..."}] format

Returns: Creation confirmation.""")
        async def create_proxy_addrgrp(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.create_proxy_addrgrp(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing proxy address group.

Required params:
  - name: Group name to update (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_proxy_addrgrp(
            device_id: str,
            name: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.update_proxy_addrgrp(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Proxy Addrgrp")
        async def delete_proxy_addrgrp(
            device_id: str,
            name: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.delete_proxy_addrgrp(device_id, name, vdom)

        @self.mcp.tool(description="List Shaping Policies")
        async def list_shaping_policies(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.list_shaping_policies(device_id, vdom)

        @self.mcp.tool(description="Create a new shaping policy. All multi-value fields (interface, address, service references) MUST use [{'name': '...'}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM and will cause 500 errors.")
        async def create_shaping_policy(
            device_id: str,
            policy_data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.create_shaping_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description='Update an existing shaping policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_shaping_policy(
            device_id: str,
            policy_id: str,
            policy_data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.update_shaping_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Delete Shaping Policy")
        async def delete_shaping_policy(
            device_id: str,
            policy_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.delete_shaping_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="List Shaping Profiles")
        async def list_shaping_profiles(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.list_shaping_profiles(device_id, vdom)

        @self.mcp.tool(description="""Create a shaping profile.

Required fields in data:
  - name: Profile name (string)
  - default-class-id: Default traffic class ID (integer)

Returns: Creation confirmation.""")
        async def create_shaping_profile(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.create_shaping_profile(device_id, data, vdom)

        @self.mcp.tool(description="""Update a shaping profile.

Required params:
  - name: Profile name to update (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_shaping_profile(
            device_id: str,
            name: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.update_shaping_profile(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Shaping Profile")
        async def delete_shaping_profile(
            device_id: str,
            name: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.delete_shaping_profile(device_id, name, vdom)

        @self.mcp.tool(description="Create a new DoS policy. All multi-value fields (interface, address, service references) MUST use [{'name': '...'}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM and will cause 500 errors.")
        async def create_dos_policy(
            device_id: str,
            policy_data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.create_dos_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description='Update an existing DoS policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_dos_policy(
            device_id: str,
            policy_id: str,
            policy_data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.update_dos_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Delete Dos Policy")
        async def delete_dos_policy(
            device_id: str,
            policy_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.delete_dos_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="Create a new local-in policy. All multi-value fields (interface, address, service references) MUST use [{'name': '...'}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM and will cause 500 errors.")
        async def create_local_in_policy(
            device_id: str,
            policy_data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.create_local_in_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description='Update an existing local-in policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_local_in_policy(
            device_id: str,
            policy_id: str,
            policy_data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.update_local_in_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Delete Local In Policy")
        async def delete_local_in_policy(
            device_id: str,
            policy_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.delete_local_in_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="List Interface Policies")
        async def list_interface_policies(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.list_interface_policies(device_id, vdom)

        @self.mcp.tool(description="Create a new interface policy. All multi-value fields (interface, address, service references) MUST use [{'name': '...'}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM and will cause 500 errors.")
        async def create_interface_policy(
            device_id: str,
            policy_data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.create_interface_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description='Update an existing interface policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_interface_policy(
            device_id: str,
            policy_id: str,
            policy_data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.update_interface_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Delete Interface Policy")
        async def delete_interface_policy(
            device_id: str,
            policy_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.delete_interface_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="List Multicast Policies")
        async def list_multicast_policies(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.list_multicast_policies(device_id, vdom)

        @self.mcp.tool(description="Create a new multicast policy. All multi-value fields (interface, address, service references) MUST use [{'name': '...'}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM and will cause 500 errors.")
        async def create_multicast_policy(
            device_id: str,
            policy_data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.create_multicast_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description='Update an existing multicast policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_multicast_policy(
            device_id: str,
            policy_id: str,
            policy_data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.update_multicast_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Delete Multicast Policy")
        async def delete_multicast_policy(
            device_id: str,
            policy_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.delete_multicast_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="List Multicast Addresses")
        async def list_multicast_addresses(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.list_multicast_addresses(device_id, vdom)

        @self.mcp.tool(description="""Create a multicast address object.

Required fields in data:
  - name: Address name (string)
  - type: "multicastrange" (required)
  - start-ip: Starting multicast IP (e.g. "224.0.0.1")
  - end-ip: Ending multicast IP (e.g. "224.0.0.255")

Returns: Creation confirmation.""")
        async def create_multicast_address(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.create_multicast_address(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing multicast address.

Required params:
  - name: Address name to update (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_multicast_address(
            device_id: str,
            name: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.update_multicast_address(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Multicast Address")
        async def delete_multicast_address(
            device_id: str,
            name: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.delete_multicast_address(device_id, name, vdom)

        @self.mcp.tool(description="List Sniffers")
        async def list_sniffers(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.list_sniffers(device_id, vdom)

        @self.mcp.tool(description="""Create a packet sniffer configuration.

Required fields in data:
  - id: Sniffer ID (integer)
  - interface: Interface to sniff on
  - host: Host filter (e.g. "192.168.1.0/24")
  - max-packet-count: Integer

Returns: Creation confirmation.""")
        async def create_sniffer(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.create_sniffer(device_id, data, vdom)

        @self.mcp.tool(description="""Update a packet sniffer configuration.

Required params:
  - name: Sniffer name (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_sniffer(
            device_id: str,
            sniffer_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.update_sniffer(device_id, sniffer_id, data, vdom)

        @self.mcp.tool(description="Delete Sniffer")
        async def delete_sniffer(
            device_id: str,
            sniffer_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.firewall_tools.delete_sniffer(device_id, sniffer_id, vdom)

        # ============================================================
        # Resource tools (auto-registered - 31 methods)
        # ============================================================

        @self.mcp.tool(description="""Create a traffic shaper.

Required fields in data:
  - name: Shaper name (string)
  - max-bandwidth: Max bandwidth in Kbps (integer)
  - guaranteed-bandwidth: Guaranteed bandwidth in Kbps (integer)

Returns: Creation confirmation.""")
        async def create_traffic_shaper(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.create_traffic_shaper(device_id, data, vdom)

        @self.mcp.tool(description="""Update a traffic shaper.

Required params:
  - name: Shaper name to update (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_traffic_shaper(
            device_id: str,
            name: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.update_traffic_shaper(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Traffic Shaper")
        async def delete_traffic_shaper(
            device_id: str,
            name: str,
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.delete_traffic_shaper(device_id, name, vdom)

        @self.mcp.tool(description="List Per Ip Shapers")
        async def list_per_ip_shapers(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.list_per_ip_shapers(device_id, vdom)

        @self.mcp.tool(description="""Create a per-IP shaper.

Required fields in data:
  - name: Shaper name (string)
  - max-bandwidth: Max bandwidth per IP (Kbps)
  - max-concurrent-session: Max sessions per IP

Returns: Creation confirmation.""")
        async def create_per_ip_shaper(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.create_per_ip_shaper(device_id, data, vdom)

        @self.mcp.tool(description="""Update a per-IP shaper.

Required params:
  - name: Shaper name to update (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_per_ip_shaper(
            device_id: str,
            name: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.update_per_ip_shaper(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Per Ip Shaper")
        async def delete_per_ip_shaper(
            device_id: str,
            name: str,
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.delete_per_ip_shaper(device_id, name, vdom)

        @self.mcp.tool(description="""Create a central SNAT map entry.

Required fields in data:
  - policyid: Policy ID (integer)
  - orig-addr: Source address in [{"name": "..."}] format
  - srcintf: Source interface in [{"name": "..."}] format
  - ippool: IP pool references in [{"name": "..."}] format

Returns: Creation confirmation.""")
        async def create_central_snat_map(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.create_central_snat_map(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing central SNAT map.

Required params:
  - name: Map name (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_central_snat_map(
            device_id: str,
            policy_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.update_central_snat_map(device_id, policy_id, data, vdom)

        @self.mcp.tool(description="Delete Central Snat Map")
        async def delete_central_snat_map(
            device_id: str,
            policy_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.delete_central_snat_map(device_id, policy_id, vdom)

        @self.mcp.tool(description="Get Central Snat Map Detail")
        async def get_central_snat_map_detail(
            device_id: str,
            policy_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.get_central_snat_map_detail(device_id, policy_id, vdom)

        @self.mcp.tool(description="List Ip Translations")
        async def list_ip_translations(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.list_ip_translations(device_id, vdom)

        @self.mcp.tool(description="""Create an IP translation rule for bidirectional NAT.

Required fields in data:
  - src: Original IP
  - dst: Translated IP

Returns: Creation confirmation.""")
        async def create_ip_translation(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.create_ip_translation(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing IP translation rule.

Required params:
  - name: Rule name (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_ip_translation(
            device_id: str,
            trans_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.update_ip_translation(device_id, trans_id, data, vdom)

        @self.mcp.tool(description="Delete Ip Translation")
        async def delete_ip_translation(
            device_id: str,
            trans_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.delete_ip_translation(device_id, trans_id, vdom)

        @self.mcp.tool(description="List Identity Based Routes")
        async def list_identity_based_routes(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.list_identity_based_routes(device_id, vdom)

        @self.mcp.tool(description="""Create an identity-based routing rule.

Required fields in data:
  - id: Rule ID (integer)
  - device: Outgoing interface name
  - gateway: Gateway IP address
  - groups: User group references in [{"name": "..."}] format

Returns: Creation confirmation.""")
        async def create_identity_based_route(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.create_identity_based_route(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing identity-based routing rule.

Required params:
  - name: Rule name (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_identity_based_route(
            device_id: str,
            name: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.update_identity_based_route(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Identity Based Route")
        async def delete_identity_based_route(
            device_id: str,
            name: str,
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.delete_identity_based_route(device_id, name, vdom)

        @self.mcp.tool(description="List Dns Translations")
        async def list_dns_translations(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.list_dns_translations(device_id, vdom)

        @self.mcp.tool(description="""Create a DNS translation rule for NAT DNS doctoring.

Required fields in data:
  - src: Original DNS name or IP
  - dst: Translated IP address

Returns: Creation confirmation.""")
        async def create_dns_translation(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.create_dns_translation(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing DNS translation rule.

Required params:
  - name: Rule name to update (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_dns_translation(
            device_id: str,
            trans_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.update_dns_translation(device_id, trans_id, data, vdom)

        @self.mcp.tool(description="Delete Dns Translation")
        async def delete_dns_translation(
            device_id: str,
            trans_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.delete_dns_translation(device_id, trans_id, vdom)

        @self.mcp.tool(description="List Ttl Policies")
        async def list_ttl_policies(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.list_ttl_policies(device_id, vdom)

        @self.mcp.tool(description="Create a new TTL policy. All multi-value fields (interface, address, service references) MUST use [{'name': '...'}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM and will cause 500 errors.")
        async def create_ttl_policy(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.create_ttl_policy(device_id, data, vdom)

        @self.mcp.tool(description='Update an existing TTL policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_ttl_policy(
            device_id: str,
            policy_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.update_ttl_policy(device_id, policy_id, data, vdom)

        @self.mcp.tool(description="Delete Ttl Policy")
        async def delete_ttl_policy(
            device_id: str,
            policy_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.delete_ttl_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="List Decrypted Traffic Mirrors")
        async def list_decrypted_traffic_mirrors(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.list_decrypted_traffic_mirrors(device_id, vdom)

        @self.mcp.tool(description="""Create a decrypted traffic mirror rule for SSL inspection traffic capture.

Required fields in data:
  - name: Rule name (string)
  - dstmac: Destination MAC for mirrored traffic
  - interface: Output interface for mirrored traffic

Returns: Creation confirmation.""")
        async def create_decrypted_traffic_mirror(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.create_decrypted_traffic_mirror(device_id, data, vdom)

        @self.mcp.tool(description="""Update a decrypted traffic mirror rule.

Required params:
  - name: Rule name (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_decrypted_traffic_mirror(
            device_id: str,
            name: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.update_decrypted_traffic_mirror(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Decrypted Traffic Mirror")
        async def delete_decrypted_traffic_mirror(
            device_id: str,
            name: str,
            vdom: Optional[str] = None,
        ):
            return await self.resource_tools.delete_decrypted_traffic_mirror(device_id, name, vdom)

        # ============================================================
        # Security tools (auto-registered - 25 methods)
        # ============================================================

        @self.mcp.tool(description="""Create an SSL/SSH inspection profile.

Required fields in data:
  - name: Profile name (string)
  - ssl-anomaly-log: "enable" or "disable"
  - server-cert-mode: "replace" (deep inspection) or "protect" (certificate-only)

Returns: Creation confirmation.""")
        async def create_ssl_ssh_profile(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.create_ssl_ssh_profile(device_id, data, vdom)

        @self.mcp.tool(description="""Update an SSL/SSH inspection profile.

Required params:
  - name: Profile name (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_ssl_ssh_profile(
            device_id: str,
            name: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.update_ssl_ssh_profile(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Ssl Ssh Profile")
        async def delete_ssl_ssh_profile(
            device_id: str,
            name: str,
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.delete_ssl_ssh_profile(device_id, name, vdom)

        @self.mcp.tool(description="List Ssl Servers")
        async def list_ssl_servers(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.list_ssl_servers(device_id, vdom)

        @self.mcp.tool(description="""Create an SSL server definition for SSL inspection.

Required fields in data:
  - name: Server name (string)
  - ip: Server IP address

Returns: Creation confirmation.""")
        async def create_ssl_server(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.create_ssl_server(device_id, data, vdom)

        @self.mcp.tool(description="""Update an SSL server definition.

Required params:
  - name: Server name (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_ssl_server(
            device_id: str,
            name: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.update_ssl_server(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Ssl Server")
        async def delete_ssl_server(
            device_id: str,
            name: str,
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.delete_ssl_server(device_id, name, vdom)

        @self.mcp.tool(description="""Create a security profile group to bundle multiple profiles for firewall policy binding.

Required fields in data:
  - name: Group name (string)

Optional: av-profile, ips-sensor, webfilter-profile, application-list, ssl-ssh-profile, dnsfilter-profile (each a string profile name)

Returns: Creation confirmation.""")
        async def create_profile_group(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.create_profile_group(device_id, data, vdom)

        @self.mcp.tool(description="""Update a security profile group.

Required params:
  - name: Group name (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_profile_group(
            device_id: str,
            name: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.update_profile_group(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Profile Group")
        async def delete_profile_group(
            device_id: str,
            name: str,
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.delete_profile_group(device_id, name, vdom)

        @self.mcp.tool(description="List Profile Protocol Options")
        async def list_profile_protocol_options(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.list_profile_protocol_options(device_id, vdom)

        @self.mcp.tool(description="""Create a protocol options profile for protocol-level inspection settings.

Required fields in data:
  - name: Profile name (string)

Optional protocol blocks: http, ftp, imap, pop3, smtp, nntp, dns, cifs — each with ports, status, comfort-interval, etc.

Returns: Creation confirmation.""")
        async def create_profile_protocol_options(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.create_profile_protocol_options(device_id, data, vdom)

        @self.mcp.tool(description="""Update a protocol options profile.

Required params:
  - name: Profile name (string)
  - data: JSON with updated fields

Returns: Update confirmation.""")
        async def update_profile_protocol_options(
            device_id: str,
            name: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.update_profile_protocol_options(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Profile Protocol Options")
        async def delete_profile_protocol_options(
            device_id: str,
            name: str,
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.delete_profile_protocol_options(device_id, name, vdom)

        @self.mcp.tool(description="""Create a new IPS sensor.

IPS sensors define intrusion prevention rules for firewall policies. Must be bound to a security policy via ips-sensor field (utm-status: enable required on the policy first).

Required fields in data:
  - name: Sensor name (string)
  - entries: Array of filter entries:
    [{rule: 12345, status: "enable", action: "block", location: "server"}]

Common rule IDs: FortiGuard IPS signatures use numeric rule IDs. Use list_ips_signatures() to find available rule IDs.

Returns: Creation confirmation with sensor details.""")
        async def create_ips_sensor(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.create_ips_sensor(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing IPS sensor.

Required params:
  - name: Sensor name to update (string)
  - data: JSON object with updated fields, e.g.:
    {entries: [{rule: 12345, status: "enable", action: "block", location: "all"}]}

Returns: Update confirmation.""")
        async def update_ips_sensor(
            device_id: str,
            name: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.update_ips_sensor(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Ips Sensor")
        async def delete_ips_sensor(
            device_id: str,
            name: str,
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.delete_ips_sensor(device_id, name, vdom)

        @self.mcp.tool(description="Get Ips Sensor Detail")
        async def get_ips_sensor_detail(
            device_id: str,
            name: str,
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.get_ips_sensor_detail(device_id, name, vdom)

        @self.mcp.tool(description="""Update general log settings.

Common fields in data:
  - resolve-ip: "enable" or "disable"
  - faz-status: "enable" or "disable"
  - syslog-status: "enable" or "disable"
  - local-in-allow: "enable" or "disable"

Returns: Update confirmation.""")
        async def update_log_setting(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.update_log_setting(device_id, data, vdom)

        @self.mcp.tool(description="Get Log Disk Setting")
        async def get_log_disk_setting(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.get_log_disk_setting(device_id, vdom)

        @self.mcp.tool(description="""Update disk log settings.

Common fields in data:
  - status: "enable" or "disable"
  - max-log-file-size: Integer (MB)
  - max-policy-packet-capture-size: Integer (bytes)
  - log-quota: Integer (MB)
  - roll-schedule: "daily" or "weekly"

Returns: Update confirmation.""")
        async def update_log_disk_setting(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.update_log_disk_setting(device_id, data, vdom)

        @self.mcp.tool(description="Get Log Fortianalyzer Setting")
        async def get_log_fortianalyzer_setting(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.get_log_fortianalyzer_setting(device_id, vdom)

        @self.mcp.tool(description="""Update FortiAnalyzer log settings.

Common fields in data:
  - status: "enable" or "disable"
  - server: FortiAnalyzer IP address
  - upload-option: "real-time", "1-minute", or "5-minute"
  - reliable: "enable" or "disable"

Returns: Update confirmation.""")
        async def update_log_fortianalyzer_setting(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.update_log_fortianalyzer_setting(device_id, data, vdom)

        @self.mcp.tool(description="Get Log Syslogd Setting")
        async def get_log_syslogd_setting(
            device_id: str,
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.get_log_syslogd_setting(device_id, vdom)

        @self.mcp.tool(description="""Update syslog server settings.

Common fields in data:
  - status: "enable" or "disable"
  - server: Syslog server IP
  - port: Integer (default 514)
  - facility: "local0" through "local7"
  - format: "default", "csv", or "cef"

Returns: Update confirmation.""")
        async def update_log_syslogd_setting(
            device_id: str,
            data: Dict[str, Any],
            vdom: Optional[str] = None,
        ):
            return await self.security_tools.update_log_syslogd_setting(device_id, data, vdom)

        # ============================================================
        # Generic CMDB tools (covers ALL 1023+ FortiOS 8.0 endpoints)
        # ============================================================
        @self.mcp.tool(description="""List resources at any CMDB path (covers ALL FortiOS 8.0 endpoints).

IMPORTANT — Path format:
  - Top-level tables: use "/" (e.g. "firewall/address", "firewall/policy")
  - SUB-TABLES must use "." NOT "/" (e.g. "firewall.service/custom" for custom services,
    "firewall.addrgrp" for address groups, "router/static" for static routes)
  - FortiOS API uses "." to separate sub-table names; using "/" for sub-tables
    returns empty results.

Examples:
  cmdb_list("FG-E", "firewall/address")           → address objects
  cmdb_list("FG-E", "firewall.service/custom")    → custom services (sub-table via ".")
  cmdb_list("FG-E", "firewall.addrgrp")           → address groups (sub-table via ".")
  cmdb_list("FG-E", "router/static")              → static routes (sub-table via ".")""")
        async def cmdb_list(
            device_id: str,
            path: str,
            vdom: Optional[str] = None
        ):
            return await self.cmdb_tools.cmdb_list(device_id, path, vdom)

        @self.mcp.tool(description="Get a single resource by name, or a singleton object (omit name for singleton like system/global)")
        async def cmdb_get(
            device_id: str,
            path: str,
            name: Optional[str] = None,
            vdom: Optional[str] = None
        ):
            return await self.cmdb_tools.cmdb_get(device_id, path, name, vdom)

        @self.mcp.tool(description="Create a new resource at any CMDB path")
        async def cmdb_create(
            device_id: str,
            path: str,
            data: dict,
            vdom: Optional[str] = None
        ):
            return await self.cmdb_tools.cmdb_create(device_id, path, data, vdom)

        @self.mcp.tool(description="Update a resource or singleton (omit name for singleton like system/global)")
        async def cmdb_update(
            device_id: str,
            path: str,
            data: dict,
            name: Optional[str] = None,
            vdom: Optional[str] = None
        ):
            return await self.cmdb_tools.cmdb_update(device_id, path, data, name, vdom)

        @self.mcp.tool(description="Delete a resource by name from any CMDB path")
        async def cmdb_delete(
            device_id: str,
            path: str,
            name: Optional[str] = None,
            vdom: Optional[str] = None
        ):
            return await self.cmdb_tools.cmdb_delete(device_id, path, name, vdom)

        # ============================================================
        # Monitor tools (47 tools — 46 specific + 1 generic monitor_request)
        # ============================================================
        @self.mcp.tool(description="Get IPSec VPN monitor status")
        async def monitor_vpn_ipsec(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_vpn_ipsec(device_id, vdom)

        @self.mcp.tool(description="Get IPSec VPN connection count")
        async def monitor_vpn_ipsec_connection_count(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_vpn_ipsec_connection_count(device_id, vdom)

        @self.mcp.tool(description="Get SSL VPN status")
        async def monitor_vpn_ssl(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_vpn_ssl(device_id, vdom)

        @self.mcp.tool(description="Get SSL VPN statistics")
        async def monitor_vpn_ssl_stats(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_vpn_ssl_stats(device_id, vdom)

        @self.mcp.tool(description="Get firewall authenticated users")
        async def monitor_user_firewall(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_user_firewall(device_id, vdom)

        @self.mcp.tool(description="Get firewall user count")
        async def monitor_user_firewall_count(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_user_firewall_count(device_id, vdom)

        @self.mcp.tool(description="Get banned users")
        async def monitor_user_banned(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_user_banned(device_id, vdom)

        @self.mcp.tool(description="Get FSSO users")
        async def monitor_user_fsso(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_user_fsso(device_id, vdom)

        @self.mcp.tool(description="Get SD-WAN health checks")
        async def monitor_virtual_wan_health_check(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_virtual_wan_health_check(device_id, vdom)

        @self.mcp.tool(description="Get SD-WAN members")
        async def monitor_virtual_wan_members(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_virtual_wan_members(device_id, vdom)

        @self.mcp.tool(description="Get SD-WAN SLA log")
        async def monitor_virtual_wan_sla_log(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_virtual_wan_sla_log(device_id, vdom)

        @self.mcp.tool(description="Get UTM application lookup by name")
        async def monitor_utm_app_lookup(device_id: str, app_name: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_utm_app_lookup(device_id, app_name, vdom)

        @self.mcp.tool(description="Get UTM application categories")
        async def monitor_utm_application_categories(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_utm_application_categories(device_id, vdom)

        @self.mcp.tool(description="Get UTM applications list")
        async def monitor_utm_applications(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_utm_applications(device_id, vdom)

        @self.mcp.tool(description="Get IPv4 routing table")
        async def monitor_router_ipv4(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_router_ipv4(device_id, vdom)

        @self.mcp.tool(description="Get IPv6 routing table")
        async def monitor_router_ipv6(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_router_ipv6(device_id, vdom)

        @self.mcp.tool(description="Get firewall ACL")
        async def monitor_firewall_acl(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_firewall_acl(device_id, vdom)

        @self.mcp.tool(description="Get firewall ACL6")
        async def monitor_firewall_acl6(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_firewall_acl6(device_id, vdom)

        @self.mcp.tool(description="Get license status")
        async def monitor_license_status(device_id: str):
            return await self.resource_tools.monitor_license_status(device_id)

        @self.mcp.tool(description="Get log disk usage")
        async def monitor_log_current_disk_usage(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_log_current_disk_usage(device_id, vdom)

        @self.mcp.tool(description="Get FortiAnalyzer log status")
        async def monitor_log_fortianalyzer(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_log_fortianalyzer(device_id, vdom)

        @self.mcp.tool(description="Get FortiCloud log status")
        async def monitor_log_forticloud(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_log_forticloud(device_id, vdom)

        @self.mcp.tool(description="Get IPS rate-based signatures")
        async def monitor_ips_rate_based(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_ips_rate_based(device_id, vdom)

        @self.mcp.tool(description="Get IPS session performance")
        async def monitor_ips_session_performance(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_ips_session_performance(device_id, vdom)

        @self.mcp.tool(description="Get FortiGuard service communication stats")
        async def monitor_fortiguard_service_stats(device_id: str):
            return await self.resource_tools.monitor_fortiguard_service_stats(device_id)

        @self.mcp.tool(description="Get GeoIP lookup for an IP address. The result shows country, region, city, latitude, longitude, and ISP. Param: ip (string) — the IP address to look up.")
        async def monitor_geoip_query(device_id: str, ip: str):
            return await self.resource_tools.monitor_geoip_query(device_id, ip)

        @self.mcp.tool(description="Get FortiView real-time statistics")
        async def monitor_fortiview_realtime_stats(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_fortiview_realtime_stats(device_id, vdom)

        @self.mcp.tool(description="Get ARP table")
        async def monitor_network_arp(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_network_arp(device_id, vdom)

        @self.mcp.tool(description="Get LLDP neighbors")
        async def monitor_network_lldp_neighbors(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_network_lldp_neighbors(device_id, vdom)

        @self.mcp.tool(description="Get DNS latency")
        async def monitor_network_dns_latency(device_id: str):
            return await self.resource_tools.monitor_network_dns_latency(device_id)

        @self.mcp.tool(description="Get reverse IP lookup (PTR record)")
        async def monitor_network_reverse_ip_lookup(device_id: str, ip: str):
            return await self.resource_tools.monitor_network_reverse_ip_lookup(device_id, ip)

        @self.mcp.tool(description="Get BGP neighbors")
        async def monitor_router_bgp_neighbors(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_router_bgp_neighbors(device_id, vdom)

        @self.mcp.tool(description="Get BGP paths")
        async def monitor_router_bgp_paths(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_router_bgp_paths(device_id, vdom)

        @self.mcp.tool(description="Get available interfaces (with names and status). Note: for VIPs use 'any' to match all interfaces.")
        async def monitor_system_available_interfaces(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_system_available_interfaces(device_id, vdom)

        @self.mcp.tool(description="Get FortiCloud registration status")
        async def monitor_registration_forticloud_status(device_id: str):
            return await self.resource_tools.monitor_registration_forticloud_status(device_id)

        @self.mcp.tool(description="Get web filter FortiGuard categories")
        async def monitor_webfilter_fortiguard_categories(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_webfilter_fortiguard_categories(device_id, vdom)

        @self.mcp.tool(description="Get system status (hostname, serial number, firmware version, HA status)")
        async def monitor_system_status(device_id: str):
            return await self.resource_tools.monitor_system_status(device_id)

        @self.mcp.tool(description="Get CPU, memory, and session resource usage. scope='current' (default) returns latest snapshot only; scope='full' returns all history (~232KB).")
        async def monitor_system_resource_usage(device_id: str, vdom: Optional[str] = None, scope: str = "current"):
            return await self.resource_tools.monitor_system_resource_usage(device_id, vdom, scope=scope)

        @self.mcp.tool(description="Get system performance status (CPU/memory per interval)")
        async def monitor_system_performance_status(device_id: str):
            return await self.resource_tools.monitor_system_performance_status(device_id)

        @self.mcp.tool(description="Get interface bandwidth, speed, and utilization")
        async def monitor_system_interface(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_system_interface(device_id, vdom)

        @self.mcp.tool(description="Get currently logged-in administrators")
        async def monitor_system_current_admins(device_id: str):
            return await self.resource_tools.monitor_system_current_admins(device_id)

        @self.mcp.tool(description="Get firmware version and available upgrades")
        async def monitor_system_firmware(device_id: str):
            return await self.resource_tools.monitor_system_firmware(device_id)

        @self.mcp.tool(description="Get VM hypervisor and platform information")
        async def monitor_system_vm_information(device_id: str):
            return await self.resource_tools.monitor_system_vm_information(device_id)

        @self.mcp.tool(description="Get firewall policy statistics and hit counts")
        async def monitor_firewall_policy(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_firewall_policy(device_id, vdom)

        @self.mcp.tool(description="Get active session table")
        async def monitor_firewall_sessions(device_id: str, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_firewall_sessions(device_id, vdom)

        @self.mcp.tool(description="Policy lookup by 5-tuple (srcip, dstip, srcport, dstport, protocol)")
        async def monitor_firewall_policy_lookup(device_id: str, params: dict, vdom: Optional[str] = None):
            return await self.resource_tools.monitor_firewall_policy_lookup(device_id, params, vdom)

        @self.mcp.tool(description="Generic monitor API — access ANY /api/v2/monitor/ GET or POST endpoint "
                       "(e.g. 'system/status', 'system/os/reboot'). Use method='POST' + data for POST endpoints.")
        async def monitor_request(device_id: str, endpoint: str,
                                   params: Optional[dict] = None, vdom: Optional[str] = None,
                                   method: str = "GET", data: Optional[dict] = None):
            return await self.resource_tools.monitor_request(device_id, endpoint, params, vdom, method, data)

        # System tools
        @self.mcp.tool(description="Health check for FortiGate MCP server")
        async def health_check():
            try:
                device_list = self.fortigate_manager.list_devices()
                
                async def check_device(device_info):
                    device_id = device_info["device_id"]
                    try:
                        api_client = self.fortigate_manager.get_device(device_id)
                        success = await asyncio.wait_for(
                            api_client.test_connection(), timeout=5.0
                        )
                        return device_id, "connected" if success else "disconnected"
                    except asyncio.TimeoutError:
                        return device_id, "timeout"
                    except Exception:
                        return device_id, "error"
                
                # F5: concurrent health checks with 5s timeout per device
                results = await asyncio.gather(
                    *[check_device(d) for d in device_list],
                    return_exceptions=True
                )
                connection_results = {}
                for r in results:
                    if isinstance(r, tuple):
                        connection_results[r[0]] = r[1]
                    else:
                        connection_results["unknown"] = f"error: {r}"
                return self._format_response({
                    "status": "ok",
                    "server": "FortiGateMCP-HTTP",
                    "timestamp": datetime.now().isoformat(),
                    "registered_devices": len(device_list),
                    "device_connections": connection_results
                }, "health")
            except Exception as e:
                return self._format_response({"status": "error", "error": str(e)}, "health")

        @self.mcp.tool(description="Get FortiGate MCP server information")
        async def get_server_info():
            # Count actual registered tools dynamically
            tool_count = len(self.mcp._tool_manager._tools) if hasattr(self.mcp, '_tool_manager') else 0
            info = {
                "name": self.config.server.name,
                "version": self.config.server.version,
                "host": self.config.server.host,
                "port": self.config.server.port,
                "registered_devices": len(self.fortigate_manager.devices),
                "available_tools": f"{tool_count} tools",
                "device_ids": list(self.fortigate_manager.devices.keys()),
            }
            return self._format_response(info, "server_info")


    def _format_response(self, data, operation: str = "operation"):
        """Format response data for MCP."""
        from mcp.types import TextContent as Content
        
        try:
            if isinstance(data, (dict, list)):
                formatted_data = json.dumps(data, indent=2, ensure_ascii=False)
            else:
                formatted_data = str(data)
            
            return [Content(type="text", text=formatted_data)]
            
        except Exception as e:
            self.logger.error(f"Error formatting response for {operation}: {e}")
            error_response = {
                "error": f"Failed to format response: {str(e)}",
                "operation": operation
            }
            return [Content(type="text", text=json.dumps(error_response, indent=2))]

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
        import asyncio
        from starlette.applications import Starlette

        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown HTTP server...")
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
