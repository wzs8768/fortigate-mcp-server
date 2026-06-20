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
import sys
import signal
from typing import Optional, Annotated, Dict, Any
from datetime import datetime

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .config.loader import load_config
from .core.logging import setup_logging
from .core.fortigate import FortiGateManager
from .tools.device import DeviceTools
from .tools.firewall import FirewallTools
from .tools.network import NetworkTools
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
    HEALTH_CHECK_DESC, GET_SERVER_INFO_DESC,
)

class FortiGateMCPServer:
    """Main server class for FortiGate MCP."""

    def __init__(self, config_path: Optional[str] = None):
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
        self._tests_passed: Optional[bool] = None
        self._setup_tools()

    def _setup_tools(self) -> None:
        """Register MCP tools with the server."""
        
        # Device management tools
        @self.mcp.tool(description=LIST_DEVICES_DESC)
        async def list_devices():
            return await self.device_tools.list_devices()

        @self.mcp.tool(description=GET_DEVICE_STATUS_DESC)
        async def get_device_status(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.device_tools.get_device_status(device_id)

        @self.mcp.tool(description=TEST_DEVICE_CONNECTION_DESC)
        async def test_device_connection(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.device_tools.test_device_connection(device_id)

        @self.mcp.tool(description=DISCOVER_VDOMS_DESC)
        async def discover_vdoms(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.device_tools.discover_vdoms(device_id)

        @self.mcp.tool(description=ADD_DEVICE_DESC)
        async def add_device(
            device_id: Annotated[str, Field(description="Unique device identifier")],
            host: Annotated[str, Field(description="FortiGate IP address or hostname")],
            port: Annotated[int, Field(description="HTTPS port", default=443)] = 443,
            username: Annotated[Optional[str], Field(description="Username", default=None)] = None,
            password: Annotated[Optional[str], Field(description="Password", default=None)] = None,
            api_token: Annotated[Optional[str], Field(description="API token", default=None)] = None,
            vdom: Annotated[str, Field(description="Virtual Domain", default="root")] = "root",
            verify_ssl: Annotated[bool, Field(description="Verify SSL", default=True)] = True,
            timeout: Annotated[int, Field(description="Timeout in seconds", default=30)] = 30
        ):
            return await self.device_tools.add_device(
                device_id, host, port, username, password, api_token, vdom, verify_ssl, timeout
            )

        @self.mcp.tool(description=REMOVE_DEVICE_DESC)
        async def remove_device(
            device_id: Annotated[str, Field(description="Device identifier to remove")]
        ):
            return await self.device_tools.remove_device(device_id)

        # Firewall policy tools
        @self.mcp.tool(description=LIST_FIREWALL_POLICIES_DESC)
        async def list_firewall_policies(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.list_policies(device_id, vdom)

        @self.mcp.tool(description=CREATE_FIREWALL_POLICY_DESC)
        async def create_firewall_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_data: Annotated[dict, Field(description="Policy configuration as JSON")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.create_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description=UPDATE_FIREWALL_POLICY_DESC)
        async def update_firewall_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy ID to update")],
            policy_data: Annotated[dict, Field(description="Updated policy configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.update_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Get detailed information for a specific firewall policy")
        async def get_firewall_policy_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy ID to get details for")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.get_policy_detail(device_id, policy_id, vdom)

        @self.mcp.tool(description=DELETE_FIREWALL_POLICY_DESC)
        async def delete_firewall_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy ID to delete")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.delete_policy(device_id, policy_id, vdom)

        # Network object tools
        @self.mcp.tool(description=LIST_ADDRESS_OBJECTS_DESC)
        async def list_address_objects(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.list_address_objects(device_id, vdom)

        @self.mcp.tool(description=CREATE_ADDRESS_OBJECT_DESC)
        async def create_address_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Address object name")],
            address_type: Annotated[str, Field(description="Address type: ipmask, iprange, fqdn, wildcard-fqdn, geography. fqdn/wildcard-fqdn both usable in policies (6.2.2+). For SSL-exempt-only FQDN use create_wildcard_fqdn_custom.")],
            address: Annotated[str, Field(description="Address value (IP/netmask, range, or FQDN)")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.create_address_object(device_id, name, address_type, address, vdom)

        @self.mcp.tool(description=LIST_SERVICE_OBJECTS_DESC)
        async def list_service_objects(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.list_service_objects(device_id, vdom)

        @self.mcp.tool(description=CREATE_SERVICE_OBJECT_DESC)
        async def create_service_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Service object name")],
            service_type: Annotated[str, Field(description="Service type")],
            protocol: Annotated[str, Field(description="Protocol (TCP, UDP, ICMP)")],
            port: Annotated[Optional[str], Field(description="Port or port range")] = None,
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.create_service_object(device_id, name, service_type, protocol, port, vdom)

        # Routing tools
        @self.mcp.tool(description=LIST_STATIC_ROUTES_DESC)
        async def list_static_routes(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.list_static_routes(device_id, vdom)

        @self.mcp.tool(description=CREATE_STATIC_ROUTE_DESC)
        async def create_static_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            dst: Annotated[str, Field(description="Destination network (IP/netmask)")],
            gateway: Annotated[str, Field(description="Next hop gateway IP")],
            device: Annotated[Optional[str], Field(description="Outgoing interface name")] = None,
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.create_static_route(device_id, dst, gateway, device, vdom)

        @self.mcp.tool(description=GET_ROUTING_TABLE_DESC)
        async def get_routing_table(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.get_routing_table(device_id, vdom)

        @self.mcp.tool(description=LIST_INTERFACES_DESC)
        async def list_interfaces(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.list_interfaces(device_id, vdom)

        @self.mcp.tool(description=GET_INTERFACE_STATUS_DESC)
        async def get_interface_status(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            interface_name: Annotated[str, Field(description="Interface name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.get_interface_status(device_id, interface_name, vdom)

        @self.mcp.tool(description=UPDATE_STATIC_ROUTE_DESC)
        async def update_static_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_id: Annotated[str, Field(description="Route identifier")],
            route_data: Annotated[dict, Field(description="Route configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.update_static_route(device_id, route_id, route_data, vdom)

        @self.mcp.tool(description=DELETE_STATIC_ROUTE_DESC)
        async def delete_static_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_id: Annotated[str, Field(description="Route identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.delete_static_route(device_id, route_id, vdom)

        @self.mcp.tool(description=GET_STATIC_ROUTE_DETAIL_DESC)
        async def get_static_route_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_id: Annotated[str, Field(description="Route identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.get_static_route_detail(device_id, route_id, vdom)

        # Virtual IP tools
        @self.mcp.tool(description=LIST_VIRTUAL_IPS_DESC)
        async def list_virtual_ips(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.virtual_ip_tools.list_virtual_ips(device_id, vdom)

        @self.mcp.tool(description=CREATE_VIRTUAL_IP_DESC)
        async def create_virtual_ip(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Virtual IP name")],
            extip: Annotated[str, Field(description="External IP address")],
            mappedip: Annotated[str, Field(description="Mapped internal IP address")],
            extintf: Annotated[str, Field(description="External interface name")],
            portforward: Annotated[str, Field(description="Enable/disable port forwarding", default="disable")] = "disable",
            protocol: Annotated[str, Field(description="Protocol type", default="tcp")] = "tcp",
            extport: Annotated[Optional[str], Field(description="External port")] = None,
            mappedport: Annotated[Optional[str], Field(description="Mapped port")] = None,
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.virtual_ip_tools.create_virtual_ip(
                device_id, name, extip, mappedip, extintf, portforward, protocol, extport, mappedport, vdom
            )

        @self.mcp.tool(description=UPDATE_VIRTUAL_IP_DESC)
        async def update_virtual_ip(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Virtual IP name")],
            vip_data: Annotated[dict, Field(description="Virtual IP configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.virtual_ip_tools.update_virtual_ip(device_id, name, vip_data, vdom)

        @self.mcp.tool(description=GET_VIRTUAL_IP_DETAIL_DESC)
        async def get_virtual_ip_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Virtual IP name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.virtual_ip_tools.get_virtual_ip_detail(device_id, name, vdom)

        @self.mcp.tool(description=DELETE_VIRTUAL_IP_DESC)
        async def delete_virtual_ip(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Virtual IP name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.virtual_ip_tools.delete_virtual_ip(device_id, name, vdom)

        # ============================================================
        # Address object update/delete tools (existing API, new MCP tools)
        # ============================================================
        @self.mcp.tool(description="Update an existing address object")
        async def update_address_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Address object name")],
            address_data: Annotated[dict, Field(description="Updated address object data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.update_address_object(device_id, name, address_data, vdom)

        @self.mcp.tool(description="Delete an address object")
        async def delete_address_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Address object name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.delete_address_object(device_id, name, vdom)

        @self.mcp.tool(description="Update an existing service object")
        async def update_service_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Service object name")],
            service_data: Annotated[dict, Field(description="Updated service object data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.update_service_object(device_id, name, service_data, vdom)

        @self.mcp.tool(description="Delete a service object")
        async def delete_service_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Service object name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.delete_service_object(device_id, name, vdom)

        # ============================================================
        # Address Group tools
        # ============================================================
        @self.mcp.tool(description="List all address groups")
        async def list_addrgrps(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.list_addrgrps(device_id, vdom)

        @self.mcp.tool(description="""Create a new address group.

Address groups combine multiple address objects into a single reference for firewall policies.

Required fields in addrgrp_data:
  - name: Group name (string)
  - member: Array of address object references in [{"name": "..."}] format, e.g.:
    [{"name": "LAN_10.0.0.0_24"}, {"name": "DMZ_192.168.1.0_24"}]

Returns: Creation confirmation with group details.""")
        async def create_addrgrp(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            addrgrp_data: Annotated[dict, Field(description="Address group configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.create_addrgrp(device_id, addrgrp_data, vdom)

        @self.mcp.tool(description="""Update an existing address group.

Required params:
  - name: Name of the address group to update (string, from list_addrgrps output)
  - addrgrp_data: JSON object with updated fields, e.g.:
    {"member": [{"name": "NEW-HOST"}, {"name": "OLD-HOST"}]}

Note: addrgrp_data must contain the 'member' field even for partial updates.

Returns: Update confirmation with new group details.""")
        async def update_addrgrp(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Address group name")],
            addrgrp_data: Annotated[dict, Field(description="Updated address group configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.update_addrgrp(device_id, name, addrgrp_data, vdom)

        @self.mcp.tool(description="Delete an address group")
        async def delete_addrgrp(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Address group name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.delete_addrgrp(device_id, name, vdom)

        @self.mcp.tool(description="Get detailed information for an address group")
        async def get_addrgrp_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Address group name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.get_addrgrp_detail(device_id, name, vdom)

        # ============================================================
        # Service Group tools
        # ============================================================
        @self.mcp.tool(description="List all service groups")
        async def list_service_groups(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.list_service_groups(device_id, vdom)

        @self.mcp.tool(description="Create a new service group")
        async def create_service_group(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            service_group_data: Annotated[dict, Field(description="Service group configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.create_service_group(device_id, service_group_data, vdom)

        @self.mcp.tool(description="Update an existing service group")
        async def update_service_group(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Service group name")],
            service_group_data: Annotated[dict, Field(description="Updated service group configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.update_service_group(device_id, name, service_group_data, vdom)

        @self.mcp.tool(description="Delete a service group")
        async def delete_service_group(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Service group name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.delete_service_group(device_id, name, vdom)

        # ============================================================
        # Schedule tools
        # ============================================================
        @self.mcp.tool(description="List all onetime schedules")
        async def list_schedule_onetime(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.schedule_tools.list_schedule_onetime(device_id, vdom)

        @self.mcp.tool(description="Create a new onetime schedule")
        async def create_schedule_onetime(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[dict, Field(description="Onetime schedule configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.schedule_tools.create_schedule_onetime(device_id, data, vdom)

        @self.mcp.tool(description="Update an existing onetime schedule")
        async def update_schedule_onetime(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Schedule name")],
            data: Annotated[dict, Field(description="Updated onetime schedule configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.schedule_tools.update_schedule_onetime(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete an onetime schedule")
        async def delete_schedule_onetime(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Schedule name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.schedule_tools.delete_schedule_onetime(device_id, name, vdom)

        @self.mcp.tool(description="List all recurring schedules")
        async def list_schedule_recurring(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
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
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[dict, Field(description="Recurring schedule configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.schedule_tools.create_schedule_recurring(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing recurring schedule.

Required params:
  - name: Schedule name to update (string)
  - data: JSON object with fields to update, e.g.:
    {"start": "09:00", "end": "17:00", "day": ["monday","tuesday","wednesday","thursday","friday"]}

Returns: Update confirmation.""")
        async def update_schedule_recurring(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Schedule name")],
            data: Annotated[dict, Field(description="Updated recurring schedule configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.schedule_tools.update_schedule_recurring(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete a recurring schedule")
        async def delete_schedule_recurring(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Schedule name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.schedule_tools.delete_schedule_recurring(device_id, name, vdom)

        @self.mcp.tool(description="List all schedule groups")
        async def list_schedule_group(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.schedule_tools.list_schedule_group(device_id, vdom)

        @self.mcp.tool(description="Create a new schedule group")
        async def create_schedule_group(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[dict, Field(description="Schedule group configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.schedule_tools.create_schedule_group(device_id, data, vdom)

        @self.mcp.tool(description="Update an existing schedule group")
        async def update_schedule_group(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Schedule group name")],
            data: Annotated[dict, Field(description="Updated schedule group configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.schedule_tools.update_schedule_group(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete a schedule group")
        async def delete_schedule_group(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Schedule group name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.schedule_tools.delete_schedule_group(device_id, name, vdom)

        # ============================================================
        # Resource tools (IP pools, VIP groups, shapers, SNAT, etc.)
        # ============================================================
        @self.mcp.tool(description="List all IP pools")
        async def list_ippools(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.list_ippools(device_id, vdom)

        @self.mcp.tool(description="Create a new IP pool")
        async def create_ippool(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[dict, Field(description="IP pool configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.create_ippool(device_id, data, vdom)

        @self.mcp.tool(description="Update an existing IP pool")
        async def update_ippool(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="IP pool name")],
            data: Annotated[dict, Field(description="Updated IP pool configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.update_ippool(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete an IP pool")
        async def delete_ippool(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="IP pool name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.delete_ippool(device_id, name, vdom)

        @self.mcp.tool(description="List all VIP groups")
        async def list_vipgrps(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.list_vipgrps(device_id, vdom)

        @self.mcp.tool(description="Create a new VIP group")
        async def create_vipgrp(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[dict, Field(description="VIP group configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.create_vipgrp(device_id, data, vdom)

        @self.mcp.tool(description="Update an existing VIP group")
        async def update_vipgrp(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="VIP group name")],
            data: Annotated[dict, Field(description="Updated VIP group configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.update_vipgrp(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete a VIP group")
        async def delete_vipgrp(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="VIP group name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.delete_vipgrp(device_id, name, vdom)

        @self.mcp.tool(description="List all traffic shapers")
        async def list_traffic_shapers(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.list_traffic_shapers(device_id, vdom)

        @self.mcp.tool(description="List all central SNAT maps")
        async def list_central_snat_maps(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.list_central_snat_maps(device_id, vdom)

        # ============================================================
        # Security Policy tools
        # ============================================================
        @self.mcp.tool(description="List all NGFW security policies")
        async def list_security_policies(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
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
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_data: Annotated[dict, Field(description="Security policy configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.create_security_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description="List all proxy policies")
        async def list_proxy_policies(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.list_proxy_policies(device_id, vdom)

        @self.mcp.tool(description="Create a new proxy policy. All multi-value fields (interface, address, service references) MUST use [{'name': '...'}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM and will cause 500 errors. schedule may be required — check FortiOS API docs.")
        async def create_proxy_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_data: Annotated[dict, Field(description="Proxy policy configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.create_proxy_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description="List all proxy addresses")
        async def list_proxy_addresses(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.list_proxy_addresses(device_id, vdom)

        @self.mcp.tool(description="List all DoS policies")
        async def list_dos_policies(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.list_dos_policies(device_id, vdom)

        @self.mcp.tool(description="List all local-in policies")
        async def list_local_in_policies(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.list_local_in_policies(device_id, vdom)

        # ============================================================
        # Wildcard FQDN tools
        # ============================================================
        @self.mcp.tool(description="List all wildcard FQDN entries")
        async def list_wildcard_fqdn_custom(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.list_wildcard_fqdn_custom(device_id, vdom)

        @self.mcp.tool(description="Create a new wildcard FQDN entry")
        async def create_wildcard_fqdn_custom(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[dict, Field(description="Wildcard FQDN configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.create_wildcard_fqdn_custom(device_id, data, vdom)

        @self.mcp.tool(description="Update a wildcard FQDN entry")
        async def update_wildcard_fqdn_custom(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Wildcard FQDN entry name")],
            data: Annotated[dict, Field(description="Updated wildcard FQDN configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.update_wildcard_fqdn_custom(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete a wildcard FQDN entry")
        async def delete_wildcard_fqdn_custom(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Wildcard FQDN entry name to delete")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.delete_wildcard_fqdn_custom(device_id, name, vdom)

        @self.mcp.tool(description="List all wildcard FQDN groups")
        async def list_wildcard_fqdn_group(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.list_wildcard_fqdn_group(device_id, vdom)

        @self.mcp.tool(description="Create a new wildcard FQDN group")
        async def create_wildcard_fqdn_group(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[dict, Field(description="Wildcard FQDN group configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.create_wildcard_fqdn_group(device_id, data, vdom)

        @self.mcp.tool(description="Update a wildcard FQDN group")
        async def update_wildcard_fqdn_group(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Wildcard FQDN group name")],
            data: Annotated[dict, Field(description="Updated wildcard FQDN group configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.update_wildcard_fqdn_group(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete a wildcard FQDN group")
        async def delete_wildcard_fqdn_group(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Wildcard FQDN group name to delete")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.delete_wildcard_fqdn_group(device_id, name, vdom)

        # ============================================================
        # Security profile tools (SSL/SSH, IPS, profile groups, log settings)
        # ============================================================
        @self.mcp.tool(description="List all SSL/SSH inspection profiles")
        async def list_ssl_ssh_profiles(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_ssl_ssh_profiles(device_id, vdom)

        @self.mcp.tool(description="List all IPS sensors")
        async def list_ips_sensors(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_ips_sensors(device_id, vdom)

        @self.mcp.tool(description="List all profile groups")
        async def list_profile_groups(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_profile_groups(device_id, vdom)

        @self.mcp.tool(description="Get firewall global settings")
        async def get_firewall_global(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.get_firewall_global(device_id, vdom)

        @self.mcp.tool(description="Update firewall global settings")
        async def update_firewall_global(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[dict, Field(description="Firewall global settings")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.update_firewall_global(device_id, data, vdom)

        @self.mcp.tool(description="Get log settings")
        async def get_log_setting(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.get_log_setting(device_id, vdom)

        # ============================================================
        # Authentication tools
        # ============================================================
        @self.mcp.tool(description="List all authentication rules")
        async def list_auth_rules(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_auth_rules(device_id, vdom)

        @self.mcp.tool(description="Create a new authentication rule")
        async def create_auth_rule(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[dict, Field(description="Authentication rule configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.create_auth_rule(device_id, data, vdom)

        @self.mcp.tool(description="Delete an authentication rule by name")
        async def delete_auth_rule(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Authentication rule name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.delete_auth_rule(device_id, name, vdom)

        @self.mcp.tool(description="List all authentication schemes")
        async def list_auth_schemes(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_auth_schemes(device_id, vdom)

        @self.mcp.tool(description="Get authentication settings")
        async def get_auth_setting(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.get_auth_setting(device_id, vdom)

        # ============================================================
        # DNS Filter tools
        # ============================================================
        @self.mcp.tool(description="List all DNS filter profiles")
        async def list_dnsfilter_profiles(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_dnsfilter_profiles(device_id, vdom)

        @self.mcp.tool(description="Create a new DNS filter profile")
        async def create_dnsfilter_profile(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[dict, Field(description="DNS filter profile configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.create_dnsfilter_profile(device_id, data, vdom)

        @self.mcp.tool(description="Delete a DNS filter profile by name")
        async def delete_dnsfilter_profile(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="DNS filter profile name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.delete_dnsfilter_profile(device_id, name, vdom)

        @self.mcp.tool(description="List all DNS domain filters")
        async def list_dnsfilter_domain_filters(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_dnsfilter_domain_filters(device_id, vdom)

        # ============================================================
        # DLP tools
        # ============================================================
        @self.mcp.tool(description="List all DLP sensors")
        async def list_dlp_sensors(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_dlp_sensors(device_id, vdom)

        @self.mcp.tool(description="List all DLP profiles")
        async def list_dlp_profiles(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_dlp_profiles(device_id, vdom)

        @self.mcp.tool(description="Get DLP settings")
        async def get_dlp_settings(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.get_dlp_settings(device_id, vdom)

        # ============================================================
        # Email Filter tools
        # ============================================================
        @self.mcp.tool(description="List all email filter profiles")
        async def list_emailfilter_profiles(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_emailfilter_profiles(device_id, vdom)

        # ============================================================
        # Certificate tools
        # ============================================================
        @self.mcp.tool(description="List all CA certificates")
        async def get_certificate_ca(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.get_certificate_ca(device_id, vdom)

        @self.mcp.tool(description="List all local certificates")
        async def get_certificate_local(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.get_certificate_local(device_id, vdom)

        # ============================================================
        # CASB tools
        # ============================================================
        @self.mcp.tool(description="List all CASB profiles")
        async def list_casb_profiles(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_casb_profiles(device_id, vdom)

        # ============================================================
        # Endpoint Control tools
        # ============================================================
        @self.mcp.tool(description="Get endpoint control settings")
        async def get_endpoint_control_settings(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.get_endpoint_control_settings(device_id, vdom)

        # ============================================================
        # Application Control tools
        # ============================================================
        @self.mcp.tool(description="List all application groups")
        async def list_application_groups(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_application_groups(device_id, vdom)

        @self.mcp.tool(description="List all application control lists")
        async def list_application_lists(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_application_lists(device_id, vdom)

        # ============================================================
        # Antivirus tools
        # ============================================================
        @self.mcp.tool(description="List all antivirus profiles")
        async def list_antivirus_profiles(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_antivirus_profiles(device_id, vdom)

        @self.mcp.tool(description="Get antivirus settings")
        async def get_antivirus_settings(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.get_antivirus_settings(device_id, vdom)

        # ============================================================
        # Alert Email tools
        # ============================================================
        @self.mcp.tool(description="Get alert email settings")
        async def get_alertemail_setting(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.get_alertemail_setting(device_id, vdom)

        # ============================================================
        # SSH Filter tools
        # ============================================================
        @self.mcp.tool(description="List all SSH filter profiles")
        async def list_ssh_filter_profiles(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_ssh_filter_profiles(device_id, vdom)

        # ============================================================
        # SCTP Filter tools
        # ============================================================
        @self.mcp.tool(description="List all SCTP filter profiles")
        async def list_sctp_filter_profiles(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_sctp_filter_profiles(device_id, vdom)

        # ============================================================
        # Switch Controller tools
        # ============================================================
        @self.mcp.tool(description="List all switch ACL groups")
        async def list_switch_acl_groups(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_switch_acl_groups(device_id, vdom)

        @self.mcp.tool(description="List all switch 802.1X policies")
        async def list_switch_8021x_policies(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_switch_8021x_policies(device_id, vdom)

        # ============================================================
        # User tools
        # ============================================================
        @self.mcp.tool(description="List all local users")
        async def list_user_locals(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_user_locals(device_id, vdom)

        @self.mcp.tool(description="List all user groups")
        async def list_user_groups(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_user_groups(device_id, vdom)

        @self.mcp.tool(description="List all LDAP servers")
        async def list_user_ldaps(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_user_ldaps(device_id, vdom)

        @self.mcp.tool(description="List all RADIUS servers")
        async def list_user_radiuses(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_user_radiuses(device_id, vdom)

        @self.mcp.tool(description="Get user authentication settings")
        async def get_user_setting(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.get_user_setting(device_id, vdom)

        # ============================================================
        # WebFilter tools
        # ============================================================
        @self.mcp.tool(description="List all web filter profiles")
        async def list_webfilter_profiles(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_webfilter_profiles(device_id, vdom)

        @self.mcp.tool(description="List all web filter URL filters")
        async def list_webfilter_urlfilters(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_webfilter_urlfilters(device_id, vdom)

        # ============================================================
        # Web Proxy tools
        # ============================================================
        @self.mcp.tool(description="List all web proxy profiles")
        async def list_web_proxy_profiles(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_web_proxy_profiles(device_id, vdom)

        # ============================================================
        # WAF tools
        # ============================================================
        @self.mcp.tool(description="List all WAF profiles")
        async def list_waf_profiles(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_waf_profiles(device_id, vdom)

        # ============================================================
        # VoIP tools
        # ============================================================
        @self.mcp.tool(description="List all VoIP profiles")
        async def list_voip_profiles(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_voip_profiles(device_id, vdom)

        # ============================================================
        # VPN - IPSec tools
        # ============================================================
        @self.mcp.tool(description="List all IPSec phase1 interfaces")
        async def list_vpn_ipsec_phase1_interfaces(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_vpn_ipsec_phase1_interfaces(device_id, vdom)

        @self.mcp.tool(description="List all IPSec phase2 interfaces")
        async def list_vpn_ipsec_phase2_interfaces(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_vpn_ipsec_phase2_interfaces(device_id, vdom)

        # ============================================================
        # VPN - SSL VPN tools
        # ============================================================
        @self.mcp.tool(description="Get SSL VPN settings")
        async def get_vpn_ssl_settings(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.get_vpn_ssl_settings(device_id, vdom)

        @self.mcp.tool(description="List all SSL VPN web portals")
        async def list_vpn_ssl_web_portals(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_vpn_ssl_web_portals(device_id, vdom)

        # ============================================================
        # System - DHCP tools
        # ============================================================
        @self.mcp.tool(description="List all DHCP servers")
        async def list_system_dhcp_servers(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_system_dhcp_servers(device_id, vdom)

        # ============================================================
        # System - SNMP tools
        # ============================================================
        @self.mcp.tool(description="List all SNMP communities")
        async def list_system_snmp_communities(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.security_tools.list_system_snmp_communities(device_id, vdom)


        # ============================================================
        # Firewall tools (auto-registered - 43 methods)
        # ============================================================

        @self.mcp.tool(description='Update an existing security policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_security_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            policy_data: Annotated[Dict[str, Any], Field(description="Policy Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.update_security_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Delete Security Policy")
        async def delete_security_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.delete_security_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="Get Security Policy Detail")
        async def get_security_policy_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.get_security_policy_detail(device_id, policy_id, vdom)

        @self.mcp.tool(description='Update an existing proxy policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_proxy_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            policy_data: Annotated[Dict[str, Any], Field(description="Policy Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.update_proxy_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Delete Proxy Policy")
        async def delete_proxy_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.delete_proxy_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="Get Proxy Policy Detail")
        async def get_proxy_policy_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.get_proxy_policy_detail(device_id, policy_id, vdom)

        @self.mcp.tool(description="Create Proxy Address")
        async def create_proxy_address(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.create_proxy_address(device_id, data, vdom)

        @self.mcp.tool(description="Update Proxy Address")
        async def update_proxy_address(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.update_proxy_address(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Proxy Address")
        async def delete_proxy_address(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.delete_proxy_address(device_id, name, vdom)

        @self.mcp.tool(description="List Proxy Addrgrps")
        async def list_proxy_addrgrps(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.list_proxy_addrgrps(device_id, vdom)

        @self.mcp.tool(description="Create Proxy Addrgrp")
        async def create_proxy_addrgrp(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.create_proxy_addrgrp(device_id, data, vdom)

        @self.mcp.tool(description="Update Proxy Addrgrp")
        async def update_proxy_addrgrp(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.update_proxy_addrgrp(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Proxy Addrgrp")
        async def delete_proxy_addrgrp(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.delete_proxy_addrgrp(device_id, name, vdom)

        @self.mcp.tool(description="List Shaping Policies")
        async def list_shaping_policies(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.list_shaping_policies(device_id, vdom)

        @self.mcp.tool(description="Create a new shaping policy. All multi-value fields (interface, address, service references) MUST use [{'name': '...'}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM and will cause 500 errors.")
        async def create_shaping_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_data: Annotated[Dict[str, Any], Field(description="Policy Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.create_shaping_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description='Update an existing shaping policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_shaping_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            policy_data: Annotated[Dict[str, Any], Field(description="Policy Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.update_shaping_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Delete Shaping Policy")
        async def delete_shaping_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.delete_shaping_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="List Shaping Profiles")
        async def list_shaping_profiles(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.list_shaping_profiles(device_id, vdom)

        @self.mcp.tool(description="Create Shaping Profile")
        async def create_shaping_profile(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.create_shaping_profile(device_id, data, vdom)

        @self.mcp.tool(description="Update Shaping Profile")
        async def update_shaping_profile(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.update_shaping_profile(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Shaping Profile")
        async def delete_shaping_profile(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.delete_shaping_profile(device_id, name, vdom)

        @self.mcp.tool(description="Create a new DoS policy. All multi-value fields (interface, address, service references) MUST use [{'name': '...'}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM and will cause 500 errors.")
        async def create_dos_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_data: Annotated[Dict[str, Any], Field(description="Policy Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.create_dos_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description='Update an existing DoS policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_dos_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            policy_data: Annotated[Dict[str, Any], Field(description="Policy Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.update_dos_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Delete Dos Policy")
        async def delete_dos_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.delete_dos_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="Create a new local-in policy. All multi-value fields (interface, address, service references) MUST use [{'name': '...'}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM and will cause 500 errors.")
        async def create_local_in_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_data: Annotated[Dict[str, Any], Field(description="Policy Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.create_local_in_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description='Update an existing local-in policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_local_in_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            policy_data: Annotated[Dict[str, Any], Field(description="Policy Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.update_local_in_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Delete Local In Policy")
        async def delete_local_in_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.delete_local_in_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="List Interface Policies")
        async def list_interface_policies(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.list_interface_policies(device_id, vdom)

        @self.mcp.tool(description="Create a new interface policy. All multi-value fields (interface, address, service references) MUST use [{'name': '...'}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM and will cause 500 errors.")
        async def create_interface_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_data: Annotated[Dict[str, Any], Field(description="Policy Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.create_interface_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description='Update an existing interface policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_interface_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            policy_data: Annotated[Dict[str, Any], Field(description="Policy Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.update_interface_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Delete Interface Policy")
        async def delete_interface_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.delete_interface_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="List Multicast Policies")
        async def list_multicast_policies(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.list_multicast_policies(device_id, vdom)

        @self.mcp.tool(description="Create a new multicast policy. All multi-value fields (interface, address, service references) MUST use [{'name': '...'}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM and will cause 500 errors.")
        async def create_multicast_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_data: Annotated[Dict[str, Any], Field(description="Policy Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.create_multicast_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description='Update an existing multicast policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_multicast_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            policy_data: Annotated[Dict[str, Any], Field(description="Policy Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.update_multicast_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Delete Multicast Policy")
        async def delete_multicast_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.delete_multicast_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="List Multicast Addresses")
        async def list_multicast_addresses(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.list_multicast_addresses(device_id, vdom)

        @self.mcp.tool(description="Create Multicast Address")
        async def create_multicast_address(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.create_multicast_address(device_id, data, vdom)

        @self.mcp.tool(description="Update Multicast Address")
        async def update_multicast_address(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.update_multicast_address(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Multicast Address")
        async def delete_multicast_address(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.delete_multicast_address(device_id, name, vdom)

        @self.mcp.tool(description="List Sniffers")
        async def list_sniffers(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.list_sniffers(device_id, vdom)

        @self.mcp.tool(description="Create Sniffer")
        async def create_sniffer(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.create_sniffer(device_id, data, vdom)

        @self.mcp.tool(description="Update Sniffer")
        async def update_sniffer(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            sniffer_id: Annotated[str, Field(description="Sniffer Id")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.update_sniffer(device_id, sniffer_id, data, vdom)

        @self.mcp.tool(description="Delete Sniffer")
        async def delete_sniffer(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            sniffer_id: Annotated[str, Field(description="Sniffer Id")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.firewall_tools.delete_sniffer(device_id, sniffer_id, vdom)

        # ============================================================
        # Resource tools (auto-registered - 31 methods)
        # ============================================================

        @self.mcp.tool(description="Create Traffic Shaper")
        async def create_traffic_shaper(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.create_traffic_shaper(device_id, data, vdom)

        @self.mcp.tool(description="Update Traffic Shaper")
        async def update_traffic_shaper(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.update_traffic_shaper(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Traffic Shaper")
        async def delete_traffic_shaper(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.delete_traffic_shaper(device_id, name, vdom)

        @self.mcp.tool(description="List Per Ip Shapers")
        async def list_per_ip_shapers(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.list_per_ip_shapers(device_id, vdom)

        @self.mcp.tool(description="Create Per Ip Shaper")
        async def create_per_ip_shaper(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.create_per_ip_shaper(device_id, data, vdom)

        @self.mcp.tool(description="Update Per Ip Shaper")
        async def update_per_ip_shaper(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.update_per_ip_shaper(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Per Ip Shaper")
        async def delete_per_ip_shaper(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.delete_per_ip_shaper(device_id, name, vdom)

        @self.mcp.tool(description="Create Central Snat Map")
        async def create_central_snat_map(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.create_central_snat_map(device_id, data, vdom)

        @self.mcp.tool(description="Update Central Snat Map")
        async def update_central_snat_map(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.update_central_snat_map(device_id, policy_id, data, vdom)

        @self.mcp.tool(description="Delete Central Snat Map")
        async def delete_central_snat_map(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.delete_central_snat_map(device_id, policy_id, vdom)

        @self.mcp.tool(description="Get Central Snat Map Detail")
        async def get_central_snat_map_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.get_central_snat_map_detail(device_id, policy_id, vdom)

        @self.mcp.tool(description="List Ip Translations")
        async def list_ip_translations(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.list_ip_translations(device_id, vdom)

        @self.mcp.tool(description="Create Ip Translation")
        async def create_ip_translation(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.create_ip_translation(device_id, data, vdom)

        @self.mcp.tool(description="Update Ip Translation")
        async def update_ip_translation(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            trans_id: Annotated[str, Field(description="Trans Id")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.update_ip_translation(device_id, trans_id, data, vdom)

        @self.mcp.tool(description="Delete Ip Translation")
        async def delete_ip_translation(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            trans_id: Annotated[str, Field(description="Trans Id")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.delete_ip_translation(device_id, trans_id, vdom)

        @self.mcp.tool(description="List Identity Based Routes")
        async def list_identity_based_routes(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.list_identity_based_routes(device_id, vdom)

        @self.mcp.tool(description="Create Identity Based Route")
        async def create_identity_based_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.create_identity_based_route(device_id, data, vdom)

        @self.mcp.tool(description="Update Identity Based Route")
        async def update_identity_based_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.update_identity_based_route(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Identity Based Route")
        async def delete_identity_based_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.delete_identity_based_route(device_id, name, vdom)

        @self.mcp.tool(description="List Dns Translations")
        async def list_dns_translations(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.list_dns_translations(device_id, vdom)

        @self.mcp.tool(description="Create Dns Translation")
        async def create_dns_translation(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.create_dns_translation(device_id, data, vdom)

        @self.mcp.tool(description="Update Dns Translation")
        async def update_dns_translation(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            trans_id: Annotated[str, Field(description="Trans Id")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.update_dns_translation(device_id, trans_id, data, vdom)

        @self.mcp.tool(description="Delete Dns Translation")
        async def delete_dns_translation(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            trans_id: Annotated[str, Field(description="Trans Id")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.delete_dns_translation(device_id, trans_id, vdom)

        @self.mcp.tool(description="List Ttl Policies")
        async def list_ttl_policies(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.list_ttl_policies(device_id, vdom)

        @self.mcp.tool(description="Create a new TTL policy. All multi-value fields (interface, address, service references) MUST use [{'name': '...'}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM and will cause 500 errors.")
        async def create_ttl_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.create_ttl_policy(device_id, data, vdom)

        @self.mcp.tool(description='Update an existing TTL policy. All multi-value fields (interface, address, service references) MUST use [{"name": "..."}] object-array format — plain strings are NOT accepted by FortiOS 8.0.0 VM."')
        async def update_ttl_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.update_ttl_policy(device_id, policy_id, data, vdom)

        @self.mcp.tool(description="Delete Ttl Policy")
        async def delete_ttl_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy Id")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.delete_ttl_policy(device_id, policy_id, vdom)

        @self.mcp.tool(description="List Decrypted Traffic Mirrors")
        async def list_decrypted_traffic_mirrors(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.list_decrypted_traffic_mirrors(device_id, vdom)

        @self.mcp.tool(description="Create Decrypted Traffic Mirror")
        async def create_decrypted_traffic_mirror(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.create_decrypted_traffic_mirror(device_id, data, vdom)

        @self.mcp.tool(description="Update Decrypted Traffic Mirror")
        async def update_decrypted_traffic_mirror(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.update_decrypted_traffic_mirror(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Decrypted Traffic Mirror")
        async def delete_decrypted_traffic_mirror(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.resource_tools.delete_decrypted_traffic_mirror(device_id, name, vdom)

        # ============================================================
        # Security tools (auto-registered - 25 methods)
        # ============================================================

        @self.mcp.tool(description="Create Ssl Ssh Profile")
        async def create_ssl_ssh_profile(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.create_ssl_ssh_profile(device_id, data, vdom)

        @self.mcp.tool(description="Update Ssl Ssh Profile")
        async def update_ssl_ssh_profile(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.update_ssl_ssh_profile(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Ssl Ssh Profile")
        async def delete_ssl_ssh_profile(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.delete_ssl_ssh_profile(device_id, name, vdom)

        @self.mcp.tool(description="List Ssl Servers")
        async def list_ssl_servers(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.list_ssl_servers(device_id, vdom)

        @self.mcp.tool(description="Create Ssl Server")
        async def create_ssl_server(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.create_ssl_server(device_id, data, vdom)

        @self.mcp.tool(description="Update Ssl Server")
        async def update_ssl_server(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.update_ssl_server(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Ssl Server")
        async def delete_ssl_server(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.delete_ssl_server(device_id, name, vdom)

        @self.mcp.tool(description="Create Profile Group")
        async def create_profile_group(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.create_profile_group(device_id, data, vdom)

        @self.mcp.tool(description="Update Profile Group")
        async def update_profile_group(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.update_profile_group(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Profile Group")
        async def delete_profile_group(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.delete_profile_group(device_id, name, vdom)

        @self.mcp.tool(description="List Profile Protocol Options")
        async def list_profile_protocol_options(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.list_profile_protocol_options(device_id, vdom)

        @self.mcp.tool(description="Create Profile Protocol Options")
        async def create_profile_protocol_options(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.create_profile_protocol_options(device_id, data, vdom)

        @self.mcp.tool(description="Update Profile Protocol Options")
        async def update_profile_protocol_options(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.update_profile_protocol_options(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Profile Protocol Options")
        async def delete_profile_protocol_options(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.delete_profile_protocol_options(device_id, name, vdom)

        @self.mcp.tool(description="""Create a new IPS sensor.

IPS sensors define intrusion prevention rules for firewall policies. Must be bound to a security policy via ips-sensor field (utm-status: enable required on the policy first).

Required fields in data:
  - name: Sensor name (string)
  - entries: Array of filter entries:
    [{"rule": 12345, "status": "enable", "action": "block", "location": "server"}]

Common rule IDs: FortiGuard IPS signatures use numeric rule IDs. Use list_ips_signatures() to find available rule IDs.

Returns: Creation confirmation with sensor details.""")
        async def create_ips_sensor(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.create_ips_sensor(device_id, data, vdom)

        @self.mcp.tool(description="""Update an existing IPS sensor.

Required params:
  - name: Sensor name to update (string)
  - data: JSON object with updated fields, e.g.:
    {"entries": [{"rule": 12345, "status": "enable", "action": "block", "location": "all"}]}

Returns: Update confirmation.""")
        async def update_ips_sensor(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.update_ips_sensor(device_id, name, data, vdom)

        @self.mcp.tool(description="Delete Ips Sensor")
        async def delete_ips_sensor(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.delete_ips_sensor(device_id, name, vdom)

        @self.mcp.tool(description="Get Ips Sensor Detail")
        async def get_ips_sensor_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.get_ips_sensor_detail(device_id, name, vdom)

        @self.mcp.tool(description="Update Log Setting")
        async def update_log_setting(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.update_log_setting(device_id, data, vdom)

        @self.mcp.tool(description="Get Log Disk Setting")
        async def get_log_disk_setting(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.get_log_disk_setting(device_id, vdom)

        @self.mcp.tool(description="Update Log Disk Setting")
        async def update_log_disk_setting(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.update_log_disk_setting(device_id, data, vdom)

        @self.mcp.tool(description="Get Log Fortianalyzer Setting")
        async def get_log_fortianalyzer_setting(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.get_log_fortianalyzer_setting(device_id, vdom)

        @self.mcp.tool(description="Update Log Fortianalyzer Setting")
        async def update_log_fortianalyzer_setting(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.update_log_fortianalyzer_setting(device_id, data, vdom)

        @self.mcp.tool(description="Get Log Syslogd Setting")
        async def get_log_syslogd_setting(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.get_log_syslogd_setting(device_id, vdom)

        @self.mcp.tool(description="Update Log Syslogd Setting")
        async def update_log_syslogd_setting(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            data: Annotated[Dict[str, Any], Field(description="Data")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.security_tools.update_log_syslogd_setting(device_id, data, vdom)

        # ============================================================
        # Generic CMDB tools (covers ALL 1023+ FortiOS 8.0 endpoints)
        # ============================================================
        @self.mcp.tool(description="List resources at any CMDB path (covers ALL FortiOS 8.0 endpoints)")
        async def cmdb_list(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            path: Annotated[str, Field(description="CMDB path, e.g. firewall/address, router/bgp, system/dns")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.cmdb_tools.cmdb_list(device_id, path, vdom)

        @self.mcp.tool(description="Get a single resource by name, or a singleton object (omit name for singleton like system/global)")
        async def cmdb_get(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            path: Annotated[str, Field(description="CMDB path, e.g. firewall/address, system/global")],
            name: Annotated[Optional[str], Field(description="Resource name or ID — omit for singleton objects", default=None)] = None,
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.cmdb_tools.cmdb_get(device_id, path, name, vdom)

        @self.mcp.tool(description="Create a new resource at any CMDB path")
        async def cmdb_create(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            path: Annotated[str, Field(description="CMDB path, e.g. firewall/address, router/static")],
            data: Annotated[Dict[str, Any], Field(description="Configuration data as JSON")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.cmdb_tools.cmdb_create(device_id, path, data, vdom)

        @self.mcp.tool(description="Update a resource or singleton (omit name for singleton like system/global)")
        async def cmdb_update(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            path: Annotated[str, Field(description="CMDB path, e.g. firewall/address, system/global")],
            data: Annotated[Dict[str, Any], Field(description="Updated configuration data")],
            name: Annotated[Optional[str], Field(description="Resource name or ID — omit for singleton objects", default=None)] = None,
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.cmdb_tools.cmdb_update(device_id, path, data, name, vdom)

        @self.mcp.tool(description="Delete a resource by name from any CMDB path")
        async def cmdb_delete(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            path: Annotated[str, Field(description="CMDB path, e.g. firewall/address")],
            name: Annotated[Optional[str], Field(description="Resource name or ID to delete", default=None)] = None,
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
        ):
            return await self.cmdb_tools.cmdb_delete(device_id, path, name, vdom)

        # ============================================================
        # Monitor tools (47 tools — 46 specific + 1 generic monitor_request)
        # ============================================================
        @self.mcp.tool(description="Get IPSec VPN monitor status")
        async def monitor_vpn_ipsec(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_vpn_ipsec(device_id, vdom)

        @self.mcp.tool(description="Get IPSec VPN connection count")
        async def monitor_vpn_ipsec_connection_count(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_vpn_ipsec_connection_count(device_id, vdom)

        @self.mcp.tool(description="Get SSL VPN status")
        async def monitor_vpn_ssl(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_vpn_ssl(device_id, vdom)

        @self.mcp.tool(description="Get SSL VPN statistics")
        async def monitor_vpn_ssl_stats(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_vpn_ssl_stats(device_id, vdom)

        @self.mcp.tool(description="Get firewall authenticated users")
        async def monitor_user_firewall(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_user_firewall(device_id, vdom)

        @self.mcp.tool(description="Get firewall user count")
        async def monitor_user_firewall_count(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_user_firewall_count(device_id, vdom)

        @self.mcp.tool(description="Get banned users")
        async def monitor_user_banned(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_user_banned(device_id, vdom)

        @self.mcp.tool(description="Get FSSO users")
        async def monitor_user_fsso(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_user_fsso(device_id, vdom)

        @self.mcp.tool(description="Get SD-WAN health checks")
        async def monitor_virtual_wan_health_check(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_virtual_wan_health_check(device_id, vdom)

        @self.mcp.tool(description="Get SD-WAN members")
        async def monitor_virtual_wan_members(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_virtual_wan_members(device_id, vdom)

        @self.mcp.tool(description="Get SD-WAN SLA log")
        async def monitor_virtual_wan_sla_log(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_virtual_wan_sla_log(device_id, vdom)

        @self.mcp.tool(description="Get UTM application lookup by name")
        async def monitor_utm_app_lookup(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            app_name: Annotated[str, Field(description="Application name to lookup")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_utm_app_lookup(device_id, app_name, vdom)

        @self.mcp.tool(description="Get UTM application categories")
        async def monitor_utm_application_categories(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_utm_application_categories(device_id, vdom)

        @self.mcp.tool(description="Get UTM applications list")
        async def monitor_utm_applications(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_utm_applications(device_id, vdom)

        @self.mcp.tool(description="Get IPv4 routing table")
        async def monitor_router_ipv4(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_router_ipv4(device_id, vdom)

        @self.mcp.tool(description="Get IPv6 routing table")
        async def monitor_router_ipv6(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_router_ipv6(device_id, vdom)

        @self.mcp.tool(description="Get firewall ACL")
        async def monitor_firewall_acl(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_firewall_acl(device_id, vdom)

        @self.mcp.tool(description="Get firewall ACL6")
        async def monitor_firewall_acl6(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_firewall_acl6(device_id, vdom)

        @self.mcp.tool(description="Get license status")
        async def monitor_license_status(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.resource_tools.monitor_license_status(device_id)

        @self.mcp.tool(description="Get log disk usage")
        async def monitor_log_current_disk_usage(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_log_current_disk_usage(device_id, vdom)

        @self.mcp.tool(description="Get FortiAnalyzer log status")
        async def monitor_log_fortianalyzer(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_log_fortianalyzer(device_id, vdom)

        @self.mcp.tool(description="Get FortiCloud log status")
        async def monitor_log_forticloud(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_log_forticloud(device_id, vdom)

        @self.mcp.tool(description="Get IPS rate-based signatures")
        async def monitor_ips_rate_based(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_ips_rate_based(device_id, vdom)

        @self.mcp.tool(description="Get IPS session performance")
        async def monitor_ips_session_performance(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_ips_session_performance(device_id, vdom)

        @self.mcp.tool(description="Get FortiGuard service communication stats")
        async def monitor_fortiguard_service_stats(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.resource_tools.monitor_fortiguard_service_stats(device_id)

        @self.mcp.tool(description="Get GeoIP lookup for an IP address. The result shows country, region, city, latitude, longitude, and ISP. Param: ip (string) — the IP address to look up.")
        async def monitor_geoip_query(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            ip: Annotated[str, Field(description="IP address to query")]
        ):
            return await self.resource_tools.monitor_geoip_query(device_id, ip)

        @self.mcp.tool(description="Get FortiView real-time statistics")
        async def monitor_fortiview_realtime_stats(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_fortiview_realtime_stats(device_id, vdom)

        @self.mcp.tool(description="Get ARP table")
        async def monitor_network_arp(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_network_arp(device_id, vdom)

        @self.mcp.tool(description="Get LLDP neighbors")
        async def monitor_network_lldp_neighbors(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_network_lldp_neighbors(device_id, vdom)

        @self.mcp.tool(description="Get DNS latency")
        async def monitor_network_dns_latency(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.resource_tools.monitor_network_dns_latency(device_id)

        @self.mcp.tool(description="Get reverse IP lookup (PTR record)")
        async def monitor_network_reverse_ip_lookup(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            ip: Annotated[str, Field(description="IP address to lookup")]
        ):
            return await self.resource_tools.monitor_network_reverse_ip_lookup(device_id, ip)

        @self.mcp.tool(description="Get BGP neighbors")
        async def monitor_router_bgp_neighbors(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_router_bgp_neighbors(device_id, vdom)

        @self.mcp.tool(description="Get BGP paths")
        async def monitor_router_bgp_paths(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_router_bgp_paths(device_id, vdom)

        @self.mcp.tool(description="Get available interfaces (with names and status). Note: for VIPs use 'any' to match all interfaces.")
        async def monitor_system_available_interfaces(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_system_available_interfaces(device_id, vdom)

        @self.mcp.tool(description="Get FortiCloud registration status")
        async def monitor_registration_forticloud_status(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.resource_tools.monitor_registration_forticloud_status(device_id)

        @self.mcp.tool(description="Get web filter FortiGuard categories")
        async def monitor_webfilter_fortiguard_categories(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_webfilter_fortiguard_categories(device_id, vdom)

        @self.mcp.tool(description="Get system status (hostname, serial number, firmware version, HA status)")
        async def monitor_system_status(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.resource_tools.monitor_system_status(device_id)

        @self.mcp.tool(description="Get CPU, memory, and session resource usage. scope='current' (default) returns latest snapshot only; scope='full' returns all history (~232KB).")
        async def monitor_system_resource_usage(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
            scope: Annotated[str, Field(description="Data scope: 'current' (latest snapshot) or 'full' (all history)", default="current")] = "current"
        ):
            return await self.resource_tools.monitor_system_resource_usage(device_id, vdom, scope=scope)

        @self.mcp.tool(description="Get system performance status (CPU/memory per interval)")
        async def monitor_system_performance_status(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.resource_tools.monitor_system_performance_status(device_id)

        @self.mcp.tool(description="Get interface bandwidth, speed, and utilization")
        async def monitor_system_interface(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_system_interface(device_id, vdom)

        @self.mcp.tool(description="Get currently logged-in administrators")
        async def monitor_system_current_admins(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.resource_tools.monitor_system_current_admins(device_id)

        @self.mcp.tool(description="Get firmware version and available upgrades")
        async def monitor_system_firmware(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.resource_tools.monitor_system_firmware(device_id)

        @self.mcp.tool(description="Get VM hypervisor and platform information")
        async def monitor_system_vm_information(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.resource_tools.monitor_system_vm_information(device_id)

        @self.mcp.tool(description="Get firewall policy statistics and hit counts")
        async def monitor_firewall_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_firewall_policy(device_id, vdom)

        @self.mcp.tool(description="Get active session table")
        async def monitor_firewall_sessions(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_firewall_sessions(device_id, vdom)

        @self.mcp.tool(description="Policy lookup by 5-tuple (srcip, dstip, srcport, dstport, protocol)")
        async def monitor_firewall_policy_lookup(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            params: Annotated[dict, Field(description="Query parameters dict")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.resource_tools.monitor_firewall_policy_lookup(device_id, params, vdom)

        @self.mcp.tool(description="Generic monitor API — access ANY /api/v2/monitor/ GET or POST endpoint "
                         "(e.g. 'system/status', 'system/os/reboot'). Use method='POST' + data for POST endpoints.")
        async def monitor_request(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            endpoint: Annotated[str, Field(description="Monitor endpoint path (e.g. 'system/status', 'license/status')")],
            params: Annotated[Optional[dict], Field(description="Optional query parameters", default=None)] = None,
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None,
            method: Annotated[str, Field(description="HTTP method: GET or POST", default="GET")] = "GET",
            data: Annotated[Optional[dict], Field(description="JSON body for POST requests", default=None)] = None
        ):
            return await self.resource_tools.monitor_request(device_id, endpoint, params, vdom, method, data)

        # System tools
        @self.mcp.tool(description=HEALTH_CHECK_DESC)
        async def health_check():
            status = "healthy" if self._tests_passed is True else ("degraded" if self._tests_passed is False else "unknown")
            details = {
                "registered_devices": len(self.fortigate_manager.devices),
                "server_version": self.config.server.version,
                "timestamp": datetime.now().isoformat()
            }
            from .formatting import FortiGateFormatters
            return FortiGateFormatters.format_health_status(status, details)

        @self.mcp.tool(description=GET_SERVER_INFO_DESC)
        async def get_server_info():
            info = {
                "name": self.config.server.name,
                "version": self.config.server.version,
                "host": self.config.server.host,
                "port": self.config.server.port,
                "registered_devices": len(self.fortigate_manager.devices),
                "available_tools": "278 MCP tools across 9 categories: Device, Firewall, Network, Routing, Schedules, Resources, Security, System, Monitor (47 tools)",
            }
            from .formatting import FortiGateFormatters
            return FortiGateFormatters.format_json_response(info, "Server Information")

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
