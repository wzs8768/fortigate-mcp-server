"""
FortiGate API management for the MCP server.

This module provides the core FortiGate API integration:
- Device connection management with persistent async HTTP clients
- Authentication handling (API token or basic auth)
- API session management with connection pooling
- Request/response processing
- Error handling and recovery
"""
import json
import re
import time
from typing import Dict, Any, Optional, List
import httpx
import urllib.parse
from ..config.models import FortiGateDeviceConfig, AuthConfig
from .logging import get_logger, log_api_call

class FortiGateAPIError(Exception):
    """Custom exception for FortiGate API errors."""

    def __init__(self, message: str, status_code: Optional[int] = None,
                 device_id: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.device_id = device_id

class FortiGateAPI:
    """FortiGate API client for individual device communication.

    Handles all HTTP communication with a single FortiGate device using
    a persistent async HTTP client with connection pooling:
    - Authentication management
    - Request/response processing
    - Error handling and retries
    - Session management
    """

    def __init__(self, device_id: str, config: FortiGateDeviceConfig):
        """Initialize FortiGate API client.

        Args:
            device_id: Unique identifier for this device
            config: Device configuration including connection details
        """
        self.device_id = device_id
        self.config = config
        self.logger = get_logger(f"device.{device_id}")

        # Build base URL
        self.base_url = f"https://{config.host}:{config.port}/api/v2"

        # Setup authentication headers
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        if config.api_token:
            self.headers["Authorization"] = f"Bearer {config.api_token}"
            self.auth_method = "token"
            if config.password:
                self.logger.warning(  # F6: warn when both are configured
                    f"Device {device_id}: Both api_token and password are configured. "
                    f"Using token; password will be ignored."
                )
        elif config.username and config.password:
            self.auth_method = "basic"
            self._basic_auth = (config.username, config.password)
        else:
            raise ValueError(f"Device {device_id}: Either api_token or username/password must be provided")

        if not config.verify_ssl:
            self.logger.warning(f"SSL verification disabled for device {device_id} - NOT recommended for production")

        # Create persistent async HTTP client with connection pooling
        self._client = httpx.AsyncClient(
            verify=config.verify_ssl,
            timeout=config.timeout,
            headers=self.headers,
            auth=(config.username, config.password) if self.auth_method == "basic" else None,
        )

        self.logger.info(f"Initialized FortiGate API client (auth: {self.auth_method})")

    async def close(self):
        """Close the underlying HTTP client and release connection pool resources."""
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        vdom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Make HTTP request to FortiGate API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path (without /api/v2 prefix)
            params: Query parameters
            data: Request body data
            vdom: Virtual Domain (uses device default if not specified)

        Returns:
            API response as dictionary

        Raises:
            FortiGateAPIError: If API request fails
        """
        # Build URL
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        # Setup parameters
        if not params:
            params = {}
        params["vdom"] = vdom or self.config.vdom

        start_time = time.time()

        try:
            response = await self._client.request(
                method=method,
                url=url,
                params=params,
                json=data if data else None
            )

            duration_ms = (time.time() - start_time) * 1000
            log_api_call(self.logger, method, endpoint, response.status_code, duration_ms)

            # Handle error responses
            if response.status_code >= 400:
                error_msg = f"API request failed: {response.status_code}"
                try:
                    error_data = response.json()
                    # I4: include all FortiOS error fields for better diagnostics
                    detail_parts = []
                    if "error" in error_data:
                        detail_parts.append(f"error={error_data['error']}")
                    if "cli_error" in error_data:
                        detail_parts.append(f"cli_error={error_data['cli_error']}")
                    if "http_status_text" in error_data:
                        detail_parts.append(f"http_status={error_data['http_status_text']}")
                    if detail_parts:
                        error_msg += f" - {', '.join(detail_parts)}"
                    elif isinstance(error_data, dict):
                        error_msg += f" - {json.dumps(error_data)}"
                except Exception:
                    error_msg += f" - {response.text}"

                raise FortiGateAPIError(
                    error_msg,
                    status_code=response.status_code,
                    device_id=self.device_id
                )

            # Parse response
            try:
                return response.json()
            except json.JSONDecodeError:
                # Some endpoints may return empty responses
                return {"status": "success"}

        except httpx.RequestError as e:
            duration_ms = (time.time() - start_time) * 1000
            log_api_call(self.logger, method, endpoint, None, duration_ms)
            raise FortiGateAPIError(
                f"Network error: {str(e)}",
                device_id=self.device_id
            )

    async def test_connection(self) -> bool:
        """Test connection to FortiGate device.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            await self.get_system_status()
            return True
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False

    async def cmdb_request(
        self,
        method: str,
        path: str,
        name: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        vdom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generic CMDB request for any FortiOS configuration endpoint.

        This is the universal entry point for ALL CMDB operations, covering
        every endpoint in the FortiOS 8.0 Configuration API (1023+ endpoints).

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            path: CMDB path, e.g. "firewall/address", "router/bgp", "system/dns"
            name: Resource name/ID for single-resource operations
            data: Request body for POST/PUT
            vdom: Virtual Domain

        Examples:
            # List all firewall addresses
            api.cmdb_request("GET", "firewall/address")

            # Get specific address
            api.cmdb_request("GET", "firewall/address", name="10.0.0.0/24")

            # Create address
            api.cmdb_request("POST", "firewall/address", data={"name": "...", "type": "ipmask", ...})

            # Update address
            api.cmdb_request("PUT", "firewall/address", name="10.0.0.0/24", data={...})

            # Delete address
            api.cmdb_request("DELETE", "firewall/address", name="10.0.0.0/24")

            # Get BGP config
            api.cmdb_request("GET", "router/bgp")

            # Update DNS settings
            api.cmdb_request("PUT", "system/dns", data={...})
        """
        # S3: validate path to prevent traversal attacks
        clean_path = path.strip('/')
        if '..' in clean_path:
            raise ValueError(f"Invalid CMDB path: {path} — path traversal not allowed")
        if not re.match(r'^[a-z][a-z0-9._/-]*$', clean_path):
            raise ValueError(f"Invalid CMDB path: {path} — only lowercase alphanumeric, ., _, -, / allowed")
        if name:
            encoded = urllib.parse.quote(name, safe='')
            endpoint = f"cmdb/{clean_path}/{encoded}"
        else:
            endpoint = f"cmdb/{clean_path}"
        return await self._make_request(method, endpoint, data=data, vdom=vdom)

    # System endpoints
    async def get_system_status(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get system status information."""
        return await self._make_request("GET", "monitor/system/status", vdom=vdom)

    async def get_system_interface(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get system interface information."""
        return await self._make_request("GET", "monitor/system/interface", vdom=vdom)

    async def get_vdoms(self) -> Dict[str, Any]:
        """Get list of Virtual Domains."""
        return await self._make_request("GET", "cmdb/system/vdom")

    # Interface endpoints
    async def get_interfaces(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get interface configuration."""
        return await self._make_request("GET", "cmdb/system/interface", vdom=vdom)

    async def update_interface(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update interface configuration."""
        return await self._make_request("PUT", f"cmdb/system/interface/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def get_interface_status(self, interface_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get specific interface status."""
        # FortiOS monitor/system/interface may return all interfaces regardless
        # of query param. Filter client-side to match the requested interface.
        data = await self._make_request("GET", "monitor/system/interface", vdom=vdom,
                                         params={"interface_name": interface_name})
        # If API returns a list/array of interfaces, pick the matching one
        results = data.get("results", [])
        if isinstance(results, list) and len(results) > 0:
            for iface in results:
                if iface.get("name") == interface_name:
                    return iface
            # If not found by exact name, return empty dict
            return {"error": f"Interface '{interface_name}' not found"}
        # If data is already a single interface dict, return as-is
        return data

    # Firewall policy endpoints
    async def get_firewall_policies(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get firewall policies."""
        return await self._make_request("GET", "cmdb/firewall/policy", vdom=vdom)

    async def create_firewall_policy(self, policy_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new firewall policy."""
        return await self._make_request("POST", "cmdb/firewall/policy", data=policy_data, vdom=vdom)

    async def update_firewall_policy(self, policy_id: str, policy_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing firewall policy."""
        encoded_id = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/policy/{encoded_id}", data=policy_data, vdom=vdom)

    async def get_firewall_policy_detail(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific firewall policy."""
        encoded_id = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("GET", f"cmdb/firewall/policy/{encoded_id}", vdom=vdom)

    async def delete_firewall_policy(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete firewall policy."""
        encoded_id = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/policy/{encoded_id}", vdom=vdom)

    # Address object endpoints
    async def get_address_objects(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get address objects."""
        return await self._make_request("GET", "cmdb/firewall/address", vdom=vdom)

    async def create_address_object(self, address_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new address object."""
        return await self._make_request("POST", "cmdb/firewall/address", data=address_data, vdom=vdom)

    async def update_address_object(self, address_name: str, address_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing address object."""
        encoded_name = urllib.parse.quote(address_name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/address/{encoded_name}", data=address_data, vdom=vdom)

    async def delete_address_object(self, address_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete address object."""
        encoded_name = urllib.parse.quote(address_name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/address/{encoded_name}", vdom=vdom)

    # Service object endpoints
    async def get_service_objects(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get service objects."""
        return await self._make_request("GET", "cmdb/firewall.service/custom", vdom=vdom)

    async def create_service_object(self, service_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new service object."""
        return await self._make_request("POST", "cmdb/firewall.service/custom", data=service_data, vdom=vdom)

    async def update_service_object(self, service_name: str, service_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing service object."""
        encoded_name = urllib.parse.quote(service_name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall.service/custom/{encoded_name}", data=service_data, vdom=vdom)

    async def delete_service_object(self, service_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete service object."""
        encoded_name = urllib.parse.quote(service_name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall.service/custom/{encoded_name}", vdom=vdom)

    # Routing endpoints
    async def get_static_routes(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get static routes."""
        return await self._make_request("GET", "cmdb/router/static", vdom=vdom)

    async def create_static_route(self, route_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new static route."""
        return await self._make_request("POST", "cmdb/router/static", data=route_data, vdom=vdom)

    async def update_static_route(self, route_id: str, route_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing static route."""
        encoded_id = urllib.parse.quote(route_id, safe='')
        return await self._make_request("PUT", f"cmdb/router/static/{encoded_id}", data=route_data, vdom=vdom)

    async def delete_static_route(self, route_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete static route."""
        encoded_id = urllib.parse.quote(route_id, safe='')
        return await self._make_request("DELETE", f"cmdb/router/static/{encoded_id}", vdom=vdom)

    async def get_static_route_detail(self, route_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific static route."""
        encoded_id = urllib.parse.quote(route_id, safe='')
        return await self._make_request("GET", f"cmdb/router/static/{encoded_id}", vdom=vdom)

    async def get_routing_table(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get routing table."""
        return await self._make_request("GET", "monitor/router/ipv4", vdom=vdom)

    # Virtual IP endpoints
    async def get_virtual_ips(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get virtual IPs."""
        return await self._make_request("GET", "cmdb/firewall/vip", vdom=vdom)

    async def create_virtual_ip(self, vip_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new virtual IP."""
        return await self._make_request("POST", "cmdb/firewall/vip", data=vip_data, vdom=vdom)

    async def update_virtual_ip(self, vip_name: str, vip_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing virtual IP."""
        encoded_name = urllib.parse.quote(vip_name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/vip/{encoded_name}", data=vip_data, vdom=vdom)

    async def delete_virtual_ip(self, vip_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete virtual IP."""
        encoded_name = urllib.parse.quote(vip_name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/vip/{encoded_name}", vdom=vdom)

    async def get_virtual_ip_detail(self, vip_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific virtual IP."""
        encoded_name = urllib.parse.quote(vip_name, safe='')
        return await self._make_request("GET", f"cmdb/firewall/vip/{encoded_name}", vdom=vdom)

    # ============================================================
    # Address Group endpoints
    # ============================================================
    async def get_addrgrps(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get address groups."""
        return await self._make_request("GET", "cmdb/firewall/addrgrp", vdom=vdom)

    async def create_addrgrp(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new address group."""
        return await self._make_request("POST", "cmdb/firewall/addrgrp", data=data, vdom=vdom)

    async def update_addrgrp(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing address group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/addrgrp/{encoded}", data=data, vdom=vdom)

    async def delete_addrgrp(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete address group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/addrgrp/{encoded}", vdom=vdom)

    async def get_addrgrp_detail(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get address group detail."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("GET", f"cmdb/firewall/addrgrp/{encoded}", vdom=vdom)

    # Address6 endpoints
    async def get_address6_objects(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get IPv6 address objects."""
        return await self._make_request("GET", "cmdb/firewall/address6", vdom=vdom)

    async def create_address6(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new IPv6 address object."""
        return await self._make_request("POST", "cmdb/firewall/address6", data=data, vdom=vdom)

    async def update_address6(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing IPv6 address object."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/address6/{encoded}", data=data, vdom=vdom)

    async def delete_address6(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete IPv6 address object."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/address6/{encoded}", vdom=vdom)

    # Addrgrp6 endpoints
    async def get_addrgrp6(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get IPv6 address groups."""
        return await self._make_request("GET", "cmdb/firewall/addrgrp6", vdom=vdom)

    async def create_addrgrp6(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new IPv6 address group."""
        return await self._make_request("POST", "cmdb/firewall/addrgrp6", data=data, vdom=vdom)

    async def update_addrgrp6(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing IPv6 address group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/addrgrp6/{encoded}", data=data, vdom=vdom)

    async def delete_addrgrp6(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete IPv6 address group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/addrgrp6/{encoded}", vdom=vdom)

    # Service Group endpoints
    async def get_service_groups(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get service groups."""
        return await self._make_request("GET", "cmdb/firewall.service/group", vdom=vdom)

    async def create_service_group(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new service group."""
        return await self._make_request("POST", "cmdb/firewall.service/group", data=data, vdom=vdom)

    async def update_service_group(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing service group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall.service/group/{encoded}", data=data, vdom=vdom)

    async def delete_service_group(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete service group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall.service/group/{encoded}", vdom=vdom)

    # Schedule endpoints
    async def get_schedule_onetime(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get onetime schedules."""
        return await self._make_request("GET", "cmdb/firewall.schedule/onetime", vdom=vdom)

    async def create_schedule_onetime(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new onetime schedule."""
        return await self._make_request("POST", "cmdb/firewall.schedule/onetime", data=data, vdom=vdom)

    async def update_schedule_onetime(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing onetime schedule."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall.schedule/onetime/{encoded}", data=data, vdom=vdom)

    async def delete_schedule_onetime(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete onetime schedule."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall.schedule/onetime/{encoded}", vdom=vdom)

    async def get_schedule_recurring(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get recurring schedules."""
        return await self._make_request("GET", "cmdb/firewall.schedule/recurring", vdom=vdom)

    async def create_schedule_recurring(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new recurring schedule."""
        return await self._make_request("POST", "cmdb/firewall.schedule/recurring", data=data, vdom=vdom)

    async def update_schedule_recurring(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing recurring schedule."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall.schedule/recurring/{encoded}", data=data, vdom=vdom)

    async def delete_schedule_recurring(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete recurring schedule."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall.schedule/recurring/{encoded}", vdom=vdom)

    async def get_schedule_group(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get schedule groups."""
        return await self._make_request("GET", "cmdb/firewall.schedule/group", vdom=vdom)

    async def create_schedule_group(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new schedule group."""
        return await self._make_request("POST", "cmdb/firewall.schedule/group", data=data, vdom=vdom)

    async def update_schedule_group(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing schedule group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall.schedule/group/{encoded}", data=data, vdom=vdom)

    async def delete_schedule_group(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete schedule group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall.schedule/group/{encoded}", vdom=vdom)

    # VIP Group endpoints
    async def get_vipgrps(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get VIP groups."""
        return await self._make_request("GET", "cmdb/firewall/vipgrp", vdom=vdom)

    async def create_vipgrp(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new VIP group."""
        return await self._make_request("POST", "cmdb/firewall/vipgrp", data=data, vdom=vdom)

    async def update_vipgrp(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing VIP group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/vipgrp/{encoded}", data=data, vdom=vdom)

    async def delete_vipgrp(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete VIP group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/vipgrp/{encoded}", vdom=vdom)

    # IP Pool endpoints
    async def get_ippools(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get IP pools."""
        return await self._make_request("GET", "cmdb/firewall/ippool", vdom=vdom)

    async def create_ippool(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new IP pool."""
        return await self._make_request("POST", "cmdb/firewall/ippool", data=data, vdom=vdom)

    async def update_ippool(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing IP pool."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/ippool/{encoded}", data=data, vdom=vdom)

    async def delete_ippool(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete IP pool."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/ippool/{encoded}", vdom=vdom)

    # Wildcard FQDN endpoints
    async def get_wildcard_fqdn_custom(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get wildcard FQDN custom entries."""
        return await self._make_request("GET", "cmdb/firewall.wildcard-fqdn/custom", vdom=vdom)

    async def create_wildcard_fqdn_custom(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new wildcard FQDN custom entry."""
        return await self._make_request("POST", "cmdb/firewall.wildcard-fqdn/custom", data=data, vdom=vdom)

    async def update_wildcard_fqdn_custom(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing wildcard FQDN custom entry."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall.wildcard-fqdn/custom/{encoded}", data=data, vdom=vdom)

    async def delete_wildcard_fqdn_custom(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete wildcard FQDN custom entry."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall.wildcard-fqdn/custom/{encoded}", vdom=vdom)

    async def get_wildcard_fqdn_group(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get wildcard FQDN groups."""
        return await self._make_request("GET", "cmdb/firewall.wildcard-fqdn/group", vdom=vdom)

    async def create_wildcard_fqdn_group(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new wildcard FQDN group."""
        return await self._make_request("POST", "cmdb/firewall.wildcard-fqdn/group", data=data, vdom=vdom)

    async def update_wildcard_fqdn_group(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing wildcard FQDN group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall.wildcard-fqdn/group/{encoded}", data=data, vdom=vdom)

    async def delete_wildcard_fqdn_group(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete wildcard FQDN group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall.wildcard-fqdn/group/{encoded}", vdom=vdom)

    # Traffic Shaper endpoints
    async def get_traffic_shapers(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get traffic shapers."""
        return await self._make_request("GET", "cmdb/firewall.shaper/traffic-shaper", vdom=vdom)

    async def create_traffic_shaper(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new traffic shaper."""
        return await self._make_request("POST", "cmdb/firewall.shaper/traffic-shaper", data=data, vdom=vdom)

    async def update_traffic_shaper(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing traffic shaper."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall.shaper/traffic-shaper/{encoded}", data=data, vdom=vdom)

    async def delete_traffic_shaper(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete traffic shaper."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall.shaper/traffic-shaper/{encoded}", vdom=vdom)

    async def get_per_ip_shapers(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get per-IP traffic shapers."""
        return await self._make_request("GET", "cmdb/firewall.shaper/per-ip-shaper", vdom=vdom)

    async def create_per_ip_shaper(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new per-IP traffic shaper."""
        return await self._make_request("POST", "cmdb/firewall.shaper/per-ip-shaper", data=data, vdom=vdom)

    async def update_per_ip_shaper(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing per-IP traffic shaper."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall.shaper/per-ip-shaper/{encoded}", data=data, vdom=vdom)

    async def delete_per_ip_shaper(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete per-IP traffic shaper."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall.shaper/per-ip-shaper/{encoded}", vdom=vdom)

    # Central SNAT Map endpoints
    async def get_central_snat_maps(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get central SNAT maps."""
        return await self._make_request("GET", "cmdb/firewall/central-snat-map", vdom=vdom)

    async def create_central_snat_map(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new central SNAT map."""
        return await self._make_request("POST", "cmdb/firewall/central-snat-map", data=data, vdom=vdom)

    async def update_central_snat_map(self, policy_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing central SNAT map."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/central-snat-map/{encoded}", data=data, vdom=vdom)

    async def delete_central_snat_map(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete central SNAT map."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/central-snat-map/{encoded}", vdom=vdom)

    async def get_central_snat_map_detail(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get central SNAT map detail."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("GET", f"cmdb/firewall/central-snat-map/{encoded}", vdom=vdom)

    # Security Policy endpoints (NGFW policy-based mode)
    async def get_security_policies(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get security policies."""
        return await self._make_request("GET", "cmdb/firewall/security-policy", vdom=vdom)

    async def create_security_policy(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new security policy."""
        return await self._make_request("POST", "cmdb/firewall/security-policy", data=data, vdom=vdom)

    async def update_security_policy(self, policy_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing security policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/security-policy/{encoded}", data=data, vdom=vdom)

    async def delete_security_policy(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete security policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/security-policy/{encoded}", vdom=vdom)

    async def get_security_policy_detail(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get security policy detail."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("GET", f"cmdb/firewall/security-policy/{encoded}", vdom=vdom)

    # Proxy Policy endpoints
    async def get_proxy_policies(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get proxy policies."""
        return await self._make_request("GET", "cmdb/firewall/proxy-policy", vdom=vdom)

    async def create_proxy_policy(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new proxy policy."""
        return await self._make_request("POST", "cmdb/firewall/proxy-policy", data=data, vdom=vdom)

    async def update_proxy_policy(self, policy_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing proxy policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/proxy-policy/{encoded}", data=data, vdom=vdom)

    async def delete_proxy_policy(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete proxy policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/proxy-policy/{encoded}", vdom=vdom)

    async def get_proxy_policy_detail(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get proxy policy detail."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("GET", f"cmdb/firewall/proxy-policy/{encoded}", vdom=vdom)

    # Proxy Address endpoints
    async def get_proxy_addresses(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get proxy addresses."""
        return await self._make_request("GET", "cmdb/firewall/proxy-address", vdom=vdom)

    async def create_proxy_address(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new proxy address."""
        return await self._make_request("POST", "cmdb/firewall/proxy-address", data=data, vdom=vdom)

    async def update_proxy_address(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing proxy address."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/proxy-address/{encoded}", data=data, vdom=vdom)

    async def delete_proxy_address(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete proxy address."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/proxy-address/{encoded}", vdom=vdom)

    # Proxy Address Group endpoints
    async def get_proxy_addrgrps(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get proxy address groups."""
        return await self._make_request("GET", "cmdb/firewall/proxy-addrgrp", vdom=vdom)

    async def create_proxy_addrgrp(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new proxy address group."""
        return await self._make_request("POST", "cmdb/firewall/proxy-addrgrp", data=data, vdom=vdom)

    async def update_proxy_addrgrp(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing proxy address group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/proxy-addrgrp/{encoded}", data=data, vdom=vdom)

    async def delete_proxy_addrgrp(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete proxy address group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/proxy-addrgrp/{encoded}", vdom=vdom)

    # Shaping Policy endpoints
    async def get_shaping_policies(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get shaping policies."""
        return await self._make_request("GET", "cmdb/firewall/shaping-policy", vdom=vdom)

    async def create_shaping_policy(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new shaping policy."""
        return await self._make_request("POST", "cmdb/firewall/shaping-policy", data=data, vdom=vdom)

    async def update_shaping_policy(self, policy_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing shaping policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/shaping-policy/{encoded}", data=data, vdom=vdom)

    async def delete_shaping_policy(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete shaping policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/shaping-policy/{encoded}", vdom=vdom)

    # Shaping Profile endpoints
    async def get_shaping_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get shaping profiles."""
        return await self._make_request("GET", "cmdb/firewall/shaping-profile", vdom=vdom)

    async def create_shaping_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new shaping profile."""
        return await self._make_request("POST", "cmdb/firewall/shaping-profile", data=data, vdom=vdom)

    async def update_shaping_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing shaping profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/shaping-profile/{encoded}", data=data, vdom=vdom)

    async def delete_shaping_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete shaping profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/shaping-profile/{encoded}", vdom=vdom)

    # DoS Policy endpoints
    async def get_dos_policies(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get DoS policies."""
        return await self._make_request("GET", "cmdb/firewall/DoS-policy", vdom=vdom)

    async def create_dos_policy(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new DoS policy."""
        return await self._make_request("POST", "cmdb/firewall/DoS-policy", data=data, vdom=vdom)

    async def update_dos_policy(self, policy_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing DoS policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/DoS-policy/{encoded}", data=data, vdom=vdom)

    async def delete_dos_policy(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete DoS policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/DoS-policy/{encoded}", vdom=vdom)

    # Local-in Policy endpoints
    async def get_local_in_policies(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get local-in policies."""
        return await self._make_request("GET", "cmdb/firewall/local-in-policy", vdom=vdom)

    async def create_local_in_policy(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new local-in policy."""
        return await self._make_request("POST", "cmdb/firewall/local-in-policy", data=data, vdom=vdom)

    async def update_local_in_policy(self, policy_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing local-in policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/local-in-policy/{encoded}", data=data, vdom=vdom)

    async def delete_local_in_policy(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete local-in policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/local-in-policy/{encoded}", vdom=vdom)

    # Interface Policy endpoints
    async def get_interface_policies(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get interface policies."""
        return await self._make_request("GET", "cmdb/firewall/interface-policy", vdom=vdom)

    async def create_interface_policy(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new interface policy."""
        return await self._make_request("POST", "cmdb/firewall/interface-policy", data=data, vdom=vdom)

    async def update_interface_policy(self, policy_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing interface policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/interface-policy/{encoded}", data=data, vdom=vdom)

    async def delete_interface_policy(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete interface policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/interface-policy/{encoded}", vdom=vdom)

    # Multicast Policy endpoints
    async def get_multicast_policies(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get multicast policies."""
        return await self._make_request("GET", "cmdb/firewall/multicast-policy", vdom=vdom)

    async def create_multicast_policy(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new multicast policy."""
        return await self._make_request("POST", "cmdb/firewall/multicast-policy", data=data, vdom=vdom)

    async def update_multicast_policy(self, policy_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing multicast policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/multicast-policy/{encoded}", data=data, vdom=vdom)

    async def delete_multicast_policy(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete multicast policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/multicast-policy/{encoded}", vdom=vdom)

    # Multicast Address endpoints
    async def get_multicast_addresses(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get multicast addresses."""
        return await self._make_request("GET", "cmdb/firewall/multicast-address", vdom=vdom)

    async def create_multicast_address(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new multicast address."""
        return await self._make_request("POST", "cmdb/firewall/multicast-address", data=data, vdom=vdom)

    async def update_multicast_address(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing multicast address."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/multicast-address/{encoded}", data=data, vdom=vdom)

    async def delete_multicast_address(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete multicast address."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/multicast-address/{encoded}", vdom=vdom)

    # Sniffer endpoints
    async def get_sniffers(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get sniffers."""
        return await self._make_request("GET", "cmdb/firewall/sniffer", vdom=vdom)

    async def create_sniffer(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new sniffer."""
        return await self._make_request("POST", "cmdb/firewall/sniffer", data=data, vdom=vdom)

    async def update_sniffer(self, sniffer_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing sniffer."""
        encoded = urllib.parse.quote(sniffer_id, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/sniffer/{encoded}", data=data, vdom=vdom)

    async def delete_sniffer(self, sniffer_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete sniffer."""
        encoded = urllib.parse.quote(sniffer_id, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/sniffer/{encoded}", vdom=vdom)

    # IP Translation endpoints
    async def get_ip_translations(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get IP translations."""
        return await self._make_request("GET", "cmdb/firewall/ip-translation", vdom=vdom)

    async def create_ip_translation(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new IP translation."""
        return await self._make_request("POST", "cmdb/firewall/ip-translation", data=data, vdom=vdom)

    async def update_ip_translation(self, trans_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing IP translation."""
        encoded = urllib.parse.quote(trans_id, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/ip-translation/{encoded}", data=data, vdom=vdom)

    async def delete_ip_translation(self, trans_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete IP translation."""
        encoded = urllib.parse.quote(trans_id, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/ip-translation/{encoded}", vdom=vdom)

    # Identity-based Route endpoints
    async def get_identity_based_routes(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get identity-based routes."""
        return await self._make_request("GET", "cmdb/firewall/identity-based-route", vdom=vdom)

    async def create_identity_based_route(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new identity-based route."""
        return await self._make_request("POST", "cmdb/firewall/identity-based-route", data=data, vdom=vdom)

    async def update_identity_based_route(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing identity-based route."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/identity-based-route/{encoded}", data=data, vdom=vdom)

    async def delete_identity_based_route(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete identity-based route."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/identity-based-route/{encoded}", vdom=vdom)

    # SSL/SSH Profile endpoints
    async def get_ssl_ssh_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get SSL/SSH profiles."""
        return await self._make_request("GET", "cmdb/firewall/ssl-ssh-profile", vdom=vdom)

    async def create_ssl_ssh_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new SSL/SSH profile."""
        return await self._make_request("POST", "cmdb/firewall/ssl-ssh-profile", data=data, vdom=vdom)

    async def update_ssl_ssh_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing SSL/SSH profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/ssl-ssh-profile/{encoded}", data=data, vdom=vdom)

    async def delete_ssl_ssh_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete SSL/SSH profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/ssl-ssh-profile/{encoded}", vdom=vdom)

    # SSL Server endpoints
    async def get_ssl_servers(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get SSL servers."""
        return await self._make_request("GET", "cmdb/firewall/ssl-server", vdom=vdom)

    async def create_ssl_server(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new SSL server."""
        return await self._make_request("POST", "cmdb/firewall/ssl-server", data=data, vdom=vdom)

    async def update_ssl_server(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing SSL server."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/ssl-server/{encoded}", data=data, vdom=vdom)

    async def delete_ssl_server(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete SSL server."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/ssl-server/{encoded}", vdom=vdom)

    # Profile Group endpoints
    async def get_profile_groups(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get profile groups."""
        return await self._make_request("GET", "cmdb/firewall/profile-group", vdom=vdom)

    async def create_profile_group(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new profile group."""
        return await self._make_request("POST", "cmdb/firewall/profile-group", data=data, vdom=vdom)

    async def update_profile_group(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing profile group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/profile-group/{encoded}", data=data, vdom=vdom)

    async def delete_profile_group(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete profile group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/profile-group/{encoded}", vdom=vdom)

    # Profile Protocol Options endpoints
    async def get_profile_protocol_options(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get profile protocol options."""
        return await self._make_request("GET", "cmdb/firewall/profile-protocol-options", vdom=vdom)

    async def create_profile_protocol_options(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new profile protocol options."""
        return await self._make_request("POST", "cmdb/firewall/profile-protocol-options", data=data, vdom=vdom)

    async def update_profile_protocol_options(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing profile protocol options."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/profile-protocol-options/{encoded}", data=data, vdom=vdom)

    async def delete_profile_protocol_options(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete profile protocol options."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/profile-protocol-options/{encoded}", vdom=vdom)

    # Firewall Global settings
    async def get_firewall_global(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get firewall global settings."""
        return await self._make_request("GET", "cmdb/firewall/global", vdom=vdom)

    async def update_firewall_global(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update firewall global settings."""
        return await self._make_request("PUT", "cmdb/firewall/global", data=data, vdom=vdom)

    # IPS Sensor endpoints
    async def get_ips_sensors(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get IPS sensors."""
        return await self._make_request("GET", "cmdb/ips/sensor", vdom=vdom)

    async def create_ips_sensor(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new IPS sensor."""
        return await self._make_request("POST", "cmdb/ips/sensor", data=data, vdom=vdom)

    async def update_ips_sensor(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing IPS sensor."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/ips/sensor/{encoded}", data=data, vdom=vdom)

    async def delete_ips_sensor(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete IPS sensor."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/ips/sensor/{encoded}", vdom=vdom)

    async def get_ips_sensor_detail(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get IPS sensor detail."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("GET", f"cmdb/ips/sensor/{encoded}", vdom=vdom)

    # Log Settings endpoints
    async def get_log_setting(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get log settings."""
        return await self._make_request("GET", "cmdb/log/setting", vdom=vdom)

    async def update_log_setting(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update log settings."""
        return await self._make_request("PUT", "cmdb/log/setting", data=data, vdom=vdom)

    async def get_log_disk_setting(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get log disk settings."""
        return await self._make_request("GET", "cmdb/log.disk/setting", vdom=vdom)

    async def update_log_disk_setting(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update log disk settings."""
        return await self._make_request("PUT", "cmdb/log.disk/setting", data=data, vdom=vdom)

    async def get_log_fortianalyzer_setting(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get FortiAnalyzer log settings."""
        return await self._make_request("GET", "cmdb/log.fortianalyzer/setting", vdom=vdom)

    async def update_log_fortianalyzer_setting(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update FortiAnalyzer log settings."""
        return await self._make_request("PUT", "cmdb/log.fortianalyzer/setting", data=data, vdom=vdom)

    async def get_log_syslogd_setting(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get syslog settings."""
        return await self._make_request("GET", "cmdb/log.syslogd/setting", vdom=vdom)

    async def update_log_syslogd_setting(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update syslog settings."""
        return await self._make_request("PUT", "cmdb/log.syslogd/setting", data=data, vdom=vdom)

    # Decrypted Traffic Mirror endpoints
    async def get_decrypted_traffic_mirrors(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get decrypted traffic mirrors."""
        return await self._make_request("GET", "cmdb/firewall/decrypted-traffic-mirror", vdom=vdom)

    async def create_decrypted_traffic_mirror(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new decrypted traffic mirror."""
        return await self._make_request("POST", "cmdb/firewall/decrypted-traffic-mirror", data=data, vdom=vdom)

    async def update_decrypted_traffic_mirror(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing decrypted traffic mirror."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/decrypted-traffic-mirror/{encoded}", data=data, vdom=vdom)

    async def delete_decrypted_traffic_mirror(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete decrypted traffic mirror."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/decrypted-traffic-mirror/{encoded}", vdom=vdom)

    # DNS Translation endpoints
    async def get_dns_translations(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get DNS translations."""
        return await self._make_request("GET", "cmdb/firewall/dnstranslation", vdom=vdom)

    async def create_dns_translation(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new DNS translation."""
        return await self._make_request("POST", "cmdb/firewall/dnstranslation", data=data, vdom=vdom)

    async def update_dns_translation(self, translation_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing DNS translation."""
        encoded = urllib.parse.quote(translation_id, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/dnstranslation/{encoded}", data=data, vdom=vdom)

    async def delete_dns_translation(self, translation_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete DNS translation."""
        encoded = urllib.parse.quote(translation_id, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/dnstranslation/{encoded}", vdom=vdom)

    # TTL Policy endpoints
    async def get_ttl_policies(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get TTL policies."""
        return await self._make_request("GET", "cmdb/firewall/ttl-policy", vdom=vdom)

    async def create_ttl_policy(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new TTL policy."""
        return await self._make_request("POST", "cmdb/firewall/ttl-policy", data=data, vdom=vdom)

    async def update_ttl_policy(self, policy_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing TTL policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("PUT", f"cmdb/firewall/ttl-policy/{encoded}", data=data, vdom=vdom)

    async def delete_ttl_policy(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete TTL policy."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("DELETE", f"cmdb/firewall/ttl-policy/{encoded}", vdom=vdom)

    # ============================================================
    # Authentication endpoints
    # ============================================================
    async def get_auth_rules(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get authentication rules."""
        return await self._make_request("GET", "cmdb/authentication/rule", vdom=vdom)

    async def create_auth_rule(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create auth rule."""
        return await self._make_request("POST", "cmdb/authentication/rule", data=data, vdom=vdom)

    async def update_auth_rule(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update auth rule."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/authentication/rule/{encoded}", data=data, vdom=vdom)

    async def delete_auth_rule(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete auth rule."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/authentication/rule/{encoded}", vdom=vdom)

    async def get_auth_schemes(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get authentication schemes."""
        return await self._make_request("GET", "cmdb/authentication/scheme", vdom=vdom)

    async def create_auth_scheme(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create auth scheme."""
        return await self._make_request("POST", "cmdb/authentication/scheme", data=data, vdom=vdom)

    async def update_auth_scheme(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update auth scheme."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/authentication/scheme/{encoded}", data=data, vdom=vdom)

    async def delete_auth_scheme(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete auth scheme."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/authentication/scheme/{encoded}", vdom=vdom)

    async def get_auth_setting(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get authentication settings."""
        return await self._make_request("GET", "cmdb/authentication/setting", vdom=vdom)

    async def update_auth_setting(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update authentication settings."""
        return await self._make_request("PUT", "cmdb/authentication/setting", data=data, vdom=vdom)

    # ============================================================
    # Certificate endpoints
    # ============================================================
    async def get_certificate_ca(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get CA certificates."""
        return await self._make_request("GET", "cmdb/certificate/ca", vdom=vdom)

    async def update_certificate_ca(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update CA certificates."""
        return await self._make_request("PUT", "cmdb/certificate/ca", data=data, vdom=vdom)

    async def get_certificate_local(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get local certificates."""
        return await self._make_request("GET", "cmdb/certificate/local", vdom=vdom)

    async def update_certificate_local(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update local certificates."""
        return await self._make_request("PUT", "cmdb/certificate/local", data=data, vdom=vdom)

    async def get_certificate_remote(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get remote certificates."""
        return await self._make_request("GET", "cmdb/certificate/remote", vdom=vdom)

    async def update_certificate_remote(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update remote certificates."""
        return await self._make_request("PUT", "cmdb/certificate/remote", data=data, vdom=vdom)

    async def get_certificate_crl(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get certificate CRL."""
        return await self._make_request("GET", "cmdb/certificate/crl", vdom=vdom)

    async def update_certificate_crl(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update certificate CRL."""
        return await self._make_request("PUT", "cmdb/certificate/crl", data=data, vdom=vdom)

    # ============================================================
    # DNS Filter endpoints
    # ============================================================
    async def get_dnsfilter_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get DNS filter profiles."""
        return await self._make_request("GET", "cmdb/dnsfilter/profile", vdom=vdom)

    async def create_dnsfilter_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create DNS filter profile."""
        return await self._make_request("POST", "cmdb/dnsfilter/profile", data=data, vdom=vdom)

    async def update_dnsfilter_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update DNS filter profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/dnsfilter/profile/{encoded}", data=data, vdom=vdom)

    async def delete_dnsfilter_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete DNS filter profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/dnsfilter/profile/{encoded}", vdom=vdom)

    async def get_dnsfilter_domain_filters(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get DNS domain filters."""
        return await self._make_request("GET", "cmdb/dnsfilter/domain-filter", vdom=vdom)

    async def create_dnsfilter_domain_filter(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create DNS domain filter."""
        return await self._make_request("POST", "cmdb/dnsfilter/domain-filter", data=data, vdom=vdom)

    async def update_dnsfilter_domain_filter(self, filt_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update DNS domain filter."""
        encoded = urllib.parse.quote(filt_id, safe='')
        return await self._make_request("PUT", f"cmdb/dnsfilter/domain-filter/{encoded}", data=data, vdom=vdom)

    async def delete_dnsfilter_domain_filter(self, filt_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete DNS domain filter."""
        encoded = urllib.parse.quote(filt_id, safe='')
        return await self._make_request("DELETE", f"cmdb/dnsfilter/domain-filter/{encoded}", vdom=vdom)

    # ============================================================
    # DLP endpoints
    # ============================================================
    async def get_dlp_sensors(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get DLP sensors."""
        return await self._make_request("GET", "cmdb/dlp/sensor", vdom=vdom)

    async def create_dlp_sensor(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create DLP sensor."""
        return await self._make_request("POST", "cmdb/dlp/sensor", data=data, vdom=vdom)

    async def update_dlp_sensor(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update DLP sensor."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/dlp/sensor/{encoded}", data=data, vdom=vdom)

    async def delete_dlp_sensor(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete DLP sensor."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/dlp/sensor/{encoded}", vdom=vdom)

    async def get_dlp_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get DLP profiles."""
        return await self._make_request("GET", "cmdb/dlp/profile", vdom=vdom)

    async def create_dlp_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create DLP profile."""
        return await self._make_request("POST", "cmdb/dlp/profile", data=data, vdom=vdom)

    async def update_dlp_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update DLP profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/dlp/profile/{encoded}", data=data, vdom=vdom)

    async def delete_dlp_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete DLP profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/dlp/profile/{encoded}", vdom=vdom)

    async def get_dlp_settings(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get DLP settings."""
        return await self._make_request("GET", "cmdb/dlp/settings", vdom=vdom)

    async def update_dlp_settings(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update DLP settings."""
        return await self._make_request("PUT", "cmdb/dlp/settings", data=data, vdom=vdom)

    async def get_dlp_filepatterns(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get DLP file patterns."""
        return await self._make_request("GET", "cmdb/dlp/filepattern", vdom=vdom)

    async def create_dlp_filepattern(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create DLP file pattern."""
        return await self._make_request("POST", "cmdb/dlp/filepattern", data=data, vdom=vdom)

    async def update_dlp_filepattern(self, filt_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update DLP file pattern."""
        encoded = urllib.parse.quote(filt_id, safe='')
        return await self._make_request("PUT", f"cmdb/dlp/filepattern/{encoded}", data=data, vdom=vdom)

    async def delete_dlp_filepattern(self, filt_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete DLP file pattern."""
        encoded = urllib.parse.quote(filt_id, safe='')
        return await self._make_request("DELETE", f"cmdb/dlp/filepattern/{encoded}", vdom=vdom)

    # ============================================================
    # Email Filter endpoints
    # ============================================================
    async def get_emailfilter_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get email filter profiles."""
        return await self._make_request("GET", "cmdb/emailfilter/profile", vdom=vdom)

    async def create_emailfilter_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create email filter profile."""
        return await self._make_request("POST", "cmdb/emailfilter/profile", data=data, vdom=vdom)

    async def update_emailfilter_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update email filter profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/emailfilter/profile/{encoded}", data=data, vdom=vdom)

    async def delete_emailfilter_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete email filter profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/emailfilter/profile/{encoded}", vdom=vdom)

    async def get_emailfilter_options(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get email filter options."""
        return await self._make_request("GET", "cmdb/emailfilter/options", vdom=vdom)

    async def update_emailfilter_options(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update email filter options."""
        return await self._make_request("PUT", "cmdb/emailfilter/options", data=data, vdom=vdom)

    # ============================================================
    # Automation endpoints
    # ============================================================
    async def get_automation_setting(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get automation settings."""
        return await self._make_request("GET", "cmdb/automation/setting", vdom=vdom)

    async def update_automation_setting(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update automation settings."""
        return await self._make_request("PUT", "cmdb/automation/setting", data=data, vdom=vdom)

    # ============================================================
    # CASB endpoints
    # ============================================================
    async def get_casb_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get CASB profiles."""
        return await self._make_request("GET", "cmdb/casb/profile", vdom=vdom)

    async def create_casb_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create CASB profile."""
        return await self._make_request("POST", "cmdb/casb/profile", data=data, vdom=vdom)

    async def update_casb_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update CASB profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/casb/profile/{encoded}", data=data, vdom=vdom)

    async def delete_casb_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete CASB profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/casb/profile/{encoded}", vdom=vdom)

    async def get_casb_saas_applications(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get CASB SaaS applications."""
        return await self._make_request("GET", "cmdb/casb/saas-application", vdom=vdom)

    async def create_casb_saas_application(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create CASB SaaS application."""
        return await self._make_request("POST", "cmdb/casb/saas-application", data=data, vdom=vdom)

    async def update_casb_saas_application(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update CASB SaaS application."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/casb/saas-application/{encoded}", data=data, vdom=vdom)

    async def delete_casb_saas_application(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete CASB SaaS application."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/casb/saas-application/{encoded}", vdom=vdom)

    # ============================================================
    # Endpoint Control endpoints
    # ============================================================
    async def get_endpoint_control_settings(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get endpoint control settings."""
        return await self._make_request("GET", "cmdb/endpoint-control/settings", vdom=vdom)

    async def update_endpoint_control_settings(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update endpoint control settings."""
        return await self._make_request("PUT", "cmdb/endpoint-control/settings", data=data, vdom=vdom)

    # ============================================================
    # Diameter Filter endpoints
    # ============================================================
    async def get_diameter_filter_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get diameter filter profiles."""
        return await self._make_request("GET", "cmdb/diameter-filter/profile", vdom=vdom)

    async def create_diameter_filter_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create diameter filter profile."""
        return await self._make_request("POST", "cmdb/diameter-filter/profile", data=data, vdom=vdom)

    async def update_diameter_filter_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update diameter filter profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/diameter-filter/profile/{encoded}", data=data, vdom=vdom)

    async def delete_diameter_filter_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete diameter filter profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/diameter-filter/profile/{encoded}", vdom=vdom)

    # ============================================================
    # Ethernet OAM endpoints
    # ============================================================
    async def get_ethernet_oam_cfm(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get Ethernet OAM CFM configuration."""
        return await self._make_request("GET", "cmdb/ethernet-oam/cfm", vdom=vdom)

    async def create_ethernet_oam_cfm(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create Ethernet OAM CFM."""
        return await self._make_request("POST", "cmdb/ethernet-oam/cfm", data=data, vdom=vdom)

    async def update_ethernet_oam_cfm(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update Ethernet OAM CFM."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/ethernet-oam/cfm/{encoded}", data=data, vdom=vdom)

    async def delete_ethernet_oam_cfm(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete Ethernet OAM CFM."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/ethernet-oam/cfm/{encoded}", vdom=vdom)
    # ============================================================
    # Application Control endpoints
    # ============================================================
    async def get_application_custom(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get custom application signatures."""
        return await self._make_request("GET", "cmdb/application/custom", vdom=vdom)

    async def create_application_custom(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create custom application signature."""
        return await self._make_request("POST", "cmdb/application/custom", data=data, vdom=vdom)

    async def update_application_custom(self, tag: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update custom application signature."""
        encoded = urllib.parse.quote(tag, safe='')
        return await self._make_request("PUT", f"cmdb/application/custom/{encoded}", data=data, vdom=vdom)

    async def delete_application_custom(self, tag: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete custom application signature."""
        encoded = urllib.parse.quote(tag, safe='')
        return await self._make_request("DELETE", f"cmdb/application/custom/{encoded}", vdom=vdom)

    async def get_application_groups(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get application groups."""
        return await self._make_request("GET", "cmdb/application/group", vdom=vdom)

    async def create_application_group(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create application group."""
        return await self._make_request("POST", "cmdb/application/group", data=data, vdom=vdom)

    async def update_application_group(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update application group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/application/group/{encoded}", data=data, vdom=vdom)

    async def delete_application_group(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete application group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/application/group/{encoded}", vdom=vdom)

    async def get_application_lists(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get application control lists."""
        return await self._make_request("GET", "cmdb/application/list", vdom=vdom)

    async def create_application_list(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create application control list."""
        return await self._make_request("POST", "cmdb/application/list", data=data, vdom=vdom)

    async def update_application_list(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update application control list."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/application/list/{encoded}", data=data, vdom=vdom)

    async def delete_application_list(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete application control list."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/application/list/{encoded}", vdom=vdom)

    async def get_application_rule_settings(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get application rule settings."""
        return await self._make_request("GET", "cmdb/application/rule-settings", vdom=vdom)

    async def update_application_rule_settings(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update application rule settings."""
        return await self._make_request("PUT", "cmdb/application/rule-settings", data=data, vdom=vdom)

    # ============================================================
    # Antivirus endpoints
    # ============================================================
    async def get_antivirus_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get antivirus profiles."""
        return await self._make_request("GET", "cmdb/antivirus/profile", vdom=vdom)

    async def create_antivirus_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create antivirus profile."""
        return await self._make_request("POST", "cmdb/antivirus/profile", data=data, vdom=vdom)

    async def update_antivirus_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update antivirus profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/antivirus/profile/{encoded}", data=data, vdom=vdom)

    async def delete_antivirus_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete antivirus profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/antivirus/profile/{encoded}", vdom=vdom)

    async def get_antivirus_settings(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get antivirus settings."""
        return await self._make_request("GET", "cmdb/antivirus/settings", vdom=vdom)

    async def update_antivirus_settings(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update antivirus settings."""
        return await self._make_request("PUT", "cmdb/antivirus/settings", data=data, vdom=vdom)

    async def get_antivirus_exempt_list(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get antivirus exempt list."""
        return await self._make_request("GET", "cmdb/antivirus/exempt-list", vdom=vdom)

    async def create_antivirus_exempt_list(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create antivirus exempt list entry."""
        return await self._make_request("POST", "cmdb/antivirus/exempt-list", data=data, vdom=vdom)

    async def update_antivirus_exempt_list(self, entry_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update antivirus exempt list entry."""
        encoded = urllib.parse.quote(entry_id, safe='')
        return await self._make_request("PUT", f"cmdb/antivirus/exempt-list/{encoded}", data=data, vdom=vdom)

    async def delete_antivirus_exempt_list(self, entry_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete antivirus exempt list entry."""
        encoded = urllib.parse.quote(entry_id, safe='')
        return await self._make_request("DELETE", f"cmdb/antivirus/exempt-list/{encoded}", vdom=vdom)

    async def get_antivirus_quarantine(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get antivirus quarantine settings."""
        return await self._make_request("GET", "cmdb/antivirus/quarantine", vdom=vdom)

    async def update_antivirus_quarantine(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update antivirus quarantine settings."""
        return await self._make_request("PUT", "cmdb/antivirus/quarantine", data=data, vdom=vdom)

    # ============================================================
    # Alert Email endpoints
    # ============================================================
    async def get_alertemail_setting(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get alert email settings."""
        return await self._make_request("GET", "cmdb/alertemail/setting", vdom=vdom)

    async def update_alertemail_setting(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update alert email settings."""
        return await self._make_request("PUT", "cmdb/alertemail/setting", data=data, vdom=vdom)
    # ============================================================
    # SSH Filter endpoints
    # ============================================================
    async def get_ssh_filter_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get SSH filter profiles."""
        return await self._make_request("GET", "cmdb/ssh-filter/profile", vdom=vdom)

    async def create_ssh_filter_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create SSH filter profile."""
        return await self._make_request("POST", "cmdb/ssh-filter/profile", data=data, vdom=vdom)

    async def update_ssh_filter_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update SSH filter profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/ssh-filter/profile/{encoded}", data=data, vdom=vdom)

    async def delete_ssh_filter_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete SSH filter profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/ssh-filter/profile/{encoded}", vdom=vdom)

    # ============================================================
    # SCTP Filter endpoints
    # ============================================================
    async def get_sctp_filter_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get SCTP filter profiles."""
        return await self._make_request("GET", "cmdb/sctp-filter/profile", vdom=vdom)

    async def create_sctp_filter_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create SCTP filter profile."""
        return await self._make_request("POST", "cmdb/sctp-filter/profile", data=data, vdom=vdom)

    async def update_sctp_filter_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update SCTP filter profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/sctp-filter/profile/{encoded}", data=data, vdom=vdom)

    async def delete_sctp_filter_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete SCTP filter profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/sctp-filter/profile/{encoded}", vdom=vdom)

    # ============================================================
    # Switch Controller - ACL endpoints
    # ============================================================
    async def get_switch_acl_groups(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get switch ACL groups."""
        return await self._make_request("GET", "cmdb/switch-controller.acl/group", vdom=vdom)

    async def create_switch_acl_group(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create switch ACL group."""
        return await self._make_request("POST", "cmdb/switch-controller.acl/group", data=data, vdom=vdom)

    async def update_switch_acl_group(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update switch ACL group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/switch-controller.acl/group/{encoded}", data=data, vdom=vdom)

    async def delete_switch_acl_group(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete switch ACL group."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/switch-controller.acl/group/{encoded}", vdom=vdom)

    async def get_switch_acl_ingress(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get switch ingress ACL policies."""
        return await self._make_request("GET", "cmdb/switch-controller.acl/ingress", vdom=vdom)

    async def create_switch_acl_ingress(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create switch ingress ACL."""
        return await self._make_request("POST", "cmdb/switch-controller.acl/ingress", data=data, vdom=vdom)

    async def update_switch_acl_ingress(self, policy_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update switch ingress ACL."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("PUT", f"cmdb/switch-controller.acl/ingress/{encoded}", data=data, vdom=vdom)

    async def delete_switch_acl_ingress(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete switch ingress ACL."""
        encoded = urllib.parse.quote(policy_id, safe='')
        return await self._make_request("DELETE", f"cmdb/switch-controller.acl/ingress/{encoded}", vdom=vdom)

    # ============================================================
    # Switch Controller - Auto Config endpoints
    # ============================================================
    async def get_switch_auto_config_custom(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get switch auto-config custom policies."""
        return await self._make_request("GET", "cmdb/switch-controller.auto-config/custom", vdom=vdom)

    async def create_switch_auto_config_custom(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create switch auto-config custom."""
        return await self._make_request("POST", "cmdb/switch-controller.auto-config/custom", data=data, vdom=vdom)

    async def update_switch_auto_config_custom(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update switch auto-config custom."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/switch-controller.auto-config/custom/{encoded}", data=data, vdom=vdom)

    async def delete_switch_auto_config_custom(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete switch auto-config custom."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/switch-controller.auto-config/custom/{encoded}", vdom=vdom)

    async def get_switch_auto_config_default(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get switch auto-config default."""
        return await self._make_request("GET", "cmdb/switch-controller.auto-config/default", vdom=vdom)

    async def update_switch_auto_config_default(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update switch auto-config default."""
        return await self._make_request("PUT", "cmdb/switch-controller.auto-config/default", data=data, vdom=vdom)

    async def get_switch_auto_config_policy(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get switch auto-config policies."""
        return await self._make_request("GET", "cmdb/switch-controller.auto-config/policy", vdom=vdom)

    async def create_switch_auto_config_policy(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create switch auto-config policy."""
        return await self._make_request("POST", "cmdb/switch-controller.auto-config/policy", data=data, vdom=vdom)

    async def update_switch_auto_config_policy(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update switch auto-config policy."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/switch-controller.auto-config/policy/{encoded}", data=data, vdom=vdom)

    async def delete_switch_auto_config_policy(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete switch auto-config policy."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/switch-controller.auto-config/policy/{encoded}", vdom=vdom)

    # ============================================================
    # Switch Controller - QoS endpoints
    # ============================================================
    async def get_switch_qos_dot1p_map(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get switch QoS dot1p map."""
        return await self._make_request("GET", "cmdb/switch-controller.qos/dot1p-map", vdom=vdom)

    async def create_switch_qos_dot1p_map(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create switch QoS dot1p map."""
        return await self._make_request("POST", "cmdb/switch-controller.qos/dot1p-map", data=data, vdom=vdom)

    async def update_switch_qos_dot1p_map(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update switch QoS dot1p map."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/switch-controller.qos/dot1p-map/{encoded}", data=data, vdom=vdom)

    async def delete_switch_qos_dot1p_map(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete switch QoS dot1p map."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/switch-controller.qos/dot1p-map/{encoded}", vdom=vdom)

    async def get_switch_qos_ip_dscp_map(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get switch QoS IP DSCP map."""
        return await self._make_request("GET", "cmdb/switch-controller.qos/ip-dscp-map", vdom=vdom)

    async def create_switch_qos_ip_dscp_map(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create switch QoS IP DSCP map."""
        return await self._make_request("POST", "cmdb/switch-controller.qos/ip-dscp-map", data=data, vdom=vdom)

    async def update_switch_qos_ip_dscp_map(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update switch QoS IP DSCP map."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/switch-controller.qos/ip-dscp-map/{encoded}", data=data, vdom=vdom)

    async def delete_switch_qos_ip_dscp_map(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete switch QoS IP DSCP map."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/switch-controller.qos/ip-dscp-map/{encoded}", vdom=vdom)

    async def get_switch_qos_qos_policy(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get switch QoS policies."""
        return await self._make_request("GET", "cmdb/switch-controller.qos/qos-policy", vdom=vdom)

    async def create_switch_qos_qos_policy(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create switch QoS policy."""
        return await self._make_request("POST", "cmdb/switch-controller.qos/qos-policy", data=data, vdom=vdom)

    async def update_switch_qos_qos_policy(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update switch QoS policy."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/switch-controller.qos/qos-policy/{encoded}", data=data, vdom=vdom)

    async def delete_switch_qos_qos_policy(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete switch QoS policy."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/switch-controller.qos/qos-policy/{encoded}", vdom=vdom)

    async def get_switch_qos_queue_policy(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get switch QoS queue policies."""
        return await self._make_request("GET", "cmdb/switch-controller.qos/queue-policy", vdom=vdom)

    async def create_switch_qos_queue_policy(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create switch QoS queue policy."""
        return await self._make_request("POST", "cmdb/switch-controller.qos/queue-policy", data=data, vdom=vdom)

    async def update_switch_qos_queue_policy(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update switch QoS queue policy."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/switch-controller.qos/queue-policy/{encoded}", data=data, vdom=vdom)

    async def delete_switch_qos_queue_policy(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete switch QoS queue policy."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/switch-controller.qos/queue-policy/{encoded}", vdom=vdom)

    # ============================================================
    # Switch Controller - Security Policy endpoints
    # ============================================================
    async def get_switch_8021x_policies(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get switch 802.1X security policies."""
        return await self._make_request("GET", "cmdb/switch-controller.security-policy/802-1X", vdom=vdom)

    async def create_switch_8021x_policy(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create switch 802.1X policy."""
        return await self._make_request("POST", "cmdb/switch-controller.security-policy/802-1X", data=data, vdom=vdom)

    async def update_switch_8021x_policy(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update switch 802.1X policy."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/switch-controller.security-policy/802-1X/{encoded}", data=data, vdom=vdom)

    async def delete_switch_8021x_policy(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete switch 802.1X policy."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/switch-controller.security-policy/802-1X/{encoded}", vdom=vdom)

    async def get_switch_security_policy_local_access(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get switch local access security policies."""
        return await self._make_request("GET", "cmdb/switch-controller.security-policy/local-access", vdom=vdom)

    async def create_switch_security_policy_local_access(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create switch local access policy."""
        return await self._make_request("POST", "cmdb/switch-controller.security-policy/local-access", data=data, vdom=vdom)

    async def update_switch_security_policy_local_access(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update switch local access policy."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/switch-controller.security-policy/local-access/{encoded}", data=data, vdom=vdom)

    async def delete_switch_security_policy_local_access(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete switch local access policy."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/switch-controller.security-policy/local-access/{encoded}", vdom=vdom)

    # ============================================================
    # Switch Controller - Initial Config endpoints
    # ============================================================
    async def get_switch_initial_config_template(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get switch initial config templates."""
        return await self._make_request("GET", "cmdb/switch-controller.initial-config/template", vdom=vdom)

    async def create_switch_initial_config_template(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create switch initial config template."""
        return await self._make_request("POST", "cmdb/switch-controller.initial-config/template", data=data, vdom=vdom)

    async def update_switch_initial_config_template(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update switch initial config template."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/switch-controller.initial-config/template/{encoded}", data=data, vdom=vdom)

    async def delete_switch_initial_config_template(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete switch initial config template."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/switch-controller.initial-config/template/{encoded}", vdom=vdom)

    async def get_switch_initial_config_vlans(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get switch initial config VLANs."""
        return await self._make_request("GET", "cmdb/switch-controller.initial-config/vlans", vdom=vdom)

    async def update_switch_initial_config_vlans(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update switch initial config VLANs."""
        return await self._make_request("PUT", "cmdb/switch-controller.initial-config/vlans", data=data, vdom=vdom)

    # ============================================================
    # Switch Controller - PTP endpoints
    # ============================================================
    async def get_switch_ptp_interface_policy(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get switch PTP interface policies."""
        return await self._make_request("GET", "cmdb/switch-controller.ptp/interface-policy", vdom=vdom)

    async def create_switch_ptp_interface_policy(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create switch PTP interface policy."""
        return await self._make_request("POST", "cmdb/switch-controller.ptp/interface-policy", data=data, vdom=vdom)

    async def update_switch_ptp_interface_policy(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update switch PTP interface policy."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/switch-controller.ptp/interface-policy/{encoded}", data=data, vdom=vdom)

    async def delete_switch_ptp_interface_policy(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete switch PTP interface policy."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/switch-controller.ptp/interface-policy/{encoded}", vdom=vdom)

    async def get_switch_ptp_profile(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get switch PTP profiles."""
        return await self._make_request("GET", "cmdb/switch-controller.ptp/profile", vdom=vdom)

    async def create_switch_ptp_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create switch PTP profile."""
        return await self._make_request("POST", "cmdb/switch-controller.ptp/profile", data=data, vdom=vdom)

    async def update_switch_ptp_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update switch PTP profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("PUT", f"cmdb/switch-controller.ptp/profile/{encoded}", data=data, vdom=vdom)

    async def delete_switch_ptp_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete switch PTP profile."""
        encoded = urllib.parse.quote(name, safe='')
        return await self._make_request("DELETE", f"cmdb/switch-controller.ptp/profile/{encoded}", vdom=vdom)
    # ============================================================
    # User - Local Users endpoints
    # ============================================================
    async def get_user_locals(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get local users."""
        return await self._make_request("GET", "cmdb/user/local", vdom=vdom)

    async def create_user_local(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create local user."""
        return await self._make_request("POST", "cmdb/user/local", data=data, vdom=vdom)

    async def update_user_local(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update local user."""
        return await self._make_request("PUT", f"cmdb/user/local/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_user_local(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete local user."""
        return await self._make_request("DELETE", f"cmdb/user/local/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # User Groups
    async def get_user_groups(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get user groups."""
        return await self._make_request("GET", "cmdb/user/group", vdom=vdom)

    async def create_user_group(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create user group."""
        return await self._make_request("POST", "cmdb/user/group", data=data, vdom=vdom)

    async def update_user_group(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/user/group/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_user_group(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/user/group/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # LDAP servers
    async def get_user_ldaps(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/user/ldap", vdom=vdom)

    async def create_user_ldap(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/user/ldap", data=data, vdom=vdom)

    async def update_user_ldap(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/user/ldap/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_user_ldap(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/user/ldap/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # RADIUS servers
    async def get_user_radiuses(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/user/radius", vdom=vdom)

    async def create_user_radius(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/user/radius", data=data, vdom=vdom)

    async def update_user_radius(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/user/radius/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_user_radius(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/user/radius/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # TACACS+ servers
    async def get_user_tacacs(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/user/tacacs+", vdom=vdom)

    async def create_user_tacacs(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/user/tacacs+", data=data, vdom=vdom)

    async def update_user_tacacs(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/user/tacacs+/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_user_tacacs(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/user/tacacs+/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # User settings
    async def get_user_setting(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/user/setting", vdom=vdom)

    async def update_user_setting(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", "cmdb/user/setting", data=data, vdom=vdom)

    # FSSO
    async def get_user_fsso(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/user/fsso", vdom=vdom)

    async def create_user_fsso(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/user/fsso", data=data, vdom=vdom)

    async def update_user_fsso(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/user/fsso/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_user_fsso(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/user/fsso/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # SAML
    async def get_user_saml(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/user/saml", vdom=vdom)

    async def create_user_saml(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/user/saml", data=data, vdom=vdom)

    async def update_user_saml(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/user/saml/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_user_saml(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/user/saml/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # FortiToken
    async def get_user_fortitokens(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/user/fortitoken", vdom=vdom)

    async def create_user_fortitoken(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/user/fortitoken", data=data, vdom=vdom)

    async def update_user_fortitoken(self, sn: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/user/fortitoken/{urllib.parse.quote(sn, safe='')}", data=data, vdom=vdom)

    async def delete_user_fortitoken(self, sn: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/user/fortitoken/{urllib.parse.quote(sn, safe='')}", vdom=vdom)

    # Peer users
    async def get_user_peers(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/user/peer", vdom=vdom)

    async def create_user_peer(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/user/peer", data=data, vdom=vdom)

    async def update_user_peer(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/user/peer/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_user_peer(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/user/peer/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # Peer groups
    async def get_user_peergrps(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/user/peergrp", vdom=vdom)

    async def create_user_peergrp(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/user/peergrp", data=data, vdom=vdom)

    async def update_user_peergrp(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/user/peergrp/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_user_peergrp(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/user/peergrp/{urllib.parse.quote(name, safe='')}", vdom=vdom)
    # ============================================================
    # WebFilter endpoints
    # ============================================================
    async def get_webfilter_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/webfilter/profile", vdom=vdom)

    async def create_webfilter_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/webfilter/profile", data=data, vdom=vdom)

    async def update_webfilter_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/webfilter/profile/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_webfilter_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/webfilter/profile/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    async def get_webfilter_urlfilters(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/webfilter/urlfilter", vdom=vdom)

    async def create_webfilter_urlfilter(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/webfilter/urlfilter", data=data, vdom=vdom)

    async def update_webfilter_urlfilter(self, filt_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/webfilter/urlfilter/{urllib.parse.quote(filt_id, safe='')}", data=data, vdom=vdom)

    async def delete_webfilter_urlfilter(self, filt_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/webfilter/urlfilter/{urllib.parse.quote(filt_id, safe='')}", vdom=vdom)

    async def get_webfilter_content(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/webfilter/content", vdom=vdom)

    async def create_webfilter_content(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/webfilter/content", data=data, vdom=vdom)

    async def update_webfilter_content(self, filt_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/webfilter/content/{urllib.parse.quote(filt_id, safe='')}", data=data, vdom=vdom)

    async def delete_webfilter_content(self, filt_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/webfilter/content/{urllib.parse.quote(filt_id, safe='')}", vdom=vdom)

    async def get_webfilter_fortiguard(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/webfilter/fortiguard", vdom=vdom)

    async def update_webfilter_fortiguard(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", "cmdb/webfilter/fortiguard", data=data, vdom=vdom)

    async def get_webfilter_search_engines(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/webfilter/search-engine", vdom=vdom)

    # ============================================================
    # Web Proxy endpoints
    # ============================================================
    async def get_web_proxy_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/web-proxy/profile", vdom=vdom)

    async def create_web_proxy_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/web-proxy/profile", data=data, vdom=vdom)

    async def update_web_proxy_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/web-proxy/profile/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_web_proxy_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/web-proxy/profile/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    async def get_web_proxy_forward_servers(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/web-proxy/forward-server", vdom=vdom)

    async def create_web_proxy_forward_server(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/web-proxy/forward-server", data=data, vdom=vdom)

    async def update_web_proxy_forward_server(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/web-proxy/forward-server/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_web_proxy_forward_server(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/web-proxy/forward-server/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    async def get_web_proxy_forward_server_groups(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/web-proxy/forward-server-group", vdom=vdom)

    async def create_web_proxy_forward_server_group(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/web-proxy/forward-server-group", data=data, vdom=vdom)

    async def update_web_proxy_forward_server_group(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/web-proxy/forward-server-group/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_web_proxy_forward_server_group(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/web-proxy/forward-server-group/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    async def get_web_proxy_explicit(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/web-proxy/explicit", vdom=vdom)

    async def update_web_proxy_explicit(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", "cmdb/web-proxy/explicit", data=data, vdom=vdom)

    async def get_web_proxy_global(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/web-proxy/global", vdom=vdom)

    async def update_web_proxy_global(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", "cmdb/web-proxy/global", data=data, vdom=vdom)

    # ============================================================
    # WAF endpoints
    # ============================================================
    async def get_waf_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/waf/profile", vdom=vdom)

    async def create_waf_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/waf/profile", data=data, vdom=vdom)

    async def update_waf_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/waf/profile/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_waf_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/waf/profile/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    async def get_waf_signatures(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/waf/signature", vdom=vdom)

    # ============================================================
    # VoIP endpoints
    # ============================================================
    async def get_voip_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/voip/profile", vdom=vdom)

    async def create_voip_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/voip/profile", data=data, vdom=vdom)

    async def update_voip_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/voip/profile/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_voip_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/voip/profile/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # ============================================================
    # Video Filter endpoints
    # ============================================================
    async def get_videofilter_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/videofilter/profile", vdom=vdom)

    async def create_videofilter_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/videofilter/profile", data=data, vdom=vdom)

    async def update_videofilter_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/videofilter/profile/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_videofilter_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/videofilter/profile/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # ============================================================
    # Virtual Patch endpoints
    # ============================================================
    async def get_virtual_patch_profiles(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/virtual-patch/profile", vdom=vdom)

    async def create_virtual_patch_profile(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/virtual-patch/profile", data=data, vdom=vdom)

    async def update_virtual_patch_profile(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/virtual-patch/profile/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_virtual_patch_profile(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/virtual-patch/profile/{urllib.parse.quote(name, safe='')}", vdom=vdom)
    # ============================================================
    # VPN - IPSec Phase1-Interface endpoints (most commonly used)
    # ============================================================
    async def get_vpn_ipsec_phase1_interfaces(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/vpn.ipsec/phase1-interface", vdom=vdom)

    async def create_vpn_ipsec_phase1_interface(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/vpn.ipsec/phase1-interface", data=data, vdom=vdom)

    async def update_vpn_ipsec_phase1_interface(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/vpn.ipsec/phase1-interface/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_vpn_ipsec_phase1_interface(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/vpn.ipsec/phase1-interface/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # Phase2-Interface
    async def get_vpn_ipsec_phase2_interfaces(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/vpn.ipsec/phase2-interface", vdom=vdom)

    async def create_vpn_ipsec_phase2_interface(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/vpn.ipsec/phase2-interface", data=data, vdom=vdom)

    async def update_vpn_ipsec_phase2_interface(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/vpn.ipsec/phase2-interface/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_vpn_ipsec_phase2_interface(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/vpn.ipsec/phase2-interface/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # Phase1 (tunnel mode)
    async def get_vpn_ipsec_phase1(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/vpn.ipsec/phase1", vdom=vdom)

    async def create_vpn_ipsec_phase1(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/vpn.ipsec/phase1", data=data, vdom=vdom)

    async def update_vpn_ipsec_phase1(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/vpn.ipsec/phase1/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_vpn_ipsec_phase1(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/vpn.ipsec/phase1/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # Phase2 (tunnel mode)
    async def get_vpn_ipsec_phase2(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/vpn.ipsec/phase2", vdom=vdom)

    async def create_vpn_ipsec_phase2(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/vpn.ipsec/phase2", data=data, vdom=vdom)

    async def update_vpn_ipsec_phase2(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/vpn.ipsec/phase2/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_vpn_ipsec_phase2(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/vpn.ipsec/phase2/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # FEC
    async def get_vpn_ipsec_fec(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/vpn.ipsec/fec", vdom=vdom)

    async def create_vpn_ipsec_fec(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/vpn.ipsec/fec", data=data, vdom=vdom)

    async def update_vpn_ipsec_fec(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/vpn.ipsec/fec/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_vpn_ipsec_fec(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/vpn.ipsec/fec/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # ============================================================
    # VPN - SSL VPN endpoints
    # ============================================================
    async def get_vpn_ssl_settings(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/vpn.ssl/settings", vdom=vdom)

    async def update_vpn_ssl_settings(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", "cmdb/vpn.ssl/settings", data=data, vdom=vdom)

    async def get_vpn_ssl_web_portals(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/vpn.ssl.web/portal", vdom=vdom)

    async def create_vpn_ssl_web_portal(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/vpn.ssl.web/portal", data=data, vdom=vdom)

    async def update_vpn_ssl_web_portal(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/vpn.ssl.web/portal/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_vpn_ssl_web_portal(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/vpn.ssl.web/portal/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    async def get_vpn_ssl_web_realms(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/vpn.ssl.web/realm", vdom=vdom)

    async def create_vpn_ssl_web_realm(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/vpn.ssl.web/realm", data=data, vdom=vdom)

    async def update_vpn_ssl_web_realm(self, url_path: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/vpn.ssl.web/realm/{urllib.parse.quote(url_path, safe='')}", data=data, vdom=vdom)

    async def delete_vpn_ssl_web_realm(self, url_path: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/vpn.ssl.web/realm/{urllib.parse.quote(url_path, safe='')}", vdom=vdom)

    async def get_vpn_ssl_web_user_bookmarks(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/vpn.ssl.web/user-bookmark", vdom=vdom)

    async def create_vpn_ssl_web_user_bookmark(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/vpn.ssl.web/user-bookmark", data=data, vdom=vdom)

    async def update_vpn_ssl_web_user_bookmark(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/vpn.ssl.web/user-bookmark/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_vpn_ssl_web_user_bookmark(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/vpn.ssl.web/user-bookmark/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    # L2TP / PPTP
    async def get_vpn_l2tp(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/vpn/l2tp", vdom=vdom)

    async def update_vpn_l2tp(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", "cmdb/vpn/l2tp", data=data, vdom=vdom)

    async def get_vpn_pptp(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/vpn/pptp", vdom=vdom)

    async def update_vpn_pptp(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", "cmdb/vpn/pptp", data=data, vdom=vdom)

    # ============================================================
    # System - DHCP Server endpoints
    # ============================================================
    async def get_system_dhcp_servers(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/system.dhcp/server", vdom=vdom)

    async def create_system_dhcp_server(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/system.dhcp/server", data=data, vdom=vdom)

    async def update_system_dhcp_server(self, server_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/system.dhcp/server/{urllib.parse.quote(server_id, safe='')}", data=data, vdom=vdom)

    async def delete_system_dhcp_server(self, server_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/system.dhcp/server/{urllib.parse.quote(server_id, safe='')}", vdom=vdom)

    # ============================================================
    # System - SNMP endpoints
    # ============================================================
    async def get_system_snmp_communities(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/system.snmp/community", vdom=vdom)

    async def create_system_snmp_community(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/system.snmp/community", data=data, vdom=vdom)

    async def update_system_snmp_community(self, comm_id: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/system.snmp/community/{urllib.parse.quote(comm_id, safe='')}", data=data, vdom=vdom)

    async def delete_system_snmp_community(self, comm_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/system.snmp/community/{urllib.parse.quote(comm_id, safe='')}", vdom=vdom)

    async def get_system_snmp_users(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/system.snmp/user", vdom=vdom)

    async def create_system_snmp_user(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("POST", "cmdb/system.snmp/user", data=data, vdom=vdom)

    async def update_system_snmp_user(self, name: str, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", f"cmdb/system.snmp/user/{urllib.parse.quote(name, safe='')}", data=data, vdom=vdom)

    async def delete_system_snmp_user(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("DELETE", f"cmdb/system.snmp/user/{urllib.parse.quote(name, safe='')}", vdom=vdom)

    async def get_system_snmp_sysinfo(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/system.snmp/sysinfo", vdom=vdom)

    async def update_system_snmp_sysinfo(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", "cmdb/system.snmp/sysinfo", data=data, vdom=vdom)

    # ============================================================
    # System - Auto Update Schedule
    # ============================================================
    async def get_system_autoupdate_schedule(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("GET", "cmdb/system.autoupdate/schedule", vdom=vdom)

    async def update_system_autoupdate_schedule(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_request("PUT", "cmdb/system.autoupdate/schedule", data=data, vdom=vdom)
    async def _make_log_request(self, endpoint: str, params: Optional[Dict] = None,
                                 vdom: Optional[str] = None) -> Dict[str, Any]:
        """Make HTTP request to FortiGate Log API (/api/v2/log/)."""
        url = f"{self.base_url.replace('/api/v2', '')}/api/v2/log/{endpoint.lstrip('/')}"
        if not params:
            params = {}
        if vdom:
            params["vdom"] = vdom
        start_time = time.time()
        try:
            response = await self._client.request("GET", url=url, params=params)
            duration_ms = (time.time() - start_time) * 1000
            log_api_call(self.logger, "GET", f"log/{endpoint}", response.status_code, duration_ms)
            if response.status_code >= 400:
                error_msg = f"Log API request failed: {response.status_code}"
                try:
                    error_data = response.json()
                    if "error" in error_data:
                        error_msg += f" - {error_data['error']}"
                except Exception:
                    error_msg += f" - {response.text}"
                raise FortiGateAPIError(error_msg, status_code=response.status_code, device_id=self.device_id)
            try:
                return response.json()
            except json.JSONDecodeError:
                return {"status": "success"}
        except httpx.RequestError as e:
            raise FortiGateAPIError(f"Network error: {str(e)}", device_id=self.device_id)

    async def _make_monitor_request(self, endpoint: str, params: Optional[Dict] = None,
                                     vdom: Optional[str] = None,
                                     method: str = "GET",
                                     data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make HTTP request to FortiGate Monitor API (/api/v2/monitor/).
        
        Args:
            endpoint: Monitor API path (e.g. 'system/status', 'license/status')
            params: Query parameters for GET, or body params for POST
            vdom: Virtual domain
            method: HTTP method (GET or POST)
            data: JSON body for POST requests
        """
        url = f"{self.base_url.replace('/api/v2', '')}/api/v2/monitor/{endpoint.lstrip('/')}"
        query_params = {}
        if vdom:
            query_params["vdom"] = vdom
        start_time = time.time()
        try:
            kwargs = {"url": url, "params": query_params}
            if method.upper() == "POST":
                kwargs["json"] = data if data else (params if params else {})
            elif params:
                kwargs["params"] = {**query_params}  # start with vdom
                kwargs["params"].update(params)  # merge additional params
            else:
                kwargs["params"] = query_params
            
            response = await self._client.request(method.upper(), **kwargs)
            duration_ms = (time.time() - start_time) * 1000
            log_api_call(self.logger, method.upper(), f"monitor/{endpoint}", response.status_code, duration_ms)
            if response.status_code >= 400:
                error_msg = f"Monitor API request failed: {response.status_code}"
                try:
                    error_data = response.json()
                    if "error" in error_data:
                        error_msg += f" - {error_data['error']}"
                except Exception:
                    error_msg += f" - {response.text}"
                raise FortiGateAPIError(error_msg, status_code=response.status_code, device_id=self.device_id)
            try:
                return response.json()
            except json.JSONDecodeError:
                return {"status": "success"}
        except httpx.RequestError as e:
            raise FortiGateAPIError(f"Network error: {str(e)}", device_id=self.device_id)

    # ============================================================
    # Monitor API endpoints
    # ============================================================
    async def monitor_vpn_ipsec(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("vpn/ipsec", vdom=vdom)

    async def monitor_vpn_ipsec_connection_count(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("vpn/ipsec/connection-count", vdom=vdom)

    async def monitor_vpn_ssl(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("vpn/ssl", vdom=vdom)

    async def monitor_vpn_ssl_stats(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("vpn/ssl/stats", vdom=vdom)

    async def monitor_user_firewall(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("user/firewall", vdom=vdom)

    async def monitor_user_firewall_count(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("user/firewall/count", vdom=vdom)

    async def monitor_user_banned(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("user/banned", vdom=vdom)

    async def monitor_user_fsso(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("user/fsso", vdom=vdom)

    async def monitor_virtual_wan_health_check(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("virtual-wan/health-check", vdom=vdom)

    async def monitor_virtual_wan_members(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("virtual-wan/members", vdom=vdom)

    async def monitor_virtual_wan_sla_log(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("virtual-wan/sla-log", vdom=vdom)

    async def monitor_utm_app_lookup(self, app_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("utm/app-lookup", params={"application": app_name}, vdom=vdom)

    async def monitor_utm_application_categories(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("utm/application-categories", vdom=vdom)

    async def monitor_utm_applications(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("utm/applications", vdom=vdom)

    async def monitor_router_ipv4(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("router/ipv4", vdom=vdom)

    async def monitor_router_ipv6(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("router/ipv6", vdom=vdom)

    async def monitor_firewall_acl(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("firewall/acl", vdom=vdom)

    async def monitor_firewall_acl6(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("firewall/acl6", vdom=vdom)

    async def monitor_license_status(self) -> Dict[str, Any]:
        return await self._make_monitor_request("license/status")

    async def monitor_log_current_disk_usage(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("log/current-disk-usage", vdom=vdom)

    async def monitor_log_fortianalyzer(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("log/fortianalyzer", vdom=vdom)

    async def monitor_log_forticloud(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("log/forticloud", vdom=vdom)

    async def monitor_ips_rate_based(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("ips/rate-based", vdom=vdom)

    async def monitor_ips_session_performance(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("ips/session/performance", vdom=vdom)

    async def monitor_fortiguard_service_stats(self) -> Dict[str, Any]:
        return await self._make_monitor_request("fortiguard/service-communication-stats")

    async def monitor_geoip_query(self, ip: str) -> Dict[str, Any]:
        return await self._make_monitor_request("geoip/geoip-query/select", 
                                                 method="POST",
                                                 data={"ip_addresses": [ip]})

    async def monitor_fortiview_realtime_stats(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("fortiview/realtime-statistics", vdom=vdom)

    async def monitor_network_arp(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("network/arp", vdom=vdom)

    async def monitor_network_lldp_neighbors(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("network/lldp/neighbors", vdom=vdom)

    async def monitor_network_dns_latency(self) -> Dict[str, Any]:
        return await self._make_monitor_request("network/dns/latency")

    async def monitor_network_reverse_ip_lookup(self, ip: str) -> Dict[str, Any]:
        return await self._make_monitor_request("network/reverse-ip-lookup", params={"ip": ip})

    async def monitor_router_bgp_neighbors(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("router/bgp/neighbors", vdom=vdom)

    async def monitor_router_bgp_paths(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("router/bgp/paths", vdom=vdom)

    async def monitor_system_available_interfaces(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("system/available-interfaces", vdom=vdom)

    async def monitor_registration_forticloud_status(self) -> Dict[str, Any]:
        return await self._make_monitor_request("registration/forticloud/device-status")

    async def monitor_webfilter_fortiguard_categories(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_monitor_request("webfilter/fortiguard-categories", vdom=vdom)

    # --- System monitor (hardware / status) ---
    async def monitor_system_status(self) -> Dict[str, Any]:
        """Get FortiGate system status (hostname, serial, version, HA, etc.)."""
        return await self._make_monitor_request("system/status")

    async def monitor_system_resource_usage(self, vdom: Optional[str] = None,
                                            scope: str = "current") -> Dict[str, Any]:
        """Get CPU/memory/session resource usage.
        
        Args:
            vdom: Virtual Domain (optional)
            scope: "current" for latest snapshot only, "global" for full history
        """
        params = {"scope": scope}
        if vdom:
            params["vdom"] = vdom
        return await self._make_monitor_request("system/resource/usage", params=params)

    async def monitor_system_performance_status(self) -> Dict[str, Any]:
        """Get system performance status (CPU/memory per interval)."""
        return await self._make_monitor_request("system/performance/status")

    async def monitor_system_interface(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get interface bandwidth/speed/utilization from monitor."""
        return await self._make_monitor_request("system/interface", vdom=vdom)

    async def monitor_system_current_admins(self) -> Dict[str, Any]:
        """Get currently logged-in administrators."""
        return await self._make_monitor_request("system/current-admins")

    async def monitor_system_firmware(self) -> Dict[str, Any]:
        """Get current firmware version and available upgrades."""
        return await self._make_monitor_request("system/firmware")

    async def monitor_system_vm_information(self) -> Dict[str, Any]:
        """Get VM hypervisor / platform info."""
        return await self._make_monitor_request("system/vm-information")

    # --- Firewall monitor ---
    async def monitor_firewall_policy(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get firewall policy statistics and hit counts."""
        return await self._make_monitor_request("firewall/policy", vdom=vdom)

    async def monitor_firewall_sessions(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get current session table."""
        return await self._make_monitor_request("firewall/sessions", vdom=vdom)

    async def monitor_firewall_policy_lookup(self, params: dict, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Policy lookup by 5-tuple: srcip, dstip, srcport, dstport, protocol."""
        return await self._make_monitor_request("firewall/policy-lookup", params=params, vdom=vdom)

    # --- Generic monitor ---
    async def monitor_request(self, endpoint: str, params: Optional[Dict] = None,
                               vdom: Optional[str] = None,
                               method: str = "GET",
                               data: Optional[Dict] = None) -> Dict[str, Any]:
        """Generic monitor API request — covers ALL /api/v2/monitor/ endpoints (GET + POST).
        
        Examples: 'system/status', 'license/status', 'system/resource/usage',
                  'firewall/sessions', 'router/ipv4', etc.
        
        For POST endpoints (e.g. 'firewall/policy/reset', 'system/os/reboot'),
        set method='POST' and pass data as JSON body.
        """
        return await self._make_monitor_request(endpoint, params=params, vdom=vdom,
                                                  method=method, data=data)

    # ============================================================
    # Service API endpoints (/api/v2/service/)
    # ============================================================
    async def _make_service_request(self, method: str, endpoint: str,
                                     data: Optional[Dict] = None,
                                     vdom: Optional[str] = None) -> Dict[str, Any]:
        """Make request to FortiGate Service API (/api/v2/service/)."""
        url = f"{self.base_url.replace('/api/v2', '')}/api/v2/service/{endpoint.lstrip('/')}"
        params = {}
        if vdom:
            params["vdom"] = vdom
        start_time = time.time()
        try:
            response = await self._client.request(
                method=method, url=url, params=params, json=data if data else None
            )
            duration_ms = (time.time() - start_time) * 1000
            log_api_call(self.logger, method, f"service/{endpoint}", response.status_code, duration_ms)
            if response.status_code >= 400:
                error_msg = f"Service API request failed: {response.status_code}"
                try:
                    err = response.json()
                    if "error" in err:
                        error_msg += f" - {err['error']}"
                except Exception:
                    pass
                raise FortiGateAPIError(error_msg, status_code=response.status_code, device_id=self.device_id)
            try:
                return response.json()
            except json.JSONDecodeError:
                return {"status": "success"}
        except httpx.RequestError as e:
            raise FortiGateAPIError(f"Network error: {str(e)}", device_id=self.device_id)

    # Sniffer (packet capture)
    async def service_sniffer_list(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_service_request("GET", "sniffer/list/", vdom=vdom)

    async def service_sniffer_start(self, data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_service_request("POST", "sniffer/start/", data=data, vdom=vdom)

    async def service_sniffer_stop(self, sniffer_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_service_request("POST", "sniffer/stop/", data={"id": sniffer_id}, vdom=vdom)

    async def service_sniffer_download(self, sniffer_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_service_request("POST", "sniffer/download/", data={"id": sniffer_id}, vdom=vdom)

    async def service_sniffer_delete(self, sniffer_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_service_request("POST", "sniffer/delete/", data={"id": sniffer_id}, vdom=vdom)

    # Security Rating
    async def service_security_rating_report(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_service_request("GET", "security-rating/report/", vdom=vdom)

    async def service_security_rating_recommendations(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_service_request("GET", "security-rating/recommendations/", vdom=vdom)

    # System PSIRT
    async def service_system_psirt_vulnerabilities(self) -> Dict[str, Any]:
        return await self._make_service_request("GET", "system/psirt-vulnerabilities/")

    # Topology
    async def service_topology_report(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        return await self._make_service_request("GET", "topology/report/", vdom=vdom)

    # ============================================================
    # Log query endpoints (disk, memory, forticloud, fortianalyzer)
    # ============================================================
    async def get_logs(self, source: str, log_type: str, subtype: Optional[str] = None,
                       filter_str: Optional[str] = None, limit: int = 100,
                       vdom: Optional[str] = None) -> Dict[str, Any]:
        """Query logs from a log source.
        
        Args:
            source: 'disk', 'memory', 'forticloud', or 'fortianalyzer'
            log_type: 'traffic', 'event', 'virus', 'webfilter', 'app-ctrl', etc.
            subtype: For traffic/event: 'forward', 'local', 'sniffer', etc.
            filter_str: Log filter expression
            limit: Max results (default 100)
        """
        if subtype and log_type in ("traffic", "event"):
            endpoint = f"{source}/{log_type}/{subtype}"
        else:
            endpoint = f"{source}/{log_type}"
        params = {"limit": limit}
        if filter_str:
            params["filter"] = filter_str
        return await self._make_log_request(endpoint, params=params, vdom=vdom)

    async def get_logs_raw(self, source: str, log_type: str, subtype: Optional[str] = None,
                           filter_str: Optional[str] = None, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get raw logs (download format)."""
        if subtype and log_type in ("traffic", "event"):
            endpoint = f"{source}/{log_type}/{subtype}/raw"
        else:
            endpoint = f"{source}/{log_type}/raw"
        params = {}
        if filter_str:
            params["filter"] = filter_str
        return await self._make_log_request(endpoint, params=params, vdom=vdom)

    async def get_log_archive(self, source: str, log_type: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get log archive listing."""
        endpoint = f"{source}/{log_type}/archive"
        return await self._make_log_request(endpoint, vdom=vdom)

    async def download_log_archive(self, source: str, log_type: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Download log archive."""
        endpoint = f"{source}/{log_type}/archive-download"
        return await self._make_log_request(endpoint, vdom=vdom)

    async def get_virus_log_archive(self, source: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get virus log archive."""
        return await self._make_log_request(f"{source}/virus/archive", vdom=vdom)

    # Search endpoints
    async def get_log_search_status(self, session_id: str) -> Dict[str, Any]:
        """Get log search session status."""
        return await self._make_log_request(f"search/status/{session_id}")

    async def abort_log_search(self, session_id: str) -> Dict[str, Any]:
        """Abort a log search session."""
        url = f"{self.base_url.replace('/api/v2', '')}/api/v2/log/search/abort/{session_id}"
        try:
            response = await self._client.request("POST", url=url)
            return response.json() if response.status_code < 400 else {"status": "error", "code": response.status_code}
        except Exception:
            return {"status": "error"}


class FortiGateManager:
    """Manager for multiple FortiGate devices.

    Handles device registration, connection management, and provides
    unified access to multiple FortiGate devices.
    """

    def __init__(self, devices: Dict[str, FortiGateDeviceConfig], auth_config: AuthConfig):
        """Initialize FortiGate manager.

        Args:
            devices: Dictionary of device configurations
            auth_config: Authentication configuration
        """
        self.devices: Dict[str, FortiGateAPI] = {}
        self.auth_config = auth_config
        self.logger = get_logger("fortigate_manager")

        # Initialize devices
        for device_id, config in devices.items():
            try:
                self.devices[device_id] = FortiGateAPI(device_id, config)
                self.logger.info(f"Initialized device: {device_id}")
            except Exception as e:
                self.logger.error(  # F7: log full details for failed device init
                    f"Failed to initialize device {device_id}: {e}. "
                    f"This device will be unavailable. Check config and network connectivity."
                )

    def get_device(self, device_id: str) -> FortiGateAPI:
        """Get FortiGate API client for a device.

        Args:
            device_id: Device identifier

        Returns:
            FortiGateAPI client instance

        Raises:
            ValueError: If device not found
        """
        if device_id not in self.devices:
            raise ValueError(f"Device '{device_id}' not found")
        return self.devices[device_id]

    def list_devices(self) -> List[Dict[str, Any]]:
        """List all registered device IDs with configuration details.

        Returns:
            List of dicts with device_id, host, port, vdom, auth_method, ssl_status
        """
        result = []
        for device_id, api in self.devices.items():
            cfg = api.config
            auth_method = "token" if cfg.api_token else ("password" if cfg.username else "none")
            result.append({
                "device_id": device_id,
                "host": cfg.host,
                "port": cfg.port,
                "vdom": cfg.vdom,
                "auth_method": auth_method,
                "verify_ssl": cfg.verify_ssl,
                "timeout": cfg.timeout,
            })
        return result

    def add_device(self, device_id: str, host: str, port: int = 443,
                   username: Optional[str] = None, password: Optional[str] = None,
                   api_token: Optional[str] = None, vdom: str = "root",
                   verify_ssl: bool = True, timeout: int = 30) -> None:
        """Add a new device to the manager.

        Args:
            device_id: Unique identifier for the device
            host: Device IP address or hostname
            port: HTTPS port
            username: Username for authentication
            password: Password for authentication
            api_token: API token for authentication
            vdom: Virtual Domain name
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        if device_id in self.devices:
            raise ValueError(f"Device '{device_id}' already exists")

        # Create device configuration
        device_config = FortiGateDeviceConfig(
            host=host,
            port=port,
            username=username,
            password=password,
            api_token=api_token,
            vdom=vdom,
            verify_ssl=verify_ssl,
            timeout=timeout
        )

        # Create API client
        self.devices[device_id] = FortiGateAPI(device_id, device_config)
        self.logger.info(f"Added device: {device_id}")

    async def remove_device(self, device_id: str) -> None:
        """Remove a device from the manager and close its connection.

        Args:
            device_id: Device identifier to remove
        """
        if device_id not in self.devices:
            raise ValueError(f"Device '{device_id}' not found")

        await self.devices[device_id].close()
        del self.devices[device_id]
        self.logger.info(f"Removed device: {device_id}")

    async def test_all_connections(self) -> Dict[str, bool]:
        """Test connections to all devices.

        Returns:
            Dictionary mapping device IDs to connection status
        """
        results = {}
        for device_id, api_client in self.devices.items():
            try:
                results[device_id] = await api_client.test_connection()
            except Exception as e:
                self.logger.error(f"Connection test failed for {device_id}: {e}")
                results[device_id] = False
        return results

    async def close_all(self) -> None:
        """Close all device clients and release connection pool resources."""
        for device_id, api_client in self.devices.items():
            try:
                await api_client.close()
                self.logger.info(f"Closed connection for device: {device_id}")
            except Exception as e:
                self.logger.error(f"Error closing connection for {device_id}: {e}")
