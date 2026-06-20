"""Generic CMDB tools for FortiGate MCP — covers ALL FortiOS 8.0 CMDB endpoints."""

from typing import List, Optional, Dict, Any
from mcp.types import TextContent as Content
from .base import FortiGateTool


class CmdbTools(FortiGateTool):
    """Generic CRUD tools for ANY FortiOS CMDB endpoint (1023+ endpoints)."""

    async def cmdb_list(
        self, device_id: str, path: str,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """List resources at a CMDB path (GET collection).

        Args:
            device_id: FortiGate device identifier
            path: CMDB path, e.g. "firewall/address", "router/bgp", "system/dns"
            vdom: Virtual Domain
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            result = await api_client.cmdb_request("GET", path, vdom=vdom)
            return self._format_response(result, path.replace("/", "_"))
        except Exception as e:
            return self._handle_error(f"cmdb_list {path}", device_id, e)

    async def cmdb_get(
        self, device_id: str, path: str, name: Optional[str] = None,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Get a single resource by name/ID, or a singleton object (omit name).

        For singleton objects like system/global, system/dns, system/ntp,
        omit name and the request goes to the singleton URL directly.

        Args:
            device_id: FortiGate device identifier
            path: CMDB path, e.g. "firewall/address", "system/global"
            name: Resource name/ID (omit for singleton objects)
            vdom: Virtual Domain
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            result = await api_client.cmdb_request("GET", path, name=name, vdom=vdom)
            return self._format_response(result, f"{path}_detail")
        except Exception as e:
            label = f"{path}/{name}" if name else path
            return self._handle_error(f"cmdb_get {label}", device_id, e)

    async def cmdb_create(
        self, device_id: str, path: str, data: Dict[str, Any],
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Create a new resource (POST).

        Args:
            device_id: FortiGate device identifier
            path: CMDB path, e.g. "firewall/address"
            data: Resource configuration as JSON dict
            vdom: Virtual Domain
        """
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)

            # Firewall policy paths need field validation (FortiOS gives opaque -56)
            if path in ("firewall/policy", "firewall/security-policy"):
                from .firewall import FirewallTools
                validator = FirewallTools.__new__(FirewallTools)
                validator.logger = self.logger
                err = validator._validate_policy_data(
                    data, "firewall policy" if path == "firewall/policy" else "security policy")
                if err:
                    return self._format_operation_result(
                        f"cmdb_create {path}", device_id, False, error=err)

            api_client = self._get_device_api(device_id)
            await api_client.cmdb_request("POST", path, data=data, vdom=vdom)
            name = data.get("name", "resource")
            return self._format_operation_result("cmdb_create", device_id, True, f"Created {path} '{name}'")
        except Exception as e:
            return self._handle_error(f"cmdb_create {path}", device_id, e)

    async def cmdb_update(
        self, device_id: str, path: str, data: Dict[str, Any],
        name: Optional[str] = None, vdom: Optional[str] = None
    ) -> List[Content]:
        """Update a resource (PUT). Omit name for singleton objects.

        For singleton objects like system/global, omit name and the request goes
        directly to PUT /api/v2/cmdb/system/global without appending a key.

        Args:
            device_id: FortiGate device identifier
            path: CMDB path, e.g. "firewall/address", "system/global"
            data: Updated configuration data as JSON dict
            name: Resource name/ID (omit for singleton objects)
            vdom: Virtual Domain
        """
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.cmdb_request("PUT", path, name=name, data=data, vdom=vdom)
            label = name if name else path
            return self._format_operation_result("cmdb_update", device_id, True, f"Updated {label}")
        except Exception as e:
            label = f"{path}/{name}" if name else path
            return self._handle_error(f"cmdb_update {label}", device_id, e)

    async def cmdb_delete(
        self, device_id: str, path: str,
        name: Optional[str] = None, vdom: Optional[str] = None
    ) -> List[Content]:
        """Delete a resource by name/ID (DELETE with key).

        Args:
            device_id: FortiGate device identifier
            path: CMDB path, e.g. "firewall/address"
            name: Resource name or ID to delete
            vdom: Virtual Domain
        """
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)  # S1: prevent accidental table-wide delete
            api_client = self._get_device_api(device_id)
            await api_client.cmdb_request("DELETE", path, name=name, vdom=vdom)
            label = name if name else path
            return self._format_operation_result("cmdb_delete", device_id, True, f"Deleted {label}")
        except Exception as e:
            label = f"{path}/{name}" if name else path
            return self._handle_error(f"cmdb_delete {label}", device_id, e)
