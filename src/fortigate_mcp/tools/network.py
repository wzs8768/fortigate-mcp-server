"""Network object management tools for FortiGate MCP."""
from typing import List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool

class NetworkTools(FortiGateTool):
    """Tools for FortiGate network object management."""

    async def list_address_objects(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List address objects."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            addresses_data = await api_client.get_address_objects(vdom=vdom)
            return self._format_response(addresses_data, "address_objects")
        except Exception as e:
            return self._handle_error("list address objects", device_id, e)

    async def create_address_object(self, device_id: str, name: str, address_type: str, address: str,
                             vdom: Optional[str] = None) -> List[Content]:
        """Create address object (cmdb/firewall/address — usable in policies).

        Maps the address value to the correct FortiOS API field based on type:
        - ipmask       -> "subnet": "10.0.0.0/24"
        - iprange      -> "start-ip" + "end-ip" parsed from "10.0.0.1-10.0.0.100"
        - fqdn         -> "fqdn": "*.example.com" (policy dstaddr + SSL exempt, 6.2.2+)
        - wildcard-fqdn-> "wildcard-fqdn": "*.example.com" (policy dstaddr, 6.2.2+)
                          NOTE: distinct from wildcard-fqdn/custom (SSL exempt only)
        - geography    -> "country": "CN"

        For SSL-exempt-only wildcard FQDN objects (NOT for policies), use
        create_wildcard_fqdn_custom instead.
        """
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, address_type=address_type, address=address)

            address_data = {"name": name, "type": address_type}

            # Map address value to the correct field based on type
            if address_type in ("ipmask", "dynamic"):
                address_data["subnet"] = address
            elif address_type == "iprange":
                parts = address.split("-", 1)
                if len(parts) != 2:
                    raise ValueError(f"iprange address must be 'start-end' format, got: {address}")
                address_data["start-ip"] = parts[0].strip()
                address_data["end-ip"] = parts[1].strip()
            elif address_type == "fqdn":
                address_data["fqdn"] = address
            elif address_type == "wildcard-fqdn":
                # Note: wildcard-fqdn type addresses go to cmdb/firewall/address
                # (not cmdb/firewall/wildcard-fqdn/custom) and CAN be used in
                # policy dstaddr on FortiOS 8.0+.
                address_data["wildcard-fqdn"] = address
            elif address_type == "geography":
                address_data["country"] = address
            else:
                # Fallback: pass as-is (e.g. "mac" type)
                address_data["subnet"] = address

            api_client = self._get_device_api(device_id)
            await api_client.create_address_object(address_data, vdom=vdom)
            return self._format_operation_result("create address object", device_id, True, f"Address object '{name}' created successfully")
        except Exception as e:
            return self._handle_error("create address object", device_id, e)

    async def list_service_objects(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List service objects."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            services_data = await api_client.get_service_objects(vdom=vdom)
            return self._format_response(services_data, "service_objects")
        except Exception as e:
            return self._handle_error("list service objects", device_id, e)

    async def create_service_object(self, device_id: str, name: str, service_type: str, protocol: str,
                             port: Optional[str] = None, vdom: Optional[str] = None) -> List[Content]:
        """Create service object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, service_type=service_type, protocol=protocol)

            # Build service data with correct FortiOS API field names.
            # FortiOS cmdb/firewall.service/custom expects protocol-specific fields:
            #   TCP/UDP → tcp-portrange / udp-portrange
            #   ICMP    → protocol-number + icmptype + icmpcode
            #   IP      → protocol-number
            service_data = {"name": name}

            proto = protocol.upper()
            if proto in ("TCP", "UDP"):
                port_field = "tcp-portrange" if proto == "TCP" else "udp-portrange"
                if port:
                    service_data[port_field] = port
                else:
                    return self._handle_error("create service object", device_id,
                        ValueError(f"port is required for {proto} service"))
            elif proto == "ICMP":
                service_data["protocol"] = "ICMP"
                # ICMP may need icmptype/icmpcode; pass through if provided via service_type
            elif proto == "IP":
                service_data["protocol"] = "IP"
                if port:
                    service_data["protocol-number"] = str(port)
            else:
                service_data["protocol"] = protocol
                if port:
                    service_data["port"] = port

            api_client = self._get_device_api(device_id)
            await api_client.create_service_object(service_data, vdom=vdom)
            return self._format_operation_result("create service object", device_id, True, f"Service object '{name}' created successfully")
        except Exception as e:
            return self._handle_error("create service object", device_id, e)

    async def update_address_object(self, device_id: str, name: str, address_data: dict,
                             vdom: Optional[str] = None) -> List[Content]:
        """Update address object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, address_data=address_data)
            api_client = self._get_device_api(device_id)
            await api_client.update_address_object(name, address_data, vdom=vdom)
            return self._format_operation_result("update address object", device_id, True, f"Address object '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update address object", device_id, e)

    async def delete_address_object(self, device_id: str, name: str,
                             vdom: Optional[str] = None) -> List[Content]:
        """Delete address object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_address_object(name, vdom=vdom)
            return self._format_operation_result("delete address object", device_id, True, f"Address object '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete address object", device_id, e)

    async def update_service_object(self, device_id: str, name: str, service_data: dict,
                             vdom: Optional[str] = None) -> List[Content]:
        """Update service object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, service_data=service_data)
            api_client = self._get_device_api(device_id)
            await api_client.update_service_object(name, service_data, vdom=vdom)
            return self._format_operation_result("update service object", device_id, True, f"Service object '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update service object", device_id, e)

    async def delete_service_object(self, device_id: str, name: str,
                             vdom: Optional[str] = None) -> List[Content]:
        """Delete service object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_service_object(name, vdom=vdom)
            return self._format_operation_result("delete service object", device_id, True, f"Service object '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete service object", device_id, e)

    # ============================================================
    # Address Group tools
    # ============================================================
    async def list_addrgrps(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List address groups."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_addrgrps(vdom=vdom)
            return self._format_response(data, "addrgrps")
        except Exception as e:
            return self._handle_error("list address groups", device_id, e)

    async def create_addrgrp(self, device_id: str, addrgrp_data: dict,
                      vdom: Optional[str] = None) -> List[Content]:
        """Create address group."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(addrgrp_data=addrgrp_data)
            api_client = self._get_device_api(device_id)
            await api_client.create_addrgrp(addrgrp_data, vdom=vdom)
            return self._format_operation_result("create address group", device_id, True, "Address group created successfully")
        except Exception as e:
            return self._handle_error("create address group", device_id, e)

    async def update_addrgrp(self, device_id: str, name: str, addrgrp_data: dict,
                      vdom: Optional[str] = None) -> List[Content]:
        """Update address group."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_addrgrp(name, addrgrp_data, vdom=vdom)
            return self._format_operation_result("update address group", device_id, True, f"Address group '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update address group", device_id, e)

    async def delete_addrgrp(self, device_id: str, name: str,
                      vdom: Optional[str] = None) -> List[Content]:
        """Delete address group."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_addrgrp(name, vdom=vdom)
            return self._format_operation_result("delete address group", device_id, True, f"Address group '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete address group", device_id, e)

    async def get_addrgrp_detail(self, device_id: str, name: str,
                          vdom: Optional[str] = None) -> List[Content]:
        """Get address group detail."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_addrgrp_detail(name, vdom=vdom)
            return self._format_response(data, "addrgrp_detail")
        except Exception as e:
            return self._handle_error("get address group detail", device_id, e)

    # ============================================================
    # Service Group tools
    # ============================================================
    async def list_service_groups(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List service groups."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_service_groups(vdom=vdom)
            return self._format_response(data, "service_groups")
        except Exception as e:
            return self._handle_error("list service groups", device_id, e)

    async def create_service_group(self, device_id: str, service_group_data: dict,
                            vdom: Optional[str] = None) -> List[Content]:
        """Create service group."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(service_group_data=service_group_data)
            api_client = self._get_device_api(device_id)
            await api_client.create_service_group(service_group_data, vdom=vdom)
            return self._format_operation_result("create service group", device_id, True, "Service group created successfully")
        except Exception as e:
            return self._handle_error("create service group", device_id, e)

    async def update_service_group(self, device_id: str, name: str, service_group_data: dict,
                            vdom: Optional[str] = None) -> List[Content]:
        """Update service group."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_service_group(name, service_group_data, vdom=vdom)
            return self._format_operation_result("update service group", device_id, True, f"Service group '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update service group", device_id, e)

    async def delete_service_group(self, device_id: str, name: str,
                            vdom: Optional[str] = None) -> List[Content]:
        """Delete service group."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_service_group(name, vdom=vdom)
            return self._format_operation_result("delete service group", device_id, True, f"Service group '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete service group", device_id, e)

    # ============================================================
    # Wildcard FQDN tools
    # ============================================================
    async def list_wildcard_fqdn_custom(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List wildcard FQDN custom entries."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_wildcard_fqdn_custom(vdom=vdom)
            return self._format_response(data, "wildcard_fqdn_custom")
        except Exception as e:
            return self._handle_error("list wildcard FQDN", device_id, e)

    async def create_wildcard_fqdn_custom(self, device_id: str, data: dict,
                                   vdom: Optional[str] = None) -> List[Content]:
        """Create wildcard FQDN custom entry."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_wildcard_fqdn_custom(data, vdom=vdom)
            return self._format_operation_result("create wildcard FQDN", device_id, True, "Wildcard FQDN created successfully")
        except Exception as e:
            return self._handle_error("create wildcard FQDN", device_id, e)

    async def update_wildcard_fqdn_custom(self, device_id: str, name: str, data: dict,
                                   vdom: Optional[str] = None) -> List[Content]:
        """Update wildcard FQDN custom entry."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_wildcard_fqdn_custom(name, data, vdom=vdom)
            return self._format_operation_result("update wildcard FQDN", device_id, True, f"Wildcard FQDN '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update wildcard FQDN", device_id, e)

    async def delete_wildcard_fqdn_custom(self, device_id: str, name: str,
                                   vdom: Optional[str] = None) -> List[Content]:
        """Delete wildcard FQDN custom entry."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_wildcard_fqdn_custom(name, vdom=vdom)
            return self._format_operation_result("delete wildcard FQDN", device_id, True, f"Wildcard FQDN '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete wildcard FQDN", device_id, e)

    async def list_wildcard_fqdn_group(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List wildcard FQDN groups."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_wildcard_fqdn_group(vdom=vdom)
            return self._format_response(data, "wildcard_fqdn_group")
        except Exception as e:
            return self._handle_error("list wildcard FQDN groups", device_id, e)

    async def create_wildcard_fqdn_group(self, device_id: str, data: dict,
                                  vdom: Optional[str] = None) -> List[Content]:
        """Create wildcard FQDN group."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_wildcard_fqdn_group(data, vdom=vdom)
            return self._format_operation_result("create wildcard FQDN group", device_id, True, "Wildcard FQDN group created successfully")
        except Exception as e:
            return self._handle_error("create wildcard FQDN group", device_id, e)

    async def update_wildcard_fqdn_group(self, device_id: str, name: str, data: dict,
                                  vdom: Optional[str] = None) -> List[Content]:
        """Update wildcard FQDN group."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_wildcard_fqdn_group(name, data, vdom=vdom)
            return self._format_operation_result("update wildcard FQDN group", device_id, True, f"Wildcard FQDN group '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update wildcard FQDN group", device_id, e)

    async def delete_wildcard_fqdn_group(self, device_id: str, name: str,
                                  vdom: Optional[str] = None) -> List[Content]:
        """Delete wildcard FQDN group."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_wildcard_fqdn_group(name, vdom=vdom)
            return self._format_operation_result("delete wildcard FQDN group", device_id, True, f"Wildcard FQDN group '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete wildcard FQDN group", device_id, e)
