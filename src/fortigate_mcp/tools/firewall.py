"""Firewall policy management tools for FortiGate MCP."""
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool

class FirewallTools(FortiGateTool):
    """Tools for FortiGate firewall policy management."""

    async def list_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List firewall policies."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            policies_data = await api_client.get_firewall_policies(vdom=vdom)
            return self._format_response(policies_data, "firewall_policies")
        except Exception as e:
            return self._handle_error("list firewall policies", device_id, e)

    def _validate_policy_data(self, policy_data: Dict[str, Any], operation: str,
                              check_schedule: bool = True) -> Optional[str]:
        """Validate firewall/security policy data before forwarding to FortiGate.

        Returns an error message string if validation fails, None if OK.
        FortiOS 8.0.0 VM returns opaque -56/-651 errors with no field-level hints,
        so we catch common mistakes here and give clear feedback to the LLM.

        Args:
            policy_data: The policy configuration dict
            operation: Human-readable operation name for error messages
            check_schedule: Whether to require 'schedule' field (True for firewall/
                           security/proxy policies; False for DoS/multicast/etc.)
        """
        # 1. schedule is mandatory for firewall/security policies
        if check_schedule and "schedule" not in policy_data:
            return (f"Missing required field 'schedule'. FortiOS 8.0.0 requires "
                    f"'schedule: \"always\"' for {operation}. Without it the API "
                    f"returns 500/-56 with no hint. Add \"schedule\": \"always\" to policy_data.")

        # 2. Multi-value fields MUST be [{"name": "..."}] format, not plain strings
        multi_value_fields = ["srcintf", "dstintf", "srcaddr", "dstaddr", "service"]
        for field in multi_value_fields:
            if field in policy_data:
                val = policy_data[field]
                if isinstance(val, str):
                    return (f"Field '{field}' is a plain string '{val}', but FortiOS 8.0.0 "
                            f"requires [{{\"name\": \"{val}\"}}] object-array format. "
                            f"Plain strings cause 500/-651 with no hint.")
                if isinstance(val, list) and len(val) > 0 and isinstance(val[0], dict):
                    if "name" not in val[0] or not val[0]["name"]:
                        return (f"Field '{field}' has empty name in member dict. "
                                f"Use [{{\"name\": \"...\"}}] format with non-empty name.")

        # 3. Security profiles require utm-status: enable
        profile_fields = ["ips-sensor", "av-profile", "ssl-ssh-profile",
                         "webfilter-profile", "dnsfilter-profile",
                         "application-list", "profile-group", "dlp-sensor",
                         "casb-profile", "profile-protocol-options"]
        has_profiles = any(f in policy_data for f in profile_fields)
        if has_profiles and policy_data.get("utm-status") != "enable":
            return ("Security profiles detected but 'utm-status' is not set to 'enable'. "
                    "FortiOS silently ignores profile bindings without utm-status: enable. "
                    "Add \"utm-status\": \"enable\" to policy_data.")

        return None  # All checks passed

    async def create_policy(self, device_id: str, policy_data: Dict[str, Any],
                     vdom: Optional[str] = None) -> List[Content]:
        """Create firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_data=policy_data)

            # Validate before hitting FortiGate (catches -56/-651 with clear messages)
            err = self._validate_policy_data(policy_data, "firewall policy")
            if err:
                return self._format_operation_result(
                    "create firewall policy", device_id, False, error=err)

            api_client = self._get_device_api(device_id)
            await api_client.create_firewall_policy(policy_data, vdom=vdom)
            return self._format_operation_result("create firewall policy", device_id, True, "Policy created successfully")
        except Exception as e:
            return self._handle_error("create firewall policy", device_id, e)

    async def update_policy(self, device_id: str, policy_id: str,
                     policy_data: Dict[str, Any], vdom: Optional[str] = None) -> List[Content]:
        """Update firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id, policy_data=policy_data)

            # Validate format and utm-status (schedule not required for updates)
            err = self._validate_policy_data(policy_data, "firewall policy update")
            if err:
                return self._format_operation_result(
                    "update firewall policy", device_id, False, error=err)

            api_client = self._get_device_api(device_id)
            await api_client.update_firewall_policy(policy_id, policy_data, vdom=vdom)
            return self._format_operation_result("update firewall policy", device_id, True, f"Policy {policy_id} updated successfully")
        except Exception as e:
            return self._handle_error("update firewall policy", device_id, e)

    async def get_policy_detail(self, device_id: str, policy_id: str,
                         vdom: Optional[str] = None) -> List[Content]:
        """Get detailed information for a specific firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)

            api_client = self._get_device_api(device_id)

            # Get policy details
            policy_data = await api_client.get_firewall_policy_detail(policy_id, vdom=vdom)

            # Get address and service objects for resolution
            try:
                address_objects = await api_client.get_address_objects(vdom=vdom)
            except Exception:
                address_objects = None

            try:
                service_objects = await api_client.get_service_objects(vdom=vdom)
            except Exception:
                service_objects = None

            return self._format_response(
                policy_data,
                "firewall_policy_detail",
                device_id=device_id,
                address_objects=address_objects,
                service_objects=service_objects
            )
        except Exception as e:
            return self._handle_error("get firewall policy detail", device_id, e)

    async def delete_policy(self, device_id: str, policy_id: str,
                     vdom: Optional[str] = None) -> List[Content]:
        """Delete firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)

            api_client = self._get_device_api(device_id)
            await api_client.delete_firewall_policy(policy_id, vdom=vdom)
            return self._format_operation_result("delete firewall policy", device_id, True, f"Policy {policy_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete firewall policy", device_id, e)

    # ============================================================
    # Security Policy tools (NGFW policy-based mode)
    # ============================================================
    async def list_security_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_security_policies(vdom=vdom)
            return self._format_response(data, "security_policies")
        except Exception as e:
            return self._handle_error("list security policies", device_id, e)

    async def create_security_policy(self, device_id: str, policy_data: Dict[str, Any],
                              vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_data=policy_data)

            err = self._validate_policy_data(policy_data, "security policy")
            if err:
                return self._format_operation_result(
                    "create security policy", device_id, False, error=err)

            api_client = self._get_device_api(device_id)
            await api_client.create_security_policy(policy_data, vdom=vdom)
            return self._format_operation_result("create security policy", device_id, True, "Security policy created successfully")
        except Exception as e:
            return self._handle_error("create security policy", device_id, e)

    async def update_security_policy(self, device_id: str, policy_id: str, policy_data: Dict[str, Any],
                              vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id, policy_data=policy_data)

            err = self._validate_policy_data(policy_data, "security policy update")
            if err:
                return self._format_operation_result(
                    "update security policy", device_id, False, error=err)
            api_client = self._get_device_api(device_id)
            await api_client.update_security_policy(policy_id, policy_data, vdom=vdom)
            return self._format_operation_result("update security policy", device_id, True, f"Security policy {policy_id} updated successfully")
        except Exception as e:
            return self._handle_error("update security policy", device_id, e)

    async def delete_security_policy(self, device_id: str, policy_id: str,
                              vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            api_client = self._get_device_api(device_id)
            await api_client.delete_security_policy(policy_id, vdom=vdom)
            return self._format_operation_result("delete security policy", device_id, True, f"Security policy {policy_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete security policy", device_id, e)

    async def get_security_policy_detail(self, device_id: str, policy_id: str,
                                  vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_security_policy_detail(policy_id, vdom=vdom)
            return self._format_response(data, "security_policy_detail")
        except Exception as e:
            return self._handle_error("get security policy detail", device_id, e)

    # ============================================================
    # Proxy Policy tools
    # ============================================================
    async def list_proxy_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_proxy_policies(vdom=vdom)
            return self._format_response(data, "proxy_policies")
        except Exception as e:
            return self._handle_error("list proxy policies", device_id, e)

    async def create_proxy_policy(self, device_id: str, policy_data: Dict[str, Any],
                           vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_data=policy_data)

            err = self._validate_policy_data(policy_data, "proxy policy")
            if err:
                return self._format_operation_result(
                    "create proxy policy", device_id, False, error=err)
            api_client = self._get_device_api(device_id)
            await api_client.create_proxy_policy(policy_data, vdom=vdom)
            return self._format_operation_result("create proxy policy", device_id, True, "Proxy policy created successfully")
        except Exception as e:
            return self._handle_error("create proxy policy", device_id, e)

    async def update_proxy_policy(self, device_id: str, policy_id: str, policy_data: Dict[str, Any],
                           vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id, policy_data=policy_data)

            err = self._validate_policy_data(policy_data, "proxy policy update")
            if err:
                return self._format_operation_result(
                    "update proxy policy", device_id, False, error=err)
            api_client = self._get_device_api(device_id)
            await api_client.update_proxy_policy(policy_id, policy_data, vdom=vdom)
            return self._format_operation_result("update proxy policy", device_id, True, f"Proxy policy {policy_id} updated successfully")
        except Exception as e:
            return self._handle_error("update proxy policy", device_id, e)

    async def delete_proxy_policy(self, device_id: str, policy_id: str,
                           vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            api_client = self._get_device_api(device_id)
            await api_client.delete_proxy_policy(policy_id, vdom=vdom)
            return self._format_operation_result("delete proxy policy", device_id, True, f"Proxy policy {policy_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete proxy policy", device_id, e)

    async def get_proxy_policy_detail(self, device_id: str, policy_id: str,
                               vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_proxy_policy_detail(policy_id, vdom=vdom)
            return self._format_response(data, "proxy_policy_detail")
        except Exception as e:
            return self._handle_error("get proxy policy detail", device_id, e)

    # ============================================================
    # Proxy Address tools
    # ============================================================
    async def list_proxy_addresses(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_proxy_addresses(vdom=vdom)
            return self._format_response(data, "proxy_addresses")
        except Exception as e:
            return self._handle_error("list proxy addresses", device_id, e)

    async def create_proxy_address(self, device_id: str, data: Dict[str, Any],
                            vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_proxy_address(data, vdom=vdom)
            return self._format_operation_result("create proxy address", device_id, True, "Proxy address created successfully")
        except Exception as e:
            return self._handle_error("create proxy address", device_id, e)

    async def update_proxy_address(self, device_id: str, name: str, data: Dict[str, Any],
                            vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_proxy_address(name, data, vdom=vdom)
            return self._format_operation_result("update proxy address", device_id, True, f"Proxy address '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update proxy address", device_id, e)

    async def delete_proxy_address(self, device_id: str, name: str,
                            vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_proxy_address(name, vdom=vdom)
            return self._format_operation_result("delete proxy address", device_id, True, f"Proxy address '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete proxy address", device_id, e)

    async def list_proxy_addrgrps(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_proxy_addrgrps(vdom=vdom)
            return self._format_response(data, "proxy_addrgrps")
        except Exception as e:
            return self._handle_error("list proxy address groups", device_id, e)

    async def create_proxy_addrgrp(self, device_id: str, data: Dict[str, Any],
                            vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_proxy_addrgrp(data, vdom=vdom)
            return self._format_operation_result("create proxy address group", device_id, True, "Proxy address group created successfully")
        except Exception as e:
            return self._handle_error("create proxy address group", device_id, e)

    async def update_proxy_addrgrp(self, device_id: str, name: str, data: Dict[str, Any],
                            vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_proxy_addrgrp(name, data, vdom=vdom)
            return self._format_operation_result("update proxy address group", device_id, True, f"Proxy address group '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update proxy address group", device_id, e)

    async def delete_proxy_addrgrp(self, device_id: str, name: str,
                            vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_proxy_addrgrp(name, vdom=vdom)
            return self._format_operation_result("delete proxy address group", device_id, True, f"Proxy address group '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete proxy address group", device_id, e)

    # ============================================================
    # Shaping Policy tools
    # ============================================================
    async def list_shaping_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_shaping_policies(vdom=vdom)
            return self._format_response(data, "shaping_policies")
        except Exception as e:
            return self._handle_error("list shaping policies", device_id, e)

    async def create_shaping_policy(self, device_id: str, policy_data: Dict[str, Any],
                             vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_data=policy_data)

            err = self._validate_policy_data(policy_data, "shaping policy", check_schedule=False)
            if err:
                return self._format_operation_result(
                    "create shaping policy", device_id, False, error=err)
            api_client = self._get_device_api(device_id)
            await api_client.create_shaping_policy(policy_data, vdom=vdom)
            return self._format_operation_result("create shaping policy", device_id, True, "Shaping policy created successfully")
        except Exception as e:
            return self._handle_error("create shaping policy", device_id, e)

    async def update_shaping_policy(self, device_id: str, policy_id: str, policy_data: Dict[str, Any],
                             vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id, policy_data=policy_data)

            err = self._validate_policy_data(policy_data, "shaping policy update", check_schedule=False)
            if err:
                return self._format_operation_result(
                    "update shaping policy", device_id, False, error=err)
            api_client = self._get_device_api(device_id)
            await api_client.update_shaping_policy(policy_id, policy_data, vdom=vdom)
            return self._format_operation_result("update shaping policy", device_id, True, f"Shaping policy {policy_id} updated successfully")
        except Exception as e:
            return self._handle_error("update shaping policy", device_id, e)

    async def delete_shaping_policy(self, device_id: str, policy_id: str,
                             vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            api_client = self._get_device_api(device_id)
            await api_client.delete_shaping_policy(policy_id, vdom=vdom)
            return self._format_operation_result("delete shaping policy", device_id, True, f"Shaping policy {policy_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete shaping policy", device_id, e)

    async def list_shaping_profiles(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_shaping_profiles(vdom=vdom)
            return self._format_response(data, "shaping_profiles")
        except Exception as e:
            return self._handle_error("list shaping profiles", device_id, e)

    async def create_shaping_profile(self, device_id: str, data: Dict[str, Any],
                              vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_shaping_profile(data, vdom=vdom)
            return self._format_operation_result("create shaping profile", device_id, True, "Shaping profile created successfully")
        except Exception as e:
            return self._handle_error("create shaping profile", device_id, e)

    async def update_shaping_profile(self, device_id: str, name: str, data: Dict[str, Any],
                              vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_shaping_profile(name, data, vdom=vdom)
            return self._format_operation_result("update shaping profile", device_id, True, f"Shaping profile '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update shaping profile", device_id, e)

    async def delete_shaping_profile(self, device_id: str, name: str,
                              vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_shaping_profile(name, vdom=vdom)
            return self._format_operation_result("delete shaping profile", device_id, True, f"Shaping profile '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete shaping profile", device_id, e)

    # ============================================================
    # DoS Policy tools
    # ============================================================
    async def list_dos_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_dos_policies(vdom=vdom)
            return self._format_response(data, "dos_policies")
        except Exception as e:
            return self._handle_error("list DoS policies", device_id, e)

    async def create_dos_policy(self, device_id: str, policy_data: Dict[str, Any],
                         vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_data=policy_data)

            err = self._validate_policy_data(policy_data, "DoS policy", check_schedule=False)
            if err:
                return self._format_operation_result(
                    "create dos policy", device_id, False, error=err)
            api_client = self._get_device_api(device_id)
            await api_client.create_dos_policy(policy_data, vdom=vdom)
            return self._format_operation_result("create DoS policy", device_id, True, "DoS policy created successfully")
        except Exception as e:
            return self._handle_error("create DoS policy", device_id, e)

    async def update_dos_policy(self, device_id: str, policy_id: str, policy_data: Dict[str, Any],
                         vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id, policy_data=policy_data)

            err = self._validate_policy_data(policy_data, "DoS policy update", check_schedule=False)
            if err:
                return self._format_operation_result(
                    "update dos policy", device_id, False, error=err)
            api_client = self._get_device_api(device_id)
            await api_client.update_dos_policy(policy_id, policy_data, vdom=vdom)
            return self._format_operation_result("update DoS policy", device_id, True, f"DoS policy {policy_id} updated successfully")
        except Exception as e:
            return self._handle_error("update DoS policy", device_id, e)

    async def delete_dos_policy(self, device_id: str, policy_id: str,
                         vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            api_client = self._get_device_api(device_id)
            await api_client.delete_dos_policy(policy_id, vdom=vdom)
            return self._format_operation_result("delete DoS policy", device_id, True, f"DoS policy {policy_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete DoS policy", device_id, e)

    # ============================================================
    # Local-in Policy tools
    # ============================================================
    async def list_local_in_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_local_in_policies(vdom=vdom)
            return self._format_response(data, "local_in_policies")
        except Exception as e:
            return self._handle_error("list local-in policies", device_id, e)

    async def create_local_in_policy(self, device_id: str, policy_data: Dict[str, Any],
                              vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_data=policy_data)

            err = self._validate_policy_data(policy_data, "local-in policy", check_schedule=False)
            if err:
                return self._format_operation_result(
                    "create local in policy", device_id, False, error=err)
            api_client = self._get_device_api(device_id)
            await api_client.create_local_in_policy(policy_data, vdom=vdom)
            return self._format_operation_result("create local-in policy", device_id, True, "Local-in policy created successfully")
        except Exception as e:
            return self._handle_error("create local-in policy", device_id, e)

    async def update_local_in_policy(self, device_id: str, policy_id: str, policy_data: Dict[str, Any],
                              vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id, policy_data=policy_data)

            err = self._validate_policy_data(policy_data, "local-in policy update", check_schedule=False)
            if err:
                return self._format_operation_result(
                    "update local in policy", device_id, False, error=err)
            api_client = self._get_device_api(device_id)
            await api_client.update_local_in_policy(policy_id, policy_data, vdom=vdom)
            return self._format_operation_result("update local-in policy", device_id, True, f"Local-in policy {policy_id} updated successfully")
        except Exception as e:
            return self._handle_error("update local-in policy", device_id, e)

    async def delete_local_in_policy(self, device_id: str, policy_id: str,
                              vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            api_client = self._get_device_api(device_id)
            await api_client.delete_local_in_policy(policy_id, vdom=vdom)
            return self._format_operation_result("delete local-in policy", device_id, True, f"Local-in policy {policy_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete local-in policy", device_id, e)

    # ============================================================
    # Interface Policy tools
    # ============================================================
    async def list_interface_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_interface_policies(vdom=vdom)
            return self._format_response(data, "interface_policies")
        except Exception as e:
            return self._handle_error("list interface policies", device_id, e)

    async def create_interface_policy(self, device_id: str, policy_data: Dict[str, Any],
                               vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_data=policy_data)

            err = self._validate_policy_data(policy_data, "interface policy", check_schedule=False)
            if err:
                return self._format_operation_result(
                    "create interface policy", device_id, False, error=err)
            api_client = self._get_device_api(device_id)
            await api_client.create_interface_policy(policy_data, vdom=vdom)
            return self._format_operation_result("create interface policy", device_id, True, "Interface policy created successfully")
        except Exception as e:
            return self._handle_error("create interface policy", device_id, e)

    async def update_interface_policy(self, device_id: str, policy_id: str, policy_data: Dict[str, Any],
                               vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id, policy_data=policy_data)

            err = self._validate_policy_data(policy_data, "interface policy update", check_schedule=False)
            if err:
                return self._format_operation_result(
                    "update interface policy", device_id, False, error=err)
            api_client = self._get_device_api(device_id)
            await api_client.update_interface_policy(policy_id, policy_data, vdom=vdom)
            return self._format_operation_result("update interface policy", device_id, True, f"Interface policy {policy_id} updated successfully")
        except Exception as e:
            return self._handle_error("update interface policy", device_id, e)

    async def delete_interface_policy(self, device_id: str, policy_id: str,
                               vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            api_client = self._get_device_api(device_id)
            await api_client.delete_interface_policy(policy_id, vdom=vdom)
            return self._format_operation_result("delete interface policy", device_id, True, f"Interface policy {policy_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete interface policy", device_id, e)

    # ============================================================
    # Multicast Policy tools
    # ============================================================
    async def list_multicast_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_multicast_policies(vdom=vdom)
            return self._format_response(data, "multicast_policies")
        except Exception as e:
            return self._handle_error("list multicast policies", device_id, e)

    async def create_multicast_policy(self, device_id: str, policy_data: Dict[str, Any],
                               vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_data=policy_data)

            err = self._validate_policy_data(policy_data, "multicast policy", check_schedule=False)
            if err:
                return self._format_operation_result(
                    "create multicast policy", device_id, False, error=err)
            api_client = self._get_device_api(device_id)
            await api_client.create_multicast_policy(policy_data, vdom=vdom)
            return self._format_operation_result("create multicast policy", device_id, True, "Multicast policy created successfully")
        except Exception as e:
            return self._handle_error("create multicast policy", device_id, e)

    async def update_multicast_policy(self, device_id: str, policy_id: str, policy_data: Dict[str, Any],
                               vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id, policy_data=policy_data)

            err = self._validate_policy_data(policy_data, "multicast policy update", check_schedule=False)
            if err:
                return self._format_operation_result(
                    "update multicast policy", device_id, False, error=err)
            api_client = self._get_device_api(device_id)
            await api_client.update_multicast_policy(policy_id, policy_data, vdom=vdom)
            return self._format_operation_result("update multicast policy", device_id, True, f"Multicast policy {policy_id} updated successfully")
        except Exception as e:
            return self._handle_error("update multicast policy", device_id, e)

    async def delete_multicast_policy(self, device_id: str, policy_id: str,
                               vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            api_client = self._get_device_api(device_id)
            await api_client.delete_multicast_policy(policy_id, vdom=vdom)
            return self._format_operation_result("delete multicast policy", device_id, True, f"Multicast policy {policy_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete multicast policy", device_id, e)

    async def list_multicast_addresses(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_multicast_addresses(vdom=vdom)
            return self._format_response(data, "multicast_addresses")
        except Exception as e:
            return self._handle_error("list multicast addresses", device_id, e)

    async def create_multicast_address(self, device_id: str, data: Dict[str, Any],
                                vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_multicast_address(data, vdom=vdom)
            return self._format_operation_result("create multicast address", device_id, True, "Multicast address created successfully")
        except Exception as e:
            return self._handle_error("create multicast address", device_id, e)

    async def update_multicast_address(self, device_id: str, name: str, data: Dict[str, Any],
                                vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_multicast_address(name, data, vdom=vdom)
            return self._format_operation_result("update multicast address", device_id, True, f"Multicast address '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update multicast address", device_id, e)

    async def delete_multicast_address(self, device_id: str, name: str,
                                vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_multicast_address(name, vdom=vdom)
            return self._format_operation_result("delete multicast address", device_id, True, f"Multicast address '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete multicast address", device_id, e)

    # ============================================================
    # Sniffer tools
    # ============================================================
    async def list_sniffers(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_sniffers(vdom=vdom)
            return self._format_response(data, "sniffers")
        except Exception as e:
            return self._handle_error("list sniffers", device_id, e)

    async def create_sniffer(self, device_id: str, data: Dict[str, Any],
                      vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_sniffer(data, vdom=vdom)
            return self._format_operation_result("create sniffer", device_id, True, "Sniffer created successfully")
        except Exception as e:
            return self._handle_error("create sniffer", device_id, e)

    async def update_sniffer(self, device_id: str, sniffer_id: str, data: Dict[str, Any],
                      vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(sniffer_id=sniffer_id)
            api_client = self._get_device_api(device_id)
            await api_client.update_sniffer(sniffer_id, data, vdom=vdom)
            return self._format_operation_result("update sniffer", device_id, True, f"Sniffer {sniffer_id} updated successfully")
        except Exception as e:
            return self._handle_error("update sniffer", device_id, e)

    async def delete_sniffer(self, device_id: str, sniffer_id: str,
                      vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(sniffer_id=sniffer_id)
            api_client = self._get_device_api(device_id)
            await api_client.delete_sniffer(sniffer_id, vdom=vdom)
            return self._format_operation_result("delete sniffer", device_id, True, f"Sniffer {sniffer_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete sniffer", device_id, e)
