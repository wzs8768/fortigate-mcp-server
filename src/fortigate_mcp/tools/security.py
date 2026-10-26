"""Security profile tools for FortiGate MCP."""
from typing import Any

from mcp.types import TextContent as Content

from .base import FortiGateTool


class SecurityTools(FortiGateTool):
    """Tools for FortiGate security profiles."""

    # ============================================================
    # SSL/SSH Profile tools
    # ============================================================
    async def list_ssl_ssh_profiles(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_ssl_ssh_profiles(vdom=vdom)
            return self._format_response(data, "ssl_ssh_profiles")
        except Exception as e:
            return self._handle_error("list SSL/SSH profiles", device_id, e)

    async def create_ssl_ssh_profile(self, device_id: str, data: dict[str, Any],
                              vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_ssl_ssh_profile(data, vdom=vdom)
            return self._format_operation_result("create SSL/SSH profile", device_id, True, "SSL/SSH profile created successfully")
        except Exception as e:
            return self._handle_error("create SSL/SSH profile", device_id, e)

    async def update_ssl_ssh_profile(self, device_id: str, name: str, data: dict[str, Any],
                              vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_ssl_ssh_profile(name, data, vdom=vdom)
            return self._format_operation_result("update SSL/SSH profile", device_id, True, f"SSL/SSH profile '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update SSL/SSH profile", device_id, e)

    async def delete_ssl_ssh_profile(self, device_id: str, name: str,
                              vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_ssl_ssh_profile(name, vdom=vdom)
            return self._format_operation_result("delete SSL/SSH profile", device_id, True, f"SSL/SSH profile '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete SSL/SSH profile", device_id, e)

    # ============================================================
    # SSL Server tools
    # ============================================================
    async def list_ssl_servers(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_ssl_servers(vdom=vdom)
            return self._format_response(data, "ssl_servers")
        except Exception as e:
            return self._handle_error("list SSL servers", device_id, e)

    async def create_ssl_server(self, device_id: str, data: dict[str, Any],
                         vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_ssl_server(data, vdom=vdom)
            return self._format_operation_result("create SSL server", device_id, True, "SSL server created successfully")
        except Exception as e:
            return self._handle_error("create SSL server", device_id, e)

    async def update_ssl_server(self, device_id: str, name: str, data: dict[str, Any],
                         vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_ssl_server(name, data, vdom=vdom)
            return self._format_operation_result("update SSL server", device_id, True, f"SSL server '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update SSL server", device_id, e)

    async def delete_ssl_server(self, device_id: str, name: str,
                         vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_ssl_server(name, vdom=vdom)
            return self._format_operation_result("delete SSL server", device_id, True, f"SSL server '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete SSL server", device_id, e)

    # ============================================================
    # Profile Group tools
    # ============================================================
    async def list_profile_groups(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_profile_groups(vdom=vdom)
            return self._format_response(data, "profile_groups")
        except Exception as e:
            return self._handle_error("list profile groups", device_id, e)

    async def create_profile_group(self, device_id: str, data: dict[str, Any],
                            vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_profile_group(data, vdom=vdom)
            return self._format_operation_result("create profile group", device_id, True, "Profile group created successfully")
        except Exception as e:
            return self._handle_error("create profile group", device_id, e)

    async def update_profile_group(self, device_id: str, name: str, data: dict[str, Any],
                            vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_profile_group(name, data, vdom=vdom)
            return self._format_operation_result("update profile group", device_id, True, f"Profile group '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update profile group", device_id, e)

    async def delete_profile_group(self, device_id: str, name: str,
                            vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_profile_group(name, vdom=vdom)
            return self._format_operation_result("delete profile group", device_id, True, f"Profile group '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete profile group", device_id, e)

    # ============================================================
    # Profile Protocol Options tools
    # ============================================================
    async def list_profile_protocol_options(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_profile_protocol_options(vdom=vdom)
            return self._format_response(data, "profile_protocol_options")
        except Exception as e:
            return self._handle_error("list profile protocol options", device_id, e)

    async def create_profile_protocol_options(self, device_id: str, data: dict[str, Any],
                                       vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_profile_protocol_options(data, vdom=vdom)
            return self._format_operation_result("create profile protocol options", device_id, True, "Profile protocol options created successfully")
        except Exception as e:
            return self._handle_error("create profile protocol options", device_id, e)

    async def update_profile_protocol_options(self, device_id: str, name: str, data: dict[str, Any],
                                       vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_profile_protocol_options(name, data, vdom=vdom)
            return self._format_operation_result("update profile protocol options", device_id, True, f"Profile protocol options '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update profile protocol options", device_id, e)

    async def delete_profile_protocol_options(self, device_id: str, name: str,
                                       vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_profile_protocol_options(name, vdom=vdom)
            return self._format_operation_result("delete profile protocol options", device_id, True, f"Profile protocol options '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete profile protocol options", device_id, e)

    # ============================================================
    # IPS Sensor tools
    # ============================================================
    async def list_ips_sensors(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_ips_sensors(vdom=vdom)
            return self._format_response(data, "ips_sensors")
        except Exception as e:
            return self._handle_error("list IPS sensors", device_id, e)

    async def create_ips_sensor(self, device_id: str, data: dict[str, Any],
                         vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_ips_sensor(data, vdom=vdom)
            return self._format_operation_result("create IPS sensor", device_id, True, "IPS sensor created successfully")
        except Exception as e:
            return self._handle_error("create IPS sensor", device_id, e)

    async def update_ips_sensor(self, device_id: str, name: str, data: dict[str, Any],
                         vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_ips_sensor(name, data, vdom=vdom)
            return self._format_operation_result("update IPS sensor", device_id, True, f"IPS sensor '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update IPS sensor", device_id, e)

    async def delete_ips_sensor(self, device_id: str, name: str,
                         vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_ips_sensor(name, vdom=vdom)
            return self._format_operation_result("delete IPS sensor", device_id, True, f"IPS sensor '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete IPS sensor", device_id, e)

    async def get_ips_sensor_detail(self, device_id: str, name: str,
                             vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_ips_sensor_detail(name, vdom=vdom)
            return self._format_response(data, "ips_sensor_detail")
        except Exception as e:
            return self._handle_error("get IPS sensor detail", device_id, e)

    # ============================================================
    # Firewall Global settings
    # ============================================================
    async def get_firewall_global(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_firewall_global(vdom=vdom)
            return self._format_response(data, "firewall_global")
        except Exception as e:
            return self._handle_error("get firewall global", device_id, e)

    async def update_firewall_global(self, device_id: str, data: dict[str, Any],
                              vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.update_firewall_global(data, vdom=vdom)
            return self._format_operation_result("update firewall global", device_id, True, "Firewall global settings updated successfully")
        except Exception as e:
            return self._handle_error("update firewall global", device_id, e)

    # ============================================================
    # Log Settings tools
    # ============================================================
    async def get_log_setting(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_log_setting(vdom=vdom)
            return self._format_response(data, "log_setting")
        except Exception as e:
            return self._handle_error("get log setting", device_id, e)

    async def update_log_setting(self, device_id: str, data: dict[str, Any],
                          vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.update_log_setting(data, vdom=vdom)
            return self._format_operation_result("update log setting", device_id, True, "Log settings updated successfully")
        except Exception as e:
            return self._handle_error("update log setting", device_id, e)

    async def get_log_disk_setting(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_log_disk_setting(vdom=vdom)
            return self._format_response(data, "log_disk_setting")
        except Exception as e:
            return self._handle_error("get log disk setting", device_id, e)

    async def update_log_disk_setting(self, device_id: str, data: dict[str, Any],
                               vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.update_log_disk_setting(data, vdom=vdom)
            return self._format_operation_result("update log disk setting", device_id, True, "Log disk settings updated successfully")
        except Exception as e:
            return self._handle_error("update log disk setting", device_id, e)

    async def get_log_fortianalyzer_setting(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_log_fortianalyzer_setting(vdom=vdom)
            return self._format_response(data, "log_faz_setting")
        except Exception as e:
            return self._handle_error("get FortiAnalyzer log setting", device_id, e)

    async def update_log_fortianalyzer_setting(self, device_id: str, data: dict[str, Any],
                                        vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.update_log_fortianalyzer_setting(data, vdom=vdom)
            return self._format_operation_result("update FortiAnalyzer log setting", device_id, True, "FortiAnalyzer log settings updated successfully")
        except Exception as e:
            return self._handle_error("update FortiAnalyzer log setting", device_id, e)

    async def get_log_syslogd_setting(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_log_syslogd_setting(vdom=vdom)
            return self._format_response(data, "log_syslogd_setting")
        except Exception as e:
            return self._handle_error("get syslog setting", device_id, e)

    async def update_log_syslogd_setting(self, device_id: str, data: dict[str, Any],
                                  vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.update_log_syslogd_setting(data, vdom=vdom)
            return self._format_operation_result("update syslog setting", device_id, True, "Syslog settings updated successfully")
        except Exception as e:
            return self._handle_error("update syslog setting", device_id, e)

    # ============================================================
    # Authentication tools
    # ============================================================
    async def list_auth_rules(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_auth_rules(vdom=vdom)
            return self._format_response(data, "auth_rules")
        except Exception as e:
            return self._handle_error("list auth rules", device_id, e)

    async def create_auth_rule(self, device_id: str, data: dict[str, Any],
                        vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_auth_rule(data, vdom=vdom)
            return self._format_operation_result("create auth rule", device_id, True, "Auth rule created successfully")
        except Exception as e:
            return self._handle_error("create auth rule", device_id, e)

    async def delete_auth_rule(self, device_id: str, name: str,
                        vdom: str | None = None) -> list[Content]:
        """Delete authentication rule."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_auth_rule(name, vdom=vdom)
            return self._format_operation_result("delete auth rule", device_id, True, f"Auth rule '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete auth rule", device_id, e)

    async def list_auth_schemes(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_auth_schemes(vdom=vdom)
            return self._format_response(data, "auth_schemes")
        except Exception as e:
            return self._handle_error("list auth schemes", device_id, e)

    async def get_auth_setting(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_auth_setting(vdom=vdom)
            return self._format_response(data, "auth_setting")
        except Exception as e:
            return self._handle_error("get auth setting", device_id, e)

    # ============================================================
    # DNS Filter tools
    # ============================================================
    async def list_dnsfilter_profiles(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_dnsfilter_profiles(vdom=vdom)
            return self._format_response(data, "dnsfilter_profiles")
        except Exception as e:
            return self._handle_error("list DNS filter profiles", device_id, e)

    async def create_dnsfilter_profile(self, device_id: str, data: dict[str, Any],
                                vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_dnsfilter_profile(data, vdom=vdom)
            return self._format_operation_result("create DNS filter profile", device_id, True, "DNS filter profile created successfully")
        except Exception as e:
            return self._handle_error("create DNS filter profile", device_id, e)

    async def delete_dnsfilter_profile(self, device_id: str, name: str,
                                vdom: str | None = None) -> list[Content]:
        """Delete DNS filter profile."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_dnsfilter_profile(name, vdom=vdom)
            return self._format_operation_result("delete DNS filter profile", device_id, True, f"DNS filter profile '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete DNS filter profile", device_id, e)

    async def list_dnsfilter_domain_filters(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_dnsfilter_domain_filters(vdom=vdom)
            return self._format_response(data, "dnsfilter_domain_filters")
        except Exception as e:
            return self._handle_error("list DNS domain filters", device_id, e)

    # ============================================================
    # DLP tools
    # ============================================================
    # FortiOS exposes nine DLP config objects with identical CRUD semantics;
    # ``settings`` is a singleton. These helpers keep each public tool method
    # to a couple of lines while the MCP surface stays object-specific.
    async def _dlp_list(self, device_id: str, object_type: str, plural: str,
                        vdom: str | None = None,
                        resource_type: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.dlp_list(object_type, vdom=vdom)
            return self._format_response(
                data, resource_type or f"dlp_{object_type.replace('-', '_')}"
            )
        except Exception as e:
            return self._handle_error(f"list DLP {plural}", device_id, e)

    async def _dlp_get(self, device_id: str, object_type: str, key: str, label: str,
                       vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=key)
            api_client = self._get_device_api(device_id)
            data = await api_client.dlp_get(object_type, key, vdom=vdom)
            return self._format_response(
                data, f"dlp_{object_type.replace('-', '_')}_detail"
            )
        except Exception as e:
            return self._handle_error(f"get DLP {label}", device_id, e)

    async def _dlp_create(self, device_id: str, object_type: str, data: dict[str, Any],
                          label: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.dlp_create(object_type, data, vdom=vdom)
            return self._format_operation_result(
                f"create DLP {label}", device_id, True, f"DLP {label} created successfully"
            )
        except Exception as e:
            return self._handle_error(f"create DLP {label}", device_id, e)

    async def _dlp_update(self, device_id: str, object_type: str, key: str,
                          data: dict[str, Any], label: str,
                          vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=key, data=data)
            api_client = self._get_device_api(device_id)
            await api_client.dlp_update(object_type, key, data, vdom=vdom)
            return self._format_operation_result(
                f"update DLP {label}", device_id, True, f"DLP {label} '{key}' updated successfully"
            )
        except Exception as e:
            return self._handle_error(f"update DLP {label}", device_id, e)

    async def _dlp_delete(self, device_id: str, object_type: str, key: str,
                          label: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=key)
            api_client = self._get_device_api(device_id)
            await api_client.dlp_delete(object_type, key, vdom=vdom)
            return self._format_operation_result(
                f"delete DLP {label}", device_id, True, f"DLP {label} '{key}' deleted successfully"
            )
        except Exception as e:
            return self._handle_error(f"delete DLP {label}", device_id, e)

    # --- data-type ---
    async def list_dlp_data_types(self, device_id: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_list(device_id, "data-type", "data types", vdom)

    async def get_dlp_data_type(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_get(device_id, "data-type", name, "data type", vdom)

    async def create_dlp_data_type(self, device_id: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_create(device_id, "data-type", data, "data type", vdom)

    async def update_dlp_data_type(self, device_id: str, name: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_update(device_id, "data-type", name, data, "data type", vdom)

    async def delete_dlp_data_type(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_delete(device_id, "data-type", name, "data type", vdom)

    # --- dictionary ---
    async def list_dlp_dictionaries(self, device_id: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_list(device_id, "dictionary", "dictionaries", vdom)

    async def get_dlp_dictionary(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_get(device_id, "dictionary", name, "dictionary", vdom)

    async def create_dlp_dictionary(self, device_id: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_create(device_id, "dictionary", data, "dictionary", vdom)

    async def update_dlp_dictionary(self, device_id: str, name: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_update(device_id, "dictionary", name, data, "dictionary", vdom)

    async def delete_dlp_dictionary(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_delete(device_id, "dictionary", name, "dictionary", vdom)

    # --- exact-data-match ---
    async def list_dlp_exact_data_matches(self, device_id: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_list(device_id, "exact-data-match", "exact data matches", vdom)

    async def get_dlp_exact_data_match(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_get(device_id, "exact-data-match", name, "exact data match", vdom)

    async def create_dlp_exact_data_match(self, device_id: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_create(device_id, "exact-data-match", data, "exact data match", vdom)

    async def update_dlp_exact_data_match(self, device_id: str, name: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_update(device_id, "exact-data-match", name, data, "exact data match", vdom)

    async def delete_dlp_exact_data_match(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_delete(device_id, "exact-data-match", name, "exact data match", vdom)

    # --- filepattern ---
    async def list_dlp_filepatterns(self, device_id: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_list(device_id, "filepattern", "file patterns", vdom)

    async def get_dlp_filepattern(self, device_id: str, filt_id: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_get(device_id, "filepattern", filt_id, "file pattern", vdom)

    async def create_dlp_filepattern(self, device_id: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_create(device_id, "filepattern", data, "file pattern", vdom)

    async def update_dlp_filepattern(self, device_id: str, filt_id: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_update(device_id, "filepattern", filt_id, data, "file pattern", vdom)

    async def delete_dlp_filepattern(self, device_id: str, filt_id: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_delete(device_id, "filepattern", filt_id, "file pattern", vdom)

    # --- fp-doc-source ---
    async def list_dlp_fp_doc_sources(self, device_id: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_list(device_id, "fp-doc-source", "FP document sources", vdom)

    async def get_dlp_fp_doc_source(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_get(device_id, "fp-doc-source", name, "FP document source", vdom)

    async def create_dlp_fp_doc_source(self, device_id: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_create(device_id, "fp-doc-source", data, "FP document source", vdom)

    async def update_dlp_fp_doc_source(self, device_id: str, name: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_update(device_id, "fp-doc-source", name, data, "FP document source", vdom)

    async def delete_dlp_fp_doc_source(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_delete(device_id, "fp-doc-source", name, "FP document source", vdom)

    # --- label ---
    async def list_dlp_labels(self, device_id: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_list(device_id, "label", "labels", vdom)

    async def get_dlp_label(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_get(device_id, "label", name, "label", vdom)

    async def create_dlp_label(self, device_id: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_create(device_id, "label", data, "label", vdom)

    async def update_dlp_label(self, device_id: str, name: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_update(device_id, "label", name, data, "label", vdom)

    async def delete_dlp_label(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_delete(device_id, "label", name, "label", vdom)

    # --- sensitivity ---
    async def list_dlp_sensitivities(self, device_id: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_list(device_id, "sensitivity", "sensitivities", vdom)

    async def get_dlp_sensitivity(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_get(device_id, "sensitivity", name, "sensitivity", vdom)

    async def create_dlp_sensitivity(self, device_id: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_create(device_id, "sensitivity", data, "sensitivity", vdom)

    async def update_dlp_sensitivity(self, device_id: str, name: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_update(device_id, "sensitivity", name, data, "sensitivity", vdom)

    async def delete_dlp_sensitivity(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_delete(device_id, "sensitivity", name, "sensitivity", vdom)

    # --- sensor ---
    async def list_dlp_sensors(self, device_id: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_list(device_id, "sensor", "sensors", vdom, "dlp_sensors")

    async def get_dlp_sensor(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_get(device_id, "sensor", name, "sensor", vdom)

    async def create_dlp_sensor(self, device_id: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_create(device_id, "sensor", data, "sensor", vdom)

    async def update_dlp_sensor(self, device_id: str, name: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_update(device_id, "sensor", name, data, "sensor", vdom)

    async def delete_dlp_sensor(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_delete(device_id, "sensor", name, "sensor", vdom)

    # --- profile ---
    async def list_dlp_profiles(self, device_id: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_list(device_id, "profile", "profiles", vdom, "dlp_profiles")

    async def get_dlp_profile(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_get(device_id, "profile", name, "profile", vdom)

    async def create_dlp_profile(self, device_id: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_create(device_id, "profile", data, "profile", vdom)

    async def update_dlp_profile(self, device_id: str, name: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        return await self._dlp_update(device_id, "profile", name, data, "profile", vdom)

    async def delete_dlp_profile(self, device_id: str, name: str, vdom: str | None = None) -> list[Content]:
        return await self._dlp_delete(device_id, "profile", name, "profile", vdom)

    # --- settings ---
    async def get_dlp_settings(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_dlp_settings(vdom=vdom)
            return self._format_response(data, "dlp_settings")
        except Exception as e:
            return self._handle_error("get DLP settings", device_id, e)

    async def update_dlp_settings(self, device_id: str, data: dict[str, Any], vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.update_dlp_settings(data, vdom=vdom)
            return self._format_operation_result(
                "update DLP settings", device_id, True, "DLP settings updated successfully"
            )
        except Exception as e:
            return self._handle_error("update DLP settings", device_id, e)

    # ============================================================
    # Email Filter tools
    # ============================================================
    async def list_emailfilter_profiles(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_emailfilter_profiles(vdom=vdom)
            return self._format_response(data, "emailfilter_profiles")
        except Exception as e:
            return self._handle_error("list email filter profiles", device_id, e)

    # ============================================================
    # Certificate tools
    # ============================================================
    async def get_certificate_ca(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_certificate_ca(vdom=vdom)
            return self._format_response(data, "certificate_ca")
        except Exception as e:
            return self._handle_error("get CA certificates", device_id, e)

    async def get_certificate_local(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_certificate_local(vdom=vdom)
            return self._format_response(data, "certificate_local")
        except Exception as e:
            return self._handle_error("get local certificates", device_id, e)

    # ============================================================
    # CASB tools
    # ============================================================
    async def list_casb_profiles(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_casb_profiles(vdom=vdom)
            return self._format_response(data, "casb_profiles")
        except Exception as e:
            return self._handle_error("list CASB profiles", device_id, e)

    # ============================================================
    # Endpoint Control tools
    # ============================================================
    async def get_endpoint_control_settings(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_endpoint_control_settings(vdom=vdom)
            return self._format_response(data, "endpoint_control_settings")
        except Exception as e:
            return self._handle_error("get endpoint control settings", device_id, e)

    # ============================================================
    # Application Control tools
    # ============================================================
    async def list_application_groups(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_application_groups(vdom=vdom)
            return self._format_response(data, "application_groups")
        except Exception as e:
            return self._handle_error("list application groups", device_id, e)

    async def list_application_lists(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_application_lists(vdom=vdom)
            return self._format_response(data, "application_lists")
        except Exception as e:
            return self._handle_error("list application lists", device_id, e)

    # ============================================================
    # Antivirus tools
    # ============================================================
    async def list_antivirus_profiles(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_antivirus_profiles(vdom=vdom)
            return self._format_response(data, "antivirus_profiles")
        except Exception as e:
            return self._handle_error("list antivirus profiles", device_id, e)

    async def get_antivirus_settings(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_antivirus_settings(vdom=vdom)
            return self._format_response(data, "antivirus_settings")
        except Exception as e:
            return self._handle_error("get antivirus settings", device_id, e)

    # ============================================================
    # Alert Email tools
    # ============================================================
    async def get_alertemail_setting(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_alertemail_setting(vdom=vdom)
            return self._format_response(data, "alertemail_setting")
        except Exception as e:
            return self._handle_error("get alert email setting", device_id, e)

    # ============================================================
    # SSH Filter tools
    # ============================================================
    async def list_ssh_filter_profiles(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_ssh_filter_profiles(vdom=vdom)
            return self._format_response(data, "ssh_filter_profiles")
        except Exception as e:
            return self._handle_error("list SSH filter profiles", device_id, e)

    # ============================================================
    # SCTP Filter tools
    # ============================================================
    async def list_sctp_filter_profiles(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_sctp_filter_profiles(vdom=vdom)
            return self._format_response(data, "sctp_filter_profiles")
        except Exception as e:
            return self._handle_error("list SCTP filter profiles", device_id, e)

    # ============================================================
    # Switch Controller tools
    # ============================================================
    async def list_switch_acl_groups(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_switch_acl_groups(vdom=vdom)
            return self._format_response(data, "switch_acl_groups")
        except Exception as e:
            return self._handle_error("list switch ACL groups", device_id, e)

    async def list_switch_8021x_policies(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_switch_8021x_policies(vdom=vdom)
            return self._format_response(data, "switch_8021x_policies")
        except Exception as e:
            return self._handle_error("list switch 802.1X policies", device_id, e)

    # ============================================================
    # User tools
    # ============================================================
    async def list_user_locals(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_user_locals(vdom=vdom)
            return self._format_response(data, "user_locals")
        except Exception as e:
            return self._handle_error("list local users", device_id, e)

    async def list_user_groups(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_user_groups(vdom=vdom)
            return self._format_response(data, "user_groups")
        except Exception as e:
            return self._handle_error("list user groups", device_id, e)

    async def list_user_ldaps(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_user_ldaps(vdom=vdom)
            return self._format_response(data, "user_ldaps")
        except Exception as e:
            return self._handle_error("list LDAP servers", device_id, e)

    async def list_user_radiuses(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_user_radiuses(vdom=vdom)
            return self._format_response(data, "user_radiuses")
        except Exception as e:
            return self._handle_error("list RADIUS servers", device_id, e)

    async def get_user_setting(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_user_setting(vdom=vdom)
            return self._format_response(data, "user_setting")
        except Exception as e:
            return self._handle_error("get user setting", device_id, e)

    # ============================================================
    # WebFilter tools
    # ============================================================
    async def list_webfilter_profiles(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_webfilter_profiles(vdom=vdom)
            return self._format_response(data, "webfilter_profiles")
        except Exception as e:
            return self._handle_error("list webfilter profiles", device_id, e)

    async def list_webfilter_urlfilters(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_webfilter_urlfilters(vdom=vdom)
            return self._format_response(data, "webfilter_urlfilters")
        except Exception as e:
            return self._handle_error("list webfilter URL filters", device_id, e)

    # ============================================================
    # Web Proxy tools
    # ============================================================
    async def list_web_proxy_profiles(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_web_proxy_profiles(vdom=vdom)
            return self._format_response(data, "web_proxy_profiles")
        except Exception as e:
            return self._handle_error("list web proxy profiles", device_id, e)

    # ============================================================
    # WAF tools
    # ============================================================
    async def list_waf_profiles(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_waf_profiles(vdom=vdom)
            return self._format_response(data, "waf_profiles")
        except Exception as e:
            return self._handle_error("list WAF profiles", device_id, e)

    # ============================================================
    # VoIP tools
    # ============================================================
    async def list_voip_profiles(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_voip_profiles(vdom=vdom)
            return self._format_response(data, "voip_profiles")
        except Exception as e:
            return self._handle_error("list VoIP profiles", device_id, e)

    # ============================================================
    # VPN - IPSec tools
    # ============================================================
    async def list_vpn_ipsec_phase1_interfaces(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_vpn_ipsec_phase1_interfaces(vdom=vdom)
            return self._format_response(data, "vpn_ipsec_phase1_interfaces")
        except Exception as e:
            return self._handle_error("list IPSec phase1 interfaces", device_id, e)

    async def list_vpn_ipsec_phase2_interfaces(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_vpn_ipsec_phase2_interfaces(vdom=vdom)
            return self._format_response(data, "vpn_ipsec_phase2_interfaces")
        except Exception as e:
            return self._handle_error("list IPSec phase2 interfaces", device_id, e)

    # ============================================================
    # VPN - SSL VPN tools
    # ============================================================
    async def get_vpn_ssl_settings(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_vpn_ssl_settings(vdom=vdom)
            return self._format_response(data, "vpn_ssl_settings")
        except Exception as e:
            return self._handle_error("get SSL VPN settings", device_id, e)

    async def list_vpn_ssl_web_portals(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_vpn_ssl_web_portals(vdom=vdom)
            return self._format_response(data, "vpn_ssl_web_portals")
        except Exception as e:
            return self._handle_error("list SSL VPN portals", device_id, e)

    # ============================================================
    # System - DHCP tools
    # ============================================================
    async def list_system_dhcp_servers(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_system_dhcp_servers(vdom=vdom)
            return self._format_response(data, "system_dhcp_servers")
        except Exception as e:
            return self._handle_error("list DHCP servers", device_id, e)

    # ============================================================
    # System - SNMP tools
    # ============================================================
    async def list_system_snmp_communities(self, device_id: str, vdom: str | None = None) -> list[Content]:
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_system_snmp_communities(vdom=vdom)
            return self._format_response(data, "system_snmp_communities")
        except Exception as e:
            return self._handle_error("list SNMP communities", device_id, e)
