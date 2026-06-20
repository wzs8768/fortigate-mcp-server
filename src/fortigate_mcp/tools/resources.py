"""Resource management tools for FortiGate MCP (IP pools, shapers, SNAT, etc.)."""
from typing import List, Optional, Dict, Any
from mcp.types import TextContent as Content
from .base import FortiGateTool

class ResourceTools(FortiGateTool):
    """Tools for FortiGate resource management."""

    # ============================================================
    # IP Pool tools
    # ============================================================
    async def list_ippools(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_ippools(vdom=vdom)
            return self._format_response(data, "ippools")
        except Exception as e:
            return self._handle_error("list IP pools", device_id, e)

    async def create_ippool(self, device_id: str, data: Dict[str, Any],
                     vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_ippool(data, vdom=vdom)
            return self._format_operation_result("create IP pool", device_id, True, "IP pool created successfully")
        except Exception as e:
            return self._handle_error("create IP pool", device_id, e)

    async def update_ippool(self, device_id: str, name: str, data: Dict[str, Any],
                     vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_ippool(name, data, vdom=vdom)
            return self._format_operation_result("update IP pool", device_id, True, f"IP pool '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update IP pool", device_id, e)

    async def delete_ippool(self, device_id: str, name: str,
                     vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_ippool(name, vdom=vdom)
            return self._format_operation_result("delete IP pool", device_id, True, f"IP pool '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete IP pool", device_id, e)

    # ============================================================
    # VIP Group tools
    # ============================================================
    async def list_vipgrps(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_vipgrps(vdom=vdom)
            return self._format_response(data, "vipgrps")
        except Exception as e:
            return self._handle_error("list VIP groups", device_id, e)

    async def create_vipgrp(self, device_id: str, data: Dict[str, Any],
                     vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_vipgrp(data, vdom=vdom)
            return self._format_operation_result("create VIP group", device_id, True, "VIP group created successfully")
        except Exception as e:
            return self._handle_error("create VIP group", device_id, e)

    async def update_vipgrp(self, device_id: str, name: str, data: Dict[str, Any],
                     vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_vipgrp(name, data, vdom=vdom)
            return self._format_operation_result("update VIP group", device_id, True, f"VIP group '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update VIP group", device_id, e)

    async def delete_vipgrp(self, device_id: str, name: str,
                     vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_vipgrp(name, vdom=vdom)
            return self._format_operation_result("delete VIP group", device_id, True, f"VIP group '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete VIP group", device_id, e)

    # ============================================================
    # Traffic Shaper tools
    # ============================================================
    async def list_traffic_shapers(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_traffic_shapers(vdom=vdom)
            return self._format_response(data, "traffic_shapers")
        except Exception as e:
            return self._handle_error("list traffic shapers", device_id, e)

    async def create_traffic_shaper(self, device_id: str, data: Dict[str, Any],
                             vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_traffic_shaper(data, vdom=vdom)
            return self._format_operation_result("create traffic shaper", device_id, True, "Traffic shaper created successfully")
        except Exception as e:
            return self._handle_error("create traffic shaper", device_id, e)

    async def update_traffic_shaper(self, device_id: str, name: str, data: Dict[str, Any],
                             vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_traffic_shaper(name, data, vdom=vdom)
            return self._format_operation_result("update traffic shaper", device_id, True, f"Traffic shaper '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update traffic shaper", device_id, e)

    async def delete_traffic_shaper(self, device_id: str, name: str,
                             vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_traffic_shaper(name, vdom=vdom)
            return self._format_operation_result("delete traffic shaper", device_id, True, f"Traffic shaper '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete traffic shaper", device_id, e)

    # ============================================================
    # Per-IP Shaper tools
    # ============================================================
    async def list_per_ip_shapers(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_per_ip_shapers(vdom=vdom)
            return self._format_response(data, "per_ip_shapers")
        except Exception as e:
            return self._handle_error("list per-IP shapers", device_id, e)

    async def create_per_ip_shaper(self, device_id: str, data: Dict[str, Any],
                            vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_per_ip_shaper(data, vdom=vdom)
            return self._format_operation_result("create per-IP shaper", device_id, True, "Per-IP shaper created successfully")
        except Exception as e:
            return self._handle_error("create per-IP shaper", device_id, e)

    async def update_per_ip_shaper(self, device_id: str, name: str, data: Dict[str, Any],
                            vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_per_ip_shaper(name, data, vdom=vdom)
            return self._format_operation_result("update per-IP shaper", device_id, True, f"Per-IP shaper '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update per-IP shaper", device_id, e)

    async def delete_per_ip_shaper(self, device_id: str, name: str,
                            vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_per_ip_shaper(name, vdom=vdom)
            return self._format_operation_result("delete per-IP shaper", device_id, True, f"Per-IP shaper '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete per-IP shaper", device_id, e)

    # ============================================================
    # Central SNAT Map tools
    # ============================================================
    async def list_central_snat_maps(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_central_snat_maps(vdom=vdom)
            return self._format_response(data, "central_snat_maps")
        except Exception as e:
            return self._handle_error("list central SNAT maps", device_id, e)

    async def create_central_snat_map(self, device_id: str, data: Dict[str, Any],
                               vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_central_snat_map(data, vdom=vdom)
            return self._format_operation_result("create central SNAT map", device_id, True, "Central SNAT map created successfully")
        except Exception as e:
            return self._handle_error("create central SNAT map", device_id, e)

    async def update_central_snat_map(self, device_id: str, policy_id: str, data: Dict[str, Any],
                               vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            api_client = self._get_device_api(device_id)
            await api_client.update_central_snat_map(policy_id, data, vdom=vdom)
            return self._format_operation_result("update central SNAT map", device_id, True, f"Central SNAT map {policy_id} updated successfully")
        except Exception as e:
            return self._handle_error("update central SNAT map", device_id, e)

    async def delete_central_snat_map(self, device_id: str, policy_id: str,
                               vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            api_client = self._get_device_api(device_id)
            await api_client.delete_central_snat_map(policy_id, vdom=vdom)
            return self._format_operation_result("delete central SNAT map", device_id, True, f"Central SNAT map {policy_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete central SNAT map", device_id, e)

    async def get_central_snat_map_detail(self, device_id: str, policy_id: str,
                                   vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_central_snat_map_detail(policy_id, vdom=vdom)
            return self._format_response(data, "central_snat_map_detail")
        except Exception as e:
            return self._handle_error("get central SNAT map detail", device_id, e)

    # ============================================================
    # IP Translation tools
    # ============================================================
    async def list_ip_translations(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_ip_translations(vdom=vdom)
            return self._format_response(data, "ip_translations")
        except Exception as e:
            return self._handle_error("list IP translations", device_id, e)

    async def create_ip_translation(self, device_id: str, data: Dict[str, Any],
                             vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_ip_translation(data, vdom=vdom)
            return self._format_operation_result("create IP translation", device_id, True, "IP translation created successfully")
        except Exception as e:
            return self._handle_error("create IP translation", device_id, e)

    async def update_ip_translation(self, device_id: str, trans_id: str, data: Dict[str, Any],
                             vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(trans_id=trans_id)
            api_client = self._get_device_api(device_id)
            await api_client.update_ip_translation(trans_id, data, vdom=vdom)
            return self._format_operation_result("update IP translation", device_id, True, f"IP translation {trans_id} updated successfully")
        except Exception as e:
            return self._handle_error("update IP translation", device_id, e)

    async def delete_ip_translation(self, device_id: str, trans_id: str,
                             vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(trans_id=trans_id)
            api_client = self._get_device_api(device_id)
            await api_client.delete_ip_translation(trans_id, vdom=vdom)
            return self._format_operation_result("delete IP translation", device_id, True, f"IP translation {trans_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete IP translation", device_id, e)

    # ============================================================
    # Identity-based Route tools
    # ============================================================
    async def list_identity_based_routes(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_identity_based_routes(vdom=vdom)
            return self._format_response(data, "identity_based_routes")
        except Exception as e:
            return self._handle_error("list identity-based routes", device_id, e)

    async def create_identity_based_route(self, device_id: str, data: Dict[str, Any],
                                   vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_identity_based_route(data, vdom=vdom)
            return self._format_operation_result("create identity-based route", device_id, True, "Identity-based route created successfully")
        except Exception as e:
            return self._handle_error("create identity-based route", device_id, e)

    async def update_identity_based_route(self, device_id: str, name: str, data: Dict[str, Any],
                                   vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_identity_based_route(name, data, vdom=vdom)
            return self._format_operation_result("update identity-based route", device_id, True, f"Identity-based route '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update identity-based route", device_id, e)

    async def delete_identity_based_route(self, device_id: str, name: str,
                                   vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_identity_based_route(name, vdom=vdom)
            return self._format_operation_result("delete identity-based route", device_id, True, f"Identity-based route '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete identity-based route", device_id, e)

    # ============================================================
    # DNS Translation tools
    # ============================================================
    async def list_dns_translations(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_dns_translations(vdom=vdom)
            return self._format_response(data, "dns_translations")
        except Exception as e:
            return self._handle_error("list DNS translations", device_id, e)

    async def create_dns_translation(self, device_id: str, data: Dict[str, Any],
                              vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_dns_translation(data, vdom=vdom)
            return self._format_operation_result("create DNS translation", device_id, True, "DNS translation created successfully")
        except Exception as e:
            return self._handle_error("create DNS translation", device_id, e)

    async def update_dns_translation(self, device_id: str, trans_id: str, data: Dict[str, Any],
                              vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(trans_id=trans_id)
            api_client = self._get_device_api(device_id)
            await api_client.update_dns_translation(trans_id, data, vdom=vdom)
            return self._format_operation_result("update DNS translation", device_id, True, f"DNS translation {trans_id} updated successfully")
        except Exception as e:
            return self._handle_error("update DNS translation", device_id, e)

    async def delete_dns_translation(self, device_id: str, trans_id: str,
                              vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(trans_id=trans_id)
            api_client = self._get_device_api(device_id)
            await api_client.delete_dns_translation(trans_id, vdom=vdom)
            return self._format_operation_result("delete DNS translation", device_id, True, f"DNS translation {trans_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete DNS translation", device_id, e)

    # ============================================================
    # TTL Policy tools
    # ============================================================
    async def list_ttl_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_ttl_policies(vdom=vdom)
            return self._format_response(data, "ttl_policies")
        except Exception as e:
            return self._handle_error("list TTL policies", device_id, e)

    async def create_ttl_policy(self, device_id: str, data: Dict[str, Any],
                         vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_ttl_policy(data, vdom=vdom)
            return self._format_operation_result("create TTL policy", device_id, True, "TTL policy created successfully")
        except Exception as e:
            return self._handle_error("create TTL policy", device_id, e)

    async def update_ttl_policy(self, device_id: str, policy_id: str, data: Dict[str, Any],
                         vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            api_client = self._get_device_api(device_id)
            await api_client.update_ttl_policy(policy_id, data, vdom=vdom)
            return self._format_operation_result("update TTL policy", device_id, True, f"TTL policy {policy_id} updated successfully")
        except Exception as e:
            return self._handle_error("update TTL policy", device_id, e)

    async def delete_ttl_policy(self, device_id: str, policy_id: str,
                         vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            api_client = self._get_device_api(device_id)
            await api_client.delete_ttl_policy(policy_id, vdom=vdom)
            return self._format_operation_result("delete TTL policy", device_id, True, f"TTL policy {policy_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete TTL policy", device_id, e)

    # ============================================================
    # Decrypted Traffic Mirror tools
    # ============================================================
    async def list_decrypted_traffic_mirrors(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_decrypted_traffic_mirrors(vdom=vdom)
            return self._format_response(data, "decrypted_traffic_mirrors")
        except Exception as e:
            return self._handle_error("list decrypted traffic mirrors", device_id, e)

    async def create_decrypted_traffic_mirror(self, device_id: str, data: Dict[str, Any],
                                       vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_decrypted_traffic_mirror(data, vdom=vdom)
            return self._format_operation_result("create decrypted traffic mirror", device_id, True, "Decrypted traffic mirror created successfully")
        except Exception as e:
            return self._handle_error("create decrypted traffic mirror", device_id, e)

    async def update_decrypted_traffic_mirror(self, device_id: str, name: str, data: Dict[str, Any],
                                       vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_decrypted_traffic_mirror(name, data, vdom=vdom)
            return self._format_operation_result("update decrypted traffic mirror", device_id, True, f"Decrypted traffic mirror '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update decrypted traffic mirror", device_id, e)

    async def delete_decrypted_traffic_mirror(self, device_id: str, name: str,
                                       vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_decrypted_traffic_mirror(name, vdom=vdom)
            return self._format_operation_result("delete decrypted traffic mirror", device_id, True, f"Decrypted traffic mirror '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete decrypted traffic mirror", device_id, e)

    # ============================================================
    # Monitor tools
    # ============================================================
    async def monitor_vpn_ipsec(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_vpn_ipsec(vdom=vdom)
            return self._format_response(data, "monitor_vpn_ipsec")
        except Exception as e:
            return self._handle_error("monitor IPSec VPN", device_id, e)

    async def monitor_vpn_ipsec_connection_count(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_vpn_ipsec_connection_count(vdom=vdom)
            return self._format_response(data, "monitor_vpn_ipsec_connection_count")
        except Exception as e:
            return self._handle_error("monitor IPSec VPN connection count", device_id, e)

    async def monitor_vpn_ssl(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_vpn_ssl(vdom=vdom)
            return self._format_response(data, "monitor_vpn_ssl")
        except Exception as e:
            return self._handle_error("monitor SSL VPN status", device_id, e)

    async def monitor_vpn_ssl_stats(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_vpn_ssl_stats(vdom=vdom)
            return self._format_response(data, "monitor_vpn_ssl_stats")
        except Exception as e:
            return self._handle_error("monitor SSL VPN statistics", device_id, e)

    async def monitor_user_firewall(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_user_firewall(vdom=vdom)
            return self._format_response(data, "monitor_user_firewall")
        except Exception as e:
            return self._handle_error("monitor firewall users", device_id, e)

    async def monitor_user_firewall_count(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_user_firewall_count(vdom=vdom)
            return self._format_response(data, "monitor_user_firewall_count")
        except Exception as e:
            return self._handle_error("monitor firewall user count", device_id, e)

    async def monitor_user_banned(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_user_banned(vdom=vdom)
            return self._format_response(data, "monitor_user_banned")
        except Exception as e:
            return self._handle_error("monitor banned users", device_id, e)

    async def monitor_user_fsso(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_user_fsso(vdom=vdom)
            return self._format_response(data, "monitor_user_fsso")
        except Exception as e:
            return self._handle_error("monitor FSSO users", device_id, e)

    async def monitor_virtual_wan_health_check(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_virtual_wan_health_check(vdom=vdom)
            return self._format_response(data, "monitor_virtual_wan_health_check")
        except Exception as e:
            return self._handle_error("monitor SD-WAN health checks", device_id, e)

    async def monitor_virtual_wan_members(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_virtual_wan_members(vdom=vdom)
            return self._format_response(data, "monitor_virtual_wan_members")
        except Exception as e:
            return self._handle_error("monitor SD-WAN members", device_id, e)

    async def monitor_virtual_wan_sla_log(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_virtual_wan_sla_log(vdom=vdom)
            return self._format_response(data, "monitor_virtual_wan_sla_log")
        except Exception as e:
            return self._handle_error("monitor SD-WAN SLA log", device_id, e)

    async def monitor_utm_app_lookup(self, device_id: str, app_name: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_utm_app_lookup(app_name=app_name, vdom=vdom)
            return self._format_response(data, "monitor_utm_app_lookup")
        except Exception as e:
            return self._handle_error("monitor UTM app lookup", device_id, e)

    async def monitor_utm_application_categories(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_utm_application_categories(vdom=vdom)
            return self._format_response(data, "monitor_utm_application_categories")
        except Exception as e:
            return self._handle_error("monitor UTM app categories", device_id, e)

    async def monitor_utm_applications(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_utm_applications(vdom=vdom)
            return self._format_response(data, "monitor_utm_applications")
        except Exception as e:
            return self._handle_error("monitor UTM applications", device_id, e)

    async def monitor_router_ipv4(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_router_ipv4(vdom=vdom)
            return self._format_response(data, "monitor_router_ipv4")
        except Exception as e:
            return self._handle_error("monitor IPv4 routing table", device_id, e)

    async def monitor_router_ipv6(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_router_ipv6(vdom=vdom)
            return self._format_response(data, "monitor_router_ipv6")
        except Exception as e:
            return self._handle_error("monitor IPv6 routing table", device_id, e)

    async def monitor_firewall_acl(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_firewall_acl(vdom=vdom)
            return self._format_response(data, "monitor_firewall_acl")
        except Exception as e:
            return self._handle_error("monitor firewall ACL", device_id, e)

    async def monitor_firewall_acl6(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_firewall_acl6(vdom=vdom)
            return self._format_response(data, "monitor_firewall_acl6")
        except Exception as e:
            return self._handle_error("monitor firewall ACL6", device_id, e)

    async def monitor_license_status(self, device_id: str) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_license_status()
            return self._format_response(data, "monitor_license_status")
        except Exception as e:
            return self._handle_error("monitor license status", device_id, e)

    async def monitor_log_current_disk_usage(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_log_current_disk_usage(vdom=vdom)
            return self._format_response(data, "monitor_log_current_disk_usage")
        except Exception as e:
            return self._handle_error("monitor log disk usage", device_id, e)

    async def monitor_log_fortianalyzer(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_log_fortianalyzer(vdom=vdom)
            return self._format_response(data, "monitor_log_fortianalyzer")
        except Exception as e:
            return self._handle_error("monitor FortiAnalyzer log status", device_id, e)

    async def monitor_log_forticloud(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_log_forticloud(vdom=vdom)
            return self._format_response(data, "monitor_log_forticloud")
        except Exception as e:
            return self._handle_error("monitor FortiCloud log status", device_id, e)

    async def monitor_ips_rate_based(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_ips_rate_based(vdom=vdom)
            return self._format_response(data, "monitor_ips_rate_based")
        except Exception as e:
            return self._handle_error("monitor IPS rate-based", device_id, e)

    async def monitor_ips_session_performance(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_ips_session_performance(vdom=vdom)
            return self._format_response(data, "monitor_ips_session_performance")
        except Exception as e:
            return self._handle_error("monitor IPS session performance", device_id, e)

    async def monitor_fortiguard_service_stats(self, device_id: str) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_fortiguard_service_stats()
            return self._format_response(data, "monitor_fortiguard_service_stats")
        except Exception as e:
            return self._handle_error("monitor FortiGuard service stats", device_id, e)

    async def monitor_geoip_query(self, device_id: str, ip: str) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_geoip_query(ip=ip)
            return self._format_response(data, "monitor_geoip_query")
        except Exception as e:
            return self._handle_error("monitor GeoIP query", device_id, e)

    async def monitor_fortiview_realtime_stats(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_fortiview_realtime_stats(vdom=vdom)
            return self._format_response(data, "monitor_fortiview_realtime_stats")
        except Exception as e:
            return self._handle_error("monitor FortiView realtime stats", device_id, e)

    async def monitor_network_arp(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_network_arp(vdom=vdom)
            return self._format_response(data, "monitor_network_arp")
        except Exception as e:
            return self._handle_error("monitor ARP table", device_id, e)

    async def monitor_network_lldp_neighbors(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_network_lldp_neighbors(vdom=vdom)
            return self._format_response(data, "monitor_network_lldp_neighbors")
        except Exception as e:
            return self._handle_error("monitor LLDP neighbors", device_id, e)

    async def monitor_network_dns_latency(self, device_id: str) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_network_dns_latency()
            return self._format_response(data, "monitor_network_dns_latency")
        except Exception as e:
            return self._handle_error("monitor DNS latency", device_id, e)

    async def monitor_network_reverse_ip_lookup(self, device_id: str, ip: str) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_network_reverse_ip_lookup(ip=ip)
            return self._format_response(data, "monitor_network_reverse_ip_lookup")
        except Exception as e:
            return self._handle_error("monitor reverse IP lookup", device_id, e)

    async def monitor_router_bgp_neighbors(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_router_bgp_neighbors(vdom=vdom)
            return self._format_response(data, "monitor_router_bgp_neighbors")
        except Exception as e:
            return self._handle_error("monitor BGP neighbors", device_id, e)

    async def monitor_router_bgp_paths(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_router_bgp_paths(vdom=vdom)
            return self._format_response(data, "monitor_router_bgp_paths")
        except Exception as e:
            return self._handle_error("monitor BGP paths", device_id, e)

    async def monitor_system_available_interfaces(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_system_available_interfaces(vdom=vdom)
            return self._format_response(data, "monitor_system_available_interfaces")
        except Exception as e:
            return self._handle_error("monitor available interfaces", device_id, e)

    async def monitor_registration_forticloud_status(self, device_id: str) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_registration_forticloud_status()
            return self._format_response(data, "monitor_registration_forticloud_status")
        except Exception as e:
            return self._handle_error("monitor FortiCloud registration", device_id, e)

    async def monitor_webfilter_fortiguard_categories(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_webfilter_fortiguard_categories(vdom=vdom)
            return self._format_response(data, "monitor_webfilter_fortiguard_categories")
        except Exception as e:
            return self._handle_error("monitor web filter categories", device_id, e)

    # --- New system/firewall monitor ---
    async def monitor_system_status(self, device_id: str) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_system_status()
            return self._format_response(data, "monitor_system_status")
        except Exception as e:
            return self._handle_error("monitor system status", device_id, e)

    @staticmethod
    def _filter_current(data: dict) -> dict:
        """Extract only current values from resource usage data.
        
        FortiGate API returns each metric as a list of dicts like:
        [{"current": 23, "last_1_min": 22, "last_10_min": 20, ...}]
        This strips everything except the 'current' scalar per metric.
        """
        import copy
        result = copy.deepcopy(data)  # F4: deep copy to avoid mutating caller's dict
        if "results" in result and isinstance(result["results"], dict):
            filtered = {}
            for key, val in result["results"].items():
                if isinstance(val, list) and len(val) > 0:
                    item = val[0]
                    if isinstance(item, dict) and "current" in item:
                        filtered[key] = item["current"]
                    else:
                        filtered[key] = item
                else:
                    filtered[key] = val
            result["results"] = filtered
        return result

    async def monitor_system_resource_usage(self, device_id: str, vdom: Optional[str] = None,
                                             scope: str = "current") -> List[Content]:
        """Get CPU, memory, and session resource usage.
        
        Args:
            device_id: Target device identifier
            vdom: Virtual Domain (optional)
            scope: Data scope — "current" (latest snapshot, default) or "full" (all history)
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_system_resource_usage(vdom=vdom, scope=scope)
            if scope == "current" and isinstance(data, dict):
                data = self._filter_current(data)
            return self._format_response(data, "monitor_system_resource_usage")
        except Exception as e:
            return self._handle_error("monitor CPU/memory/session usage", device_id, e)

    async def monitor_system_performance_status(self, device_id: str) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_system_performance_status()
            return self._format_response(data, "monitor_system_performance_status")
        except Exception as e:
            return self._handle_error("monitor system performance status", device_id, e)

    async def monitor_system_interface(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_system_interface(vdom=vdom)
            return self._format_response(data, "monitor_system_interface")
        except Exception as e:
            return self._handle_error("monitor interface bandwidth", device_id, e)

    async def monitor_system_current_admins(self, device_id: str) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_system_current_admins()
            return self._format_response(data, "monitor_system_current_admins")
        except Exception as e:
            return self._handle_error("monitor logged-in admins", device_id, e)

    async def monitor_system_firmware(self, device_id: str) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_system_firmware()
            return self._format_response(data, "monitor_system_firmware")
        except Exception as e:
            return self._handle_error("monitor firmware version", device_id, e)

    async def monitor_system_vm_information(self, device_id: str) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_system_vm_information()
            return self._format_response(data, "monitor_system_vm_information")
        except Exception as e:
            return self._handle_error("monitor VM platform info", device_id, e)

    async def monitor_firewall_policy(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_firewall_policy(vdom=vdom)
            return self._format_response(data, "monitor_firewall_policy")
        except Exception as e:
            return self._handle_error("monitor firewall policy stats", device_id, e)

    async def monitor_firewall_sessions(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_firewall_sessions(vdom=vdom)
            return self._format_response(data, "monitor_firewall_sessions")
        except Exception as e:
            return self._handle_error("monitor session table", device_id, e)

    async def monitor_firewall_policy_lookup(self, device_id: str, params: dict, vdom: Optional[str] = None) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.monitor_firewall_policy_lookup(params=params, vdom=vdom)
            return self._format_response(data, "monitor_firewall_policy_lookup")
        except Exception as e:
            return self._handle_error("monitor policy lookup", device_id, e)

    # --- Generic monitor ---
    async def monitor_request(self, device_id: str, endpoint: str,
                               params: Optional[dict] = None,
                               vdom: Optional[str] = None,
                               method: str = "GET",
                               data: Optional[dict] = None) -> List[Content]:
        """Generic monitor API — access ANY /api/v2/monitor/ endpoint (GET + POST)."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            result = await api_client.monitor_request(endpoint, params=params, vdom=vdom,
                                                       method=method, data=data)
            return self._format_response(result, f"monitor/{endpoint}")
        except Exception as e:
            return self._handle_error(f"monitor {endpoint}", device_id, e)
