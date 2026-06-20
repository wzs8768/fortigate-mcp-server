"""Schedule management tools for FortiGate MCP."""
from typing import List, Optional, Dict, Any
from mcp.types import TextContent as Content
from .base import FortiGateTool

class ScheduleTools(FortiGateTool):
    """Tools for FortiGate schedule management."""

    # ============================================================
    # Onetime Schedule tools
    # ============================================================
    async def list_schedule_onetime(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List onetime schedules."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_schedule_onetime(vdom=vdom)
            return self._format_response(data, "onetime_schedules")
        except Exception as e:
            return self._handle_error("list onetime schedules", device_id, e)

    async def create_schedule_onetime(self, device_id: str, data: Dict[str, Any],
                               vdom: Optional[str] = None) -> List[Content]:
        """Create onetime schedule."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_schedule_onetime(data, vdom=vdom)
            return self._format_operation_result("create onetime schedule", device_id, True, "Onetime schedule created successfully")
        except Exception as e:
            return self._handle_error("create onetime schedule", device_id, e)

    async def update_schedule_onetime(self, device_id: str, name: str, data: Dict[str, Any],
                               vdom: Optional[str] = None) -> List[Content]:
        """Update onetime schedule."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_schedule_onetime(name, data, vdom=vdom)
            return self._format_operation_result("update onetime schedule", device_id, True, f"Onetime schedule '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update onetime schedule", device_id, e)

    async def delete_schedule_onetime(self, device_id: str, name: str,
                               vdom: Optional[str] = None) -> List[Content]:
        """Delete onetime schedule."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_schedule_onetime(name, vdom=vdom)
            return self._format_operation_result("delete onetime schedule", device_id, True, f"Onetime schedule '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete onetime schedule", device_id, e)

    # ============================================================
    # Recurring Schedule tools
    # ============================================================
    async def list_schedule_recurring(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List recurring schedules."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_schedule_recurring(vdom=vdom)
            return self._format_response(data, "recurring_schedules")
        except Exception as e:
            return self._handle_error("list recurring schedules", device_id, e)

    async def create_schedule_recurring(self, device_id: str, data: Dict[str, Any],
                                 vdom: Optional[str] = None) -> List[Content]:
        """Create recurring schedule."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_schedule_recurring(data, vdom=vdom)
            return self._format_operation_result("create recurring schedule", device_id, True, "Recurring schedule created successfully")
        except Exception as e:
            return self._handle_error("create recurring schedule", device_id, e)

    async def update_schedule_recurring(self, device_id: str, name: str, data: Dict[str, Any],
                                 vdom: Optional[str] = None) -> List[Content]:
        """Update recurring schedule."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_schedule_recurring(name, data, vdom=vdom)
            return self._format_operation_result("update recurring schedule", device_id, True, f"Recurring schedule '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update recurring schedule", device_id, e)

    async def delete_schedule_recurring(self, device_id: str, name: str,
                                 vdom: Optional[str] = None) -> List[Content]:
        """Delete recurring schedule."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_schedule_recurring(name, vdom=vdom)
            return self._format_operation_result("delete recurring schedule", device_id, True, f"Recurring schedule '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete recurring schedule", device_id, e)

    # ============================================================
    # Schedule Group tools
    # ============================================================
    async def list_schedule_group(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List schedule groups."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_schedule_group(vdom=vdom)
            return self._format_response(data, "schedule_groups")
        except Exception as e:
            return self._handle_error("list schedule groups", device_id, e)

    async def create_schedule_group(self, device_id: str, data: Dict[str, Any],
                             vdom: Optional[str] = None) -> List[Content]:
        """Create schedule group."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(data=data)
            api_client = self._get_device_api(device_id)
            await api_client.create_schedule_group(data, vdom=vdom)
            return self._format_operation_result("create schedule group", device_id, True, "Schedule group created successfully")
        except Exception as e:
            return self._handle_error("create schedule group", device_id, e)

    async def update_schedule_group(self, device_id: str, name: str, data: Dict[str, Any],
                             vdom: Optional[str] = None) -> List[Content]:
        """Update schedule group."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.update_schedule_group(name, data, vdom=vdom)
            return self._format_operation_result("update schedule group", device_id, True, f"Schedule group '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update schedule group", device_id, e)

    async def delete_schedule_group(self, device_id: str, name: str,
                             vdom: Optional[str] = None) -> List[Content]:
        """Delete schedule group."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            await api_client.delete_schedule_group(name, vdom=vdom)
            return self._format_operation_result("delete schedule group", device_id, True, f"Schedule group '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete schedule group", device_id, e)
