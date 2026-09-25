"""
Device management tools for FortiGate MCP.

This module provides MCP tools for managing FortiGate devices:
- Device registration and removal
- Connection testing
- System status monitoring
- VDOM discovery
"""

from mcp.types import TextContent as Content

from .base import FortiGateTool


class DeviceTools(FortiGateTool):
    """Tools for FortiGate device management."""

    async def list_devices(self) -> list[Content]:
        """List all registered FortiGate devices.

        Returns:
            List of Content objects with device information
        """
        try:
            devices_info = self.fortigate_manager.list_devices()
            return self._format_response(devices_info, "devices")
        except Exception as e:
            return self._handle_error("list devices", "all", e)

    async def get_device_status(self, device_id: str) -> list[Content]:
        """Get system status for a specific device.

        Args:
            device_id: Target device identifier

        Returns:
            List of Content objects with device status
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            status_data = await api_client.get_system_status()
            return self._format_response((device_id, status_data), "device_status")
        except Exception as e:
            return self._handle_error("get device status", device_id, e)

    async def test_device_connection(self, device_id: str) -> list[Content]:
        """Test connection to a specific device.

        Args:
            device_id: Target device identifier

        Returns:
            List of Content objects with connection test result
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            success = await api_client.test_connection()
            return self._format_connection_test(device_id, success)
        except Exception as e:
            return self._format_connection_test(device_id, False, str(e))

    async def discover_vdoms(self, device_id: str) -> list[Content]:
        """Discover VDOMs on a FortiGate device.

        Args:
            device_id: Target device identifier

        Returns:
            List of Content objects with VDOM information
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            vdoms_data = await api_client.get_vdoms()
            return self._format_response(vdoms_data, "vdoms")
        except Exception as e:
            return self._handle_error("discover VDOMs", device_id, e)

    async def add_device(self, device_id: str, host: str, port: int = 443,
                   username: str | None = None, password: str | None = None,
                   api_token: str | None = None, vdom: str = "root",
                   verify_ssl: bool = True, timeout: int = 30,
                   os_version: str | None = None) -> list[Content]:
        """Add a new FortiGate device.

        Args:
            device_id: Unique identifier for the device
            host: Device IP address or hostname
            port: HTTPS port (default: 443)
            username: Username for authentication
            password: Password for authentication
            api_token: API token for authentication (preferred)
            vdom: Virtual Domain name (default: "root")
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            os_version: Optional FortiOS version (e.g. '7.6.7', '8.0.0'). Auto-detected if not provided.

        Returns:
            List of Content objects with operation result
        """
        try:
            self._validate_required_params(device_id=device_id, host=host)

            # Check if device already exists
            if device_id in self.fortigate_manager.devices:
                return self._format_operation_result(
                    "add device", device_id, False,
                    error=f"Device '{device_id}' already exists"
                )

            # Add device to manager
            self.fortigate_manager.add_device(
                device_id=device_id,
                host=host,
                port=port,
                username=username,
                password=password,
                api_token=api_token,
                vdom=vdom,
                verify_ssl=verify_ssl,
                timeout=timeout,
                os_version=os_version,
            )

            return self._format_operation_result(
                "add device", device_id, True,
                f"Device '{device_id}' added successfully"
            )
        except Exception as e:
            return self._handle_error("add device", device_id, e)

    async def remove_device(self, device_id: str) -> list[Content]:
        """Remove a FortiGate device.

        Args:
            device_id: Device identifier to remove

        Returns:
            List of Content objects with operation result
        """
        try:
            self._validate_device_exists(device_id)
            await self.fortigate_manager.remove_device(device_id)

            return self._format_operation_result(
                "remove device", device_id, True,
                f"Device '{device_id}' removed successfully"
            )
        except Exception as e:
            return self._handle_error("remove device", device_id, e)
