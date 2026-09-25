"""FortiGate MCP tools implementation."""

from .base import FortiGateTool
from .catalog import CatalogTools
from .cmdb import CmdbTools
from .device import DeviceTools
from .firewall import FirewallTools
from .network import NetworkTools
from .resources import ResourceTools
from .routing import RoutingTools
from .schedules import ScheduleTools
from .security import SecurityTools
from .virtual_ip import VirtualIPTools

__all__ = [
    "CatalogTools",
    "CmdbTools",
    "DeviceTools",
    "FirewallTools",
    "FortiGateTool",
    "NetworkTools",
    "ResourceTools",
    "RoutingTools",
    "ScheduleTools",
    "SecurityTools",
    "VirtualIPTools",
]
