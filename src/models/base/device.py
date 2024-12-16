from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field, ConfigDict
from abc import ABC, abstractmethod


class Device(BaseModel, ABC):
    """Base class for all network devices."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    hostname: Optional[str] = None
    config: Any = None
    
    @abstractmethod
    def parse_config(self, config_text: str) -> None:
        """Parse configuration text and update device attributes."""
        pass
    
    @abstractmethod
    def parse_routing_table(self, routing_table_text: str) -> None:
        """Parse routing table output and update routes."""
        pass
    
    @property
    @abstractmethod
    def interfaces(self) -> Dict[str, Any]:
        """Return all interfaces configured on the device."""
        pass

    @property
    @abstractmethod
    def vrfs(self) -> Dict[str, Any]:
        """Return all VRFs configured on the device."""
        pass
    
    @property
    @abstractmethod
    def interface_list(self) -> List[Any]:
        """Return a list of all interfaces configured on the device."""
        pass
    
    @property
    @abstractmethod
    def vrf_list(self) -> List[Any]:
        """Return a list of all VRFs configured on the device."""
        pass
    
    @abstractmethod
    def get_interface(self, name: str) -> Optional[Any]:
        """Get interface configuration by name."""
        pass
    
    @abstractmethod
    def get_vrf(self, name: str) -> Optional[Any]:
        """Get VRF configuration by name."""
        pass
    
    @abstractmethod
    def get_routes(self) -> List[Any]:
        """Get all parsed routes."""
        pass
    
    @abstractmethod
    def get_routes_by_protocol(self, protocol: str) -> List[Any]:
        """Get routes filtered by protocol."""
        pass
    
    @abstractmethod
    def get_routes_by_network(self, network: str) -> List[Any]:
        """Get routes for a specific network."""
        pass
    
    @abstractmethod
    def get_best_routes(self) -> List[Any]:
        """Get only the best routes for each network."""
        pass
    
    def __str__(self) -> str:
        return f"{self.__class__.__name__}(hostname={self.hostname}, interfaces={len(self.interfaces)})"
    
    def __repr__(self) -> str:
        return self.__str__()