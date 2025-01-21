"""VRF class for network devices."""
from typing import Literal, Optional, Dict, List, Set

from pydantic import BaseModel, Field

from models.base.routing_protocols.route import Route


class VrfRouteTarget(BaseModel):
    """Base model for BGP route target configuration."""
    import_targets: List[str] | Literal["auto"] = Field(default_factory=list)
    export_targets: List[str] | Literal["auto"] = Field(default_factory=list)
    import_evpn_routes: bool = False
    export_evpn_routes: bool = False


class VrfAddressFamily(BaseModel):
    """Address family configuration for VRF."""
    family: Literal["ipv4 unicast", "ipv6 unicast"]
    route_targets: List[VrfRouteTarget] = Field(default_factory=list)


class VrfConfig(BaseModel):
    """VRF configuration."""
    name: str
    description: Optional[str] = None
    rd: Optional[str] = None
    route_targets: List[VrfRouteTarget] = Field(default_factory=list)
    interfaces: List[str] = Field(default_factory=list)
    # NXOS specific fields
    vni: Optional[int] = None
    routes: Optional[List[Route]] = Field(default_factory=list)
    address_families: Dict[Literal["ipv4 unicast", "ipv6 unicast"], VrfAddressFamily] = Field(default_factory=dict)
    
    def __getitem__(self, item: str):
        """Get item from VRF."""
        return getattr(self, item)
