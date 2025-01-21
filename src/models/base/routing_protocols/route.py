"""Route model."""
from ipaddress import IPv4Address, IPv4Network
import re
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

route_nh_regex = re.compile(r'\s*\*via\s+(?P<next_hop>(?:\d+\.){3}\d+|\S+)(?:%default)?,(?:\s+(?P<interface>\S+),)?\s+\[(?P<admin_distance>\d+)\/(?P<metric>\d+)\],\s+(?P<age>\S+),\s+(?P<protocol>[a-zA-Z0-9\-]+)(,\s+[a-zA-Z0-9]+)?(?:,\s+tag\s+(?P<tag>\d+))?')

protocol_map = {
    "ospf": "O",
    "bgp": "B",
    "static": "S",
    "direct": "D",
    "local": "L",
}


class Route(BaseModel):
    """Route model."""
    protocol: Optional[str] = Field(None, description="Protocol identifier (e.g., 'O' for OSPF, 'B' for BGP)")
    ospf_instance_tag: Optional[str] = Field(None, description="OSPF instance tag")
    bgp_asn: Optional[str] = Field(None, description="BGP ASN")
    name: Optional[str] = Field(None, description="Route name")
    network: IPv4Network = Field(description="Network address with prefix")
    next_hop: Optional[IPv4Address | str] = Field(None, description="Next hop IP address")
    egress_interface: Optional[str] = Field(None, description="Egress interface")
    admin_distance: int = Field(0, description="Administrative distance")
    metric: int = Field(0, description="Route metric")
    is_best: bool = Field(True, description="Whether this is the best route")
    source_protocol: Optional[str] = Field(None, description="Source protocol for redistributed routes")
    source_rid: Optional[str] = Field(None, description="Source router ID or AS number")
    tag: Optional[int] = Field(None, description="Route tag")
    age: Optional[str] = Field(None, description="Age of the route")
    attributes: List[str] = Field(default_factory=list, description="Additional route attributes")
    vrf: str = Field(default="default", description="VRF name")

    model_config = {
        "populate_by_name": True,
        "validate_assignment": True,
        "arbitrary_types_allowed": True,
        "extra": "allow",
    }

    def __init__(self, **data):
        """Initialize route."""
        super().__init__(**data)


class RoutingTable(BaseModel):
    """Routing table model."""
    vrf: str
    routes: Dict[str, List[Route]] = {}
