from typing import Dict, List, Optional, Set, Union
from pydantic import BaseModel, Field


class OspfNetwork(BaseModel):
    """Base model for OSPF network."""
    network: str
    wildcard: str
    area: Union[int, str]


class OspfConfig(BaseModel):
    """Base model for OSPF configuration."""
    process_id: int
    router_id: Optional[str] = None
    reference_bandwidth: Optional[int] = None
    networks: List[OspfNetwork] = Field(default_factory=list)
    passive_interfaces: Set[str] = Field(default_factory=set)
    area_auth: Dict[str, str] = Field(default_factory=dict)
