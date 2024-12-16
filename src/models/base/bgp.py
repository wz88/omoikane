from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class BgpNeighbor(BaseModel):
    """Base model for BGP neighbor configuration."""
    address: str
    remote_as: int
    description: Optional[str] = None
    route_maps: Dict[str, str] = Field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)


class BgpVrfConfig(BaseModel):
    """Base model for BGP VRF configuration."""
    rd: Optional[str] = None
    neighbors: List[BgpNeighbor] = Field(default_factory=list)
    redistribute: List[str] = Field(default_factory=list)
    maximum_paths: Optional[int] = None

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)


class BgpConfig(BaseModel):
    """Base model for BGP configuration."""
    asn: int
    router_id: Optional[str] = None
    vrf_configs: Dict[str, BgpVrfConfig] = Field(default_factory=dict)

    @property
    def as_number(self) -> int:
        """Alias for asn for backward compatibility."""
        return self.asn

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)
