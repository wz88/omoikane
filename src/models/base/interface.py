from typing import Dict, Optional, Any
from pydantic import BaseModel, Field


class Interface(BaseModel):
    """Base model for interface configuration."""
    name: str
    description: Optional[str] = None
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    enabled: bool = True
    speed: Optional[str] = None
    duplex: Optional[str] = None
    vrf: Optional[str] = None
    access_groups: Dict[str, str] = Field(default_factory=dict)
    switchport_mode: Optional[str] = None
    vlan: Optional[int] = None
    allowed_vlans: Optional[str] = None
    fex_associate: Optional[int] = None

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)
