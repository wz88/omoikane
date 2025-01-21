from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class VlanConfig(BaseModel):
    """Base model for VLAN configuration."""
    vlan_id: int
    name: Optional[str] = None
    state: Literal["active", "suspend"] = "active"
    interfaces: List[str] = Field(default_factory=list)
    private_vlan_type: Dict[str, str|bool] = Field(default_factory=dict)  # primary, isolated, community
    description: Optional[str] = None
    access_groups: dict = Field(default_factory=dict)  # {"in": "acl_name", "out": "acl_name"}
    # NXOS specific fields
    mode: Optional[Literal["ce", "fabricpath"]] = None
    vn_segment: Optional[int] = None
    shutdown: bool = False
    xconnect: bool = False
    private_vlan_association: List[int] = Field(default_factory=list)  # For primary VLANs

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)
