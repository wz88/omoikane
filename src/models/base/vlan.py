from typing import Any, List, Optional
from pydantic import BaseModel, Field


class VlanConfig(BaseModel):
    """Base model for VLAN configuration."""
    vlan_id: int
    name: Optional[str] = None
    state: str = "active"
    interfaces: List[str] = Field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)
