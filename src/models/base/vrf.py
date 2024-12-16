from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class VrfConfig(BaseModel):
    """Base model for VRF configuration."""
    name: str
    description: Optional[str] = None
    rd: Optional[str] = None
    route_targets: Dict[str, List[str]] = Field(default_factory=lambda: {"import": [], "export": []})
    interfaces: List[str] = Field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)
