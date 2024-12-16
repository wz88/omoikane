from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SnmpConfig(BaseModel):
    """Base model for SNMP configuration."""
    community: Dict[str, str] = Field(default_factory=dict)
    location: Optional[str] = None
    contact: Optional[str] = None
    traps: List[str] = Field(default_factory=list)
    host: Dict[str, Dict[str, str]] = Field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)
