from typing import Any, Dict, List
from pydantic import BaseModel, Field


class AaaConfig(BaseModel):
    """Base model for AAA configuration."""
    authentication: Dict[str, Dict[str, List[str]]] = Field(default_factory=lambda: {"login": {}, "enable": {}})
    authorization: Dict[str, Dict[str, List[str]]] = Field(default_factory=lambda: {"exec": {}})
    accounting: Dict[str, Dict[str, Dict[str, Any]]] = Field(default_factory=lambda: {"exec": {}})
    tacacs: Dict[str, Any] = Field(default_factory=lambda: {"hosts": {}, "timeout": 5})

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)
