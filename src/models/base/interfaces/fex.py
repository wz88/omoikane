from typing import Any, List,Optional
from pydantic import BaseModel, Field


class FexConfig(BaseModel):
    """Base model for FEX configuration."""
    id: int
    description: Optional[str] = None
    interfaces: List[str] = Field(default_factory=list)
    type: Optional[str] = None
    serial: Optional[str] = None
    pinning_max_links: Optional[int] = 1
    pinning_mode: Optional[str] = None

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        """Make the model behave like a dictionary."""
        setattr(self, key, value)
