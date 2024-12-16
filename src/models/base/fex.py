from typing import Any, Optional
from pydantic import BaseModel


class FexConfig(BaseModel):
    """Base model for FEX configuration."""
    id: int
    description: Optional[str] = None
    type: Optional[str] = None
    serial: Optional[str] = None
    max_links: int = 1

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)
