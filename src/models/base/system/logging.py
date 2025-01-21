from typing import Any, List, Optional
from pydantic import BaseModel, Field


class LoggingConfig(BaseModel):
    """Base model for logging configuration."""
    buffer_size: Optional[int] = None
    console: Optional[str] = None
    monitor: Optional[str] = None
    hosts: List[str] = Field(default_factory=list)
    trap_level: Optional[str] = None
    trap: Optional[str] = None
    facility: Optional[str] = None

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)
