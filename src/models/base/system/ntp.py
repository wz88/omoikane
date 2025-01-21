from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class NtpServer(BaseModel):
    """Base model for NTP server configuration."""
    server: str
    key: Optional[str] = None
    prefer: Optional[bool] = None
    source_interface: Optional[str] = None
    vrf: Optional[str] = None
    version: Optional[int] = None

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)


class NtpConfig(BaseModel):
    """Base model for NTP configuration."""
    servers: Dict[str, NtpServer] = Field(default_factory=dict)
    source_interface: Optional[str] = None
    authentication: Dict[str, str] = Field(default_factory=dict)  # key: key-string
    trusted_keys: Dict[str, bool] = Field(default_factory=dict)  # key: trusted

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)
