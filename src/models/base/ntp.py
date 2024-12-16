from typing import Any, Optional
from pydantic import BaseModel


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
