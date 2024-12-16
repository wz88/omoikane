from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class AclEntry(BaseModel):
    """Base model for ACL entry configuration."""
    sequence: int
    action: str  # permit/deny
    protocol: str
    source: str
    destination: str
    source_port: Optional[str] = None
    destination_port: Optional[str] = None
    source_ip: Optional[str] = None
    source_wildcard: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_wildcard: Optional[str] = None
    protocol_option: Optional[str] = None
    log: bool = False
    flags: Dict[str, bool] = Field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        if key == 'source_ip':
            return self.source_ip
        elif key == 'destination_ip':
            return self.destination_ip
        return getattr(self, key)


class Acl(BaseModel):
    """Base model for ACL configuration."""
    name: str
    type: str  # extended/standard
    protocol_option: Optional[str] = None
    entries: List[AclEntry] = Field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)
