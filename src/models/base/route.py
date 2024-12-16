from typing import List, Optional
from pydantic import BaseModel, Field


class Route(BaseModel):
    """Base model for a routing table entry."""
    protocol: str
    network: str
    next_hop: Optional[str] = None
    interface: Optional[str] = None
    admin_distance: Optional[int] = None
    metric: Optional[int] = None
    is_best: bool = False
    source_protocol: Optional[str] = None
    source_rid: Optional[str] = None
    tag: Optional[int] = None
    age: Optional[str] = None
    attributes: List[str] = Field(default_factory=list)
