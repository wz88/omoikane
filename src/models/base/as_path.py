from typing import List, Optional
from pydantic import BaseModel, Field


class AsPathListEntry(BaseModel):
    """Base model for an AS-path access list entry."""
    sequence: Optional[int]
    action: str
    regex: str


class AsPathList(BaseModel):
    """Base model for an AS-path access list."""
    name: str
    entries: List[AsPathListEntry] = Field(default_factory=list)
