from typing import List
from pydantic import BaseModel, Field


class CommunityListEntry(BaseModel):
    """Base model for a community list entry."""
    action: str
    communities: List[str]


class CommunityList(BaseModel):
    """Base model for a community list."""
    name: str
    type: str
    entries: List[CommunityListEntry] = Field(default_factory=list)
