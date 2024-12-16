from typing import List, Optional
from pydantic import BaseModel, Field


class PrefixListEntry(BaseModel):
    """Base model for a prefix list entry."""
    sequence: int
    action: str
    prefix: str
    ge: Optional[int] = None
    le: Optional[int] = None


class PrefixList(BaseModel):
    """Base model for a prefix list."""
    name: str
    entries: List[PrefixListEntry] = Field(default_factory=list)

    def __getitem__(self, key: str) -> any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)
