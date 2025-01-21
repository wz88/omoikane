"""Community list model."""
from typing import Dict, Optional, Union

from pydantic import BaseModel, Field


class CommunityListEntry(BaseModel):
    """Community list entry model."""

    sequence: int
    action: str
    communities: str
    description: Optional[str] = None

    def __getitem__(self, key: str) -> Union[int, str, Optional[str]]:
        """Get item by key."""
        return getattr(self, key)


class CommunityList(BaseModel):
    """Community list model."""

    name: str
    type: str
    description: Optional[str] = None
    entries: Dict[int, CommunityListEntry] = Field(default_factory=dict)

    def __init__(self, **data):
        """Initialize CommunityList."""
        if "entries" in data and isinstance(data["entries"], list):
            # Convert list to dictionary keyed by sequence number
            entries_dict = {entry.sequence: entry for entry in sorted(data["entries"], key=lambda x: x.sequence)}
            data["entries"] = entries_dict
        elif "entries" in data and isinstance(data["entries"], dict):
            # Ensure keys are integers
            entries_dict = {}
            for key, entry in data["entries"].items():
                if isinstance(key, str):
                    entries_dict[int(key)] = entry
                else:
                    entries_dict[key] = entry
            data["entries"] = entries_dict
        super().__init__(**data)

    def __getitem__(self, key: Union[str, int]) -> Union[str, Optional[str], CommunityListEntry, Dict[int, CommunityListEntry]]:
        """Get item by key."""
        if isinstance(key, int):
            # If key is an integer, treat it as an index into the sorted entries
            sorted_entries = sorted(self.entries.values(), key=lambda x: x.sequence)
            try:
                return sorted_entries[key]
            except IndexError:
                raise KeyError(key)
        if key == "entries":
            # Return a dictionary keyed by index for backward compatibility
            sorted_entries = sorted(self.entries.values(), key=lambda x: x.sequence)
            return {i: entry for i, entry in enumerate(sorted_entries)}
        return getattr(self, key)

    def add_entry(self, entry: CommunityListEntry) -> None:
        """Add entry to community list."""
        self.entries[entry.sequence] = entry
