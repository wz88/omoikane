"""AS path access list classes for network devices."""
from typing import Dict, Optional, List

from pydantic import BaseModel

class AsPathEntry(BaseModel):
    """AS path access list entry configuration."""
    sequence: int
    action: str
    pattern: str
    description: Optional[str] = None

    def __getitem__(self, item: str):
        """Get item from AS path entry."""
        return getattr(self, item)

class AsPathList(BaseModel):
    """AS path access list configuration."""
    name: str
    entries: Dict[int, AsPathEntry] = {}
    description: Optional[str] = None

    def add_entry(self, entry: AsPathEntry) -> None:
        """Add an entry to the AS path list."""
        self.entries[entry.sequence] = entry

    def remove_entry(self, sequence: int) -> None:
        """Remove an entry from the AS path list."""
        if sequence in self.entries:
            del self.entries[sequence]

    def get_entry(self, sequence: int) -> Optional[AsPathEntry]:
        """Get an entry by sequence number."""
        return self.entries.get(sequence)

    @property
    def entries_list(self) -> List[AsPathEntry]:
        """Return entries as a sorted list."""
        return [entry for _, entry in sorted(self.entries.items())]

    def __iter__(self):
        """Iterate over entries in sequence order."""
        return iter(self.entries_list)

    def __getitem__(self, item: str) -> List[AsPathEntry]:
        """Get item from AS path list."""
        if item == 'entries':
            return self.entries_list
        return getattr(self, item)
