"""Prefix list classes for network devices."""
from ipaddress import IPv4Network
import re
from typing import Dict, Optional, List, Literal

from pydantic import BaseModel

prefix_list_entry_regex = re.compile(r'^ip prefix-list\s+(?P<name>\S+)\s*(?:seq\s*(?P<seq>\d+))?\s+(?P<action>permit|deny)\s+(?P<prefix>\S+)\s*(?P<ge>\d+)?\s*(?P<le>\d+)?')


class PrefixListEntry(BaseModel):
    """Prefix list entry configuration."""
    sequence: int
    action: Literal["permit", "deny"]
    prefix: Optional[IPv4Network]
    ge: Optional[int] = None
    le: Optional[int] = None


class PrefixList(BaseModel):
    """Prefix list configuration."""
    name: str
    entries: Dict[str, PrefixListEntry] = {}
    description: Optional[str] = None

    def add_entry(self, entry: PrefixListEntry) -> None:
        """Add an entry to the prefix list."""
        self.entries[entry.sequence] = entry

    def remove_entry(self, sequence: int) -> None:
        """Remove an entry from the prefix list."""
        if sequence in self.entries:
            del self.entries[sequence]

    def get_entry(self, sequence: int) -> Optional[PrefixListEntry]:
        """Get an entry by sequence number."""
        return self.entries.get(sequence)

    @property
    def entries_list(self) -> List[PrefixListEntry]:
        """Return entries as a sorted list."""
        return [entry for _, entry in sorted(self.entries.items())]

    def __iter__(self):
        """Iterate over entries in sequence order."""
        return iter(self.entries_list)

    def __getitem__(self, item: str) -> List[PrefixListEntry]:
        """Get item from prefix list."""
        if item == 'entries':
            return self.entries_list
        return getattr(self, item)
