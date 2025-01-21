"""ACL classes for network devices."""
from ipaddress import IPv4Network, IPv6Network
import re
from typing import Dict, Literal, Optional, List, Union

from pydantic import BaseModel

acl_src_regex = r'(?:host\s+(?P<src_host>(?:\d+\.){3}\d+))?(?P<src>(?:\d+\.){3}\d+(?:\/\d+|\s+(?:\d+\.){3}\d+)?|any)(?:\s+(?:eq\s+(?P<src_port>\S+)|neq\s+(?P<not_src_port>\S+)|lt\s+(?P<lt_src_port>\S+)|gt\s+(?P<gt_src_port>\S+)|range\s+(?P<src_port_lower_range>\S+)\s+(?P<src_port_upper_range>\S+)|(?P<src_msg_type>\S+)))?'
acl_dst_regex = r'(?:host\s+(?P<dst_host>(?:\d+\.){3}\d+))?(?P<dst>(?:\d+\.){3}\d+(?:\/\d+|\s+(?:\d+\.){3}\d+)?|any)(?:\s+(?:eq\s+(?P<dst_port>\S+)|neq\s+(?P<not_dst_port>\S+)|lt\s+(?P<lt_dst_port>\S+)|gt\s+(?P<gt_dst_port>\S+)|range\s+(?P<dst_port_lower_range>\S+)\s+(?P<dst_port_upper_range>\S+)|(?P<dst_msg_type>\S+)))?'
acl_entry_regex = re.compile(rf'\s*(?P<seq>\d+)?\s*(?P<action>permit|deny)\s+(?P<protocol>\S+)\s+{acl_src_regex}\s+{acl_dst_regex}\s*')


class AclEntry(BaseModel):
    """ACL entry configuration."""
    sequence: int
    action: Literal["permit", "deny"]
    protocol: Literal["ip", "tcp", "udp", "icmp", "igmp", "eigrp", "ospf", "89", "pim"]
    source: str | IPv4Network | IPv6Network
    destination: str | IPv4Network | IPv6Network
    source_port: Optional[str] = None
    not_equal_source_port: Optional[str] = None
    less_than_source_port: Optional[str] = None
    greater_than_source_port: Optional[str] = None
    source_port_lower_range: Optional[str] = None
    source_port_upper_range: Optional[str] = None
    destination_port: Optional[str] = None
    not_equal_destination_port: Optional[str] = None
    less_than_destination_port: Optional[str] = None
    greater_than_destination_port: Optional[str] = None
    destination_port_lower_range: Optional[str] = None
    destination_port_upper_range: Optional[str] = None
    source_wildcard: Optional[str] = None
    destination_wildcard: Optional[str] = None
    source_message_type: Optional[str] = None
    destination_message_type: Optional[str] = None
    log: bool = False

class Ipv4Acl(BaseModel):
    """IPv4 ACL configuration."""
    name: str
    type: str = 'extended'
    entries: Dict[str, AclEntry] = {}
    description: Optional[str] = None

    def add_entry(self, entry: Union[AclEntry, dict]) -> None:
        """Add an entry to the ACL."""
        if isinstance(entry, dict):
            # Auto-generate sequence number if not provided
            sequence = max(self.entries.keys()) + 10 if self.entries else 10
            entry = AclEntry(sequence=sequence, **entry)
        self.entries[str(entry.sequence)] = entry

    def remove_entry(self, sequence: int) -> None:
        """Remove an entry from the ACL."""
        if sequence in self.entries:
            del self.entries[sequence]

    def get_entry(self, sequence: int) -> Optional[AclEntry]:
        """Get an entry by sequence number."""
        return self.entries.get(sequence)

    @property
    def entries_list(self) -> List[AclEntry]:
        """Return entries as a sorted list."""
        return [entry for _, entry in sorted(self.entries.items())]

    def __iter__(self):
        """Iterate over entries in sequence order."""
        return iter(self.entries_list)

    def __len__(self) -> int:
        """Return number of entries."""
        return len(self.entries)

    def __contains__(self, sequence: int) -> bool:
        """Check if sequence number exists."""
        return sequence in self.entries

    def __getitem__(self, item: Union[str, int]) -> Union[str, AclEntry, List[AclEntry]]:
        """Get item from ACL."""
        if isinstance(item, int):
            return self.entries[item]
        if item == 'entries':
            return self.entries_list
        return getattr(self, item)


class Ipv6Acl(BaseModel):
    """IPv6 ACL configuration."""
    name: str
    entries: Dict[str, AclEntry] = {}
    type: str = 'extended'
    description: Optional[str] = None

    def add_entry(self, entry: Union[AclEntry, dict]) -> None:
        """Add an entry to the ACL."""
        if isinstance(entry, dict):
            # Auto-generate sequence number if not provided
            sequence = max(self.entries.keys()) + 10 if self.entries else 10
            entry = AclEntry(sequence=sequence, **entry)
        self.entries[entry.sequence] = entry

    def remove_entry(self, sequence: int) -> None:
        """Remove an entry from the ACL."""
        if sequence in self.entries:
            del self.entries[sequence]

    def get_entry(self, sequence: int) -> Optional[AclEntry]:
        """Get an entry by sequence number."""
        return self.entries.get(sequence)

    @property
    def entries_list(self) -> List[AclEntry]:
        """Return entries as a sorted list."""
        return [entry for _, entry in sorted(self.entries.items())]

    def __iter__(self):
        """Iterate over entries in sequence order."""
        return iter(self.entries_list)

    def __len__(self) -> int:
        """Return number of entries."""
        return len(self.entries)

    def __contains__(self, sequence: int) -> bool:
        """Check if sequence number exists."""
        return sequence in self.entries

    def __getitem__(self, item: Union[str, int]) -> Union[str, AclEntry, List[AclEntry]]:
        """Get item from ACL."""
        if isinstance(item, int):
            return self.entries[item]
        if item == 'entries':
            return self.entries_list
        return getattr(self, item)
