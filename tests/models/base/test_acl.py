import pytest
from src.models.base.acl import Acl, AclEntry


def test_acl_entry_creation():
    """Test creating an AclEntry instance."""
    entry = AclEntry(
        sequence=10,
        action="permit",
        protocol="ip",
        source="any",
        destination="10.0.0.0/24"
    )
    assert entry.sequence == 10
    assert entry.action == "permit"
    assert entry.protocol == "ip"
    assert entry.source == "any"
    assert entry.destination == "10.0.0.0/24"
    assert entry.source_port is None
    assert entry.destination_port is None
    assert entry.protocol_option is None
    assert entry.log is False
    assert entry.flags == {}


def test_acl_entry_with_ports():
    """Test AclEntry with port specifications."""
    entry = AclEntry(
        sequence=10,
        action="permit",
        protocol="tcp",
        source="any",
        destination="10.0.0.0/24",
        source_port="1024",
        destination_port="80"
    )
    assert entry.source_port == "1024"
    assert entry.destination_port == "80"


def test_acl_entry_with_wildcards():
    """Test AclEntry with IP wildcards."""
    entry = AclEntry(
        sequence=10,
        action="permit",
        protocol="ip",
        source="192.168.1.0",
        destination="10.0.0.0",
        source_wildcard="0.0.0.255",
        destination_wildcard="0.0.0.255",
        source_ip="192.168.1.0",
        destination_ip="10.0.0.0"
    )
    assert entry.source_wildcard == "0.0.0.255"
    assert entry.destination_wildcard == "0.0.0.255"
    assert entry.source_ip == "192.168.1.0"
    assert entry.destination_ip == "10.0.0.0"


def test_acl_entry_getitem():
    """Test AclEntry __getitem__ method."""
    entry = AclEntry(
        sequence=10,
        action="permit",
        protocol="ip",
        source="192.168.1.0",
        destination="10.0.0.0",
        source_ip="192.168.1.0",
        destination_ip="10.0.0.0"
    )
    # Test special handling of source_ip and destination_ip
    assert entry["source_ip"] == "192.168.1.0"
    assert entry["destination_ip"] == "10.0.0.0"
    # Test regular attribute access
    assert entry["sequence"] == 10
    assert entry["action"] == "permit"


def test_acl_creation():
    """Test creating an Acl instance."""
    acl = Acl(
        name="TEST_ACL",
        type="extended"
    )
    assert acl.name == "TEST_ACL"
    assert acl.type == "extended"
    assert acl.protocol_option is None
    assert acl.entries == []


def test_acl_with_entries():
    """Test Acl with entries."""
    entry1 = AclEntry(
        sequence=10,
        action="permit",
        protocol="ip",
        source="any",
        destination="10.0.0.0/24"
    )
    entry2 = AclEntry(
        sequence=20,
        action="deny",
        protocol="tcp",
        source="192.168.1.0",
        destination="any",
        destination_port="80"
    )
    
    acl = Acl(
        name="TEST_ACL",
        type="extended",
        entries=[entry1, entry2]
    )
    assert len(acl.entries) == 2
    assert acl.entries[0].sequence == 10
    assert acl.entries[1].action == "deny"


def test_acl_getitem():
    """Test Acl __getitem__ method."""
    acl = Acl(name="TEST_ACL", type="extended")
    assert acl["name"] == "TEST_ACL"
    assert acl["type"] == "extended"
    assert acl["entries"] == []
