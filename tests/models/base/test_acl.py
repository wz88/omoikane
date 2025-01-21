"""Test ACL models."""
from models.base.policy.acl import Ipv4Acl, AclEntry

def test_acl_entry_creation():
    """Test creating an ACL entry."""
    entry = AclEntry(
        sequence=10,
        action="permit",
        protocol="ip",
        source="any",
        destination="any"
    )
    assert entry.sequence == 10
    assert entry.action == "permit"
    assert entry.protocol == "ip"
    assert entry.source == "any"
    assert entry.destination == "any"

def test_acl_entry_with_ports():
    """Test ACL entry with port numbers."""
    entry = AclEntry(
        sequence=10,
        action="permit",
        protocol="tcp",
        source="any",
        destination="any",
        source_port="eq 80",
        destination_port="eq 443"
    )
    assert entry.source_port == "eq 80"
    assert entry.destination_port == "eq 443"

def test_acl_entry_with_wildcards():
    """Test ACL entry with wildcard masks."""
    entry = AclEntry(
        sequence=10,
        action="permit",
        protocol="ip",
        source="10.0.0.0",
        destination="192.168.0.0",
        source_wildcard="0.0.0.255",
        destination_wildcard="0.0.0.255"
    )
    assert entry.source_wildcard == "0.0.0.255"
    assert entry.destination_wildcard == "0.0.0.255"

def test_acl_entry_getitem():
    """Test dictionary-like access to ACL entry."""
    entry = AclEntry(
        sequence=10,
        action="permit",
        protocol="ip",
        source="any",
        destination="any"
    )
    assert entry.sequence == 10
    assert entry.action == "permit"
    assert entry.protocol == "ip"
    assert entry.source == "any"
    assert entry.destination == "any"

def test_acl_creation():
    """Test creating an ACL."""
    acl = Ipv4Acl(name="TEST_ACL")
    assert acl.name == "TEST_ACL"
    assert acl.type == "extended"
    assert len(acl.entries) == 0

def test_acl_with_entries():
    """Test ACL with entries."""
    entries = {
        "10": AclEntry(
            sequence=10,
            action="permit",
            protocol="ip",
            source="any",
            destination="any"
        ),
        "20": AclEntry(
            sequence=20,
            action="deny",
            protocol="ip",
            source="10.0.0.0 0.0.0.255",
            destination="any"
        )
    }
    acl = Ipv4Acl(name="TEST_ACL", entries=entries)
    assert len(acl.entries) == 2
    assert acl.entries["10"].action == "permit"
    assert acl.entries["20"].action == "deny"

def test_acl_getitem():
    """Test dictionary-like access to ACL."""
    acl = Ipv4Acl(name="TEST_ACL")
    entry = AclEntry(
        sequence=10,
        action="permit",
        protocol="ip",
        source="any",
        destination="any"
    )
    acl.add_entry(entry)
    assert acl.name == "TEST_ACL"
    assert acl.type == "extended"
    assert acl.entries["10"].action == "permit"

def test_acl_add_entry():
    """Test adding entries to ACL."""
    acl = Ipv4Acl(name="TEST_ACL")
    entry = {
        "action": "permit",
        "protocol": "ip",
        "source": "any",
        "destination": "any"
    }
    acl.add_entry(entry)
    assert len(acl.entries) == 1
    assert list(acl.entries.values())[0].action == "permit"

def test_acl_remove_entry():
    """Test removing entries from ACL."""
    acl = Ipv4Acl(name="TEST_ACL")
    entry = AclEntry(
        sequence=10,
        action="permit",
        protocol="ip",
        source="any",
        destination="any"
    )
    acl.add_entry(entry)
    assert len(acl.entries) == 1
    acl.remove_entry("10")
    assert len(acl.entries) == 0

def test_acl_get_entry():
    """Test getting entries from ACL."""
    acl = Ipv4Acl(name="TEST_ACL")
    entry = AclEntry(
        sequence=10,
        action="permit",
        protocol="ip",
        source="any",
        destination="any"
    )
    acl.add_entry(entry)
    assert acl.get_entry("10") == entry
    assert acl.get_entry("20") is None

def test_acl_entries_list():
    """Test getting entries as sorted list."""
    acl = Ipv4Acl(name="TEST_ACL")
    entry1 = AclEntry(
        sequence=20,
        action="deny",
        protocol="ip",
        source="any",
        destination="any"
    )
    entry2 = AclEntry(
        sequence=10,
        action="permit",
        protocol="ip",
        source="any",
        destination="any"
    )
    acl.add_entry(entry1)
    acl.add_entry(entry2)
    entries = acl.entries_list
    assert len(entries) == 2
    assert entries[0].sequence == 10
    assert entries[1].sequence == 20

def test_acl_iteration():
    """Test iterating over ACL entries."""
    acl = Ipv4Acl(name="TEST_ACL")
    entry1 = AclEntry(
        sequence=20,
        action="deny",
        protocol="ip",
        source="any",
        destination="any"
    )
    entry2 = AclEntry(
        sequence=10,
        action="permit",
        protocol="ip",
        source="any",
        destination="any"
    )
    acl.add_entry(entry1)
    acl.add_entry(entry2)
    entries = list(acl)
    assert len(entries) == 2
    assert entries[0].sequence == 10
    assert entries[1].sequence == 20

def test_acl_contains():
    """Test checking if sequence exists in ACL."""
    acl = Ipv4Acl(name="TEST_ACL")
    entry = AclEntry(
        sequence=10,
        action="permit",
        protocol="ip",
        source="any",
        destination="any"
    )
    acl.add_entry(entry)
    assert "10" in acl
    assert "20" not in acl
