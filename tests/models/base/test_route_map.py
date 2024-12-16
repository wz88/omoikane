import pytest
from src.models.base.route_map import RouteMap, RouteMapEntry


def test_route_map_entry_creation():
    """Test creating a RouteMapEntry instance."""
    entry = RouteMapEntry(
        sequence=10,
        action="permit",
        description="Test route-map entry"
    )
    assert entry.sequence == 10
    assert entry.action == "permit"
    assert entry.description == "Test route-map entry"
    assert entry.match_conditions == {}
    assert entry.set_actions == {}


def test_route_map_entry_with_conditions():
    """Test RouteMapEntry with match conditions and set actions."""
    entry = RouteMapEntry(
        sequence=10,
        action="permit",
        match_conditions={"ip": ["address", "prefix-list", "TEST_PREFIX"]},
        set_actions={"community": ["123:456"]}
    )
    assert entry.match_conditions["ip"] == ["address", "prefix-list", "TEST_PREFIX"]
    assert entry.set_actions["community"] == ["123:456"]


def test_route_map_entry_backward_compatibility():
    """Test backward compatibility access via match_statements and set_statements."""
    entry = RouteMapEntry(
        sequence=10,
        action="permit",
        match_conditions={"ip": ["address", "prefix-list", "TEST_PREFIX"]},
        set_actions={"community": ["123:456"]}
    )
    # Test backward compatibility through __getitem__
    assert entry["match_statements"] == entry.match_conditions
    assert entry["set_statements"] == entry.set_actions
    # Test regular attribute access through __getitem__
    assert entry["sequence"] == 10
    assert entry["action"] == "permit"


def test_route_map_creation():
    """Test creating a RouteMap instance."""
    route_map = RouteMap(name="TEST_MAP")
    assert route_map.name == "TEST_MAP"
    assert route_map.entries == []


def test_route_map_with_entries():
    """Test RouteMap with entries."""
    entry1 = RouteMapEntry(sequence=10, action="permit")
    entry2 = RouteMapEntry(sequence=20, action="deny")
    
    route_map = RouteMap(
        name="TEST_MAP",
        entries=[entry1, entry2]
    )
    assert len(route_map.entries) == 2
    assert route_map.entries[0].sequence == 10
    assert route_map.entries[1].action == "deny"


def test_route_map_getitem():
    """Test RouteMap __getitem__ method."""
    route_map = RouteMap(name="TEST_MAP")
    assert route_map["name"] == "TEST_MAP"
    assert route_map["entries"] == []
