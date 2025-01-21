"""Test route map models."""
from models.base.policy import RouteMap, RouteMapEntry


def test_route_map_entry_creation():
    """Test creating a RouteMapEntry instance."""
    entry = RouteMapEntry(
        sequence=10,
        action="permit",
        description="Test entry"
    )
    assert entry.sequence == 10
    assert entry.action == "permit"


def test_route_map_entry_with_conditions():
    """Test RouteMapEntry with match conditions and set actions."""
    entry = RouteMapEntry(
        sequence=10,
        action="permit",
        match_conditions={"as-path": "AS_PATH_1"},
        set_actions={"local-preference": "200"}
    )
    assert entry.match_conditions["as-path"] == "AS_PATH_1"
    assert entry.set_actions["local-preference"] == "200"


def test_route_map_entry_backward_compatibility():
    """Test backward compatibility with match_statements and set_statements."""
    entry = RouteMapEntry(
        sequence=10,
        action="permit",
        match_conditions={"as-path": "AS_PATH_1"},
        set_actions={"local-preference": "200"}
    )
    assert entry.match_conditions["as-path"] == "AS_PATH_1"
    assert entry.set_actions["local-preference"] == "200"


def test_route_map_creation():
    """Test RouteMap creation."""
    route_map = RouteMap(name="TEST_MAP")
    assert route_map.name == "TEST_MAP"
    assert len(route_map.entries) == 0


def test_route_map_with_entries():
    """Test route map initialization with entries."""
    entries = [
        RouteMapEntry(sequence=10, action="permit"),
        RouteMapEntry(sequence=20, action="deny")
    ]
    route_map = RouteMap(name="test-map", entries=entries)
    assert len(route_map.entries) == 2
    assert route_map.entries[10].action == "permit"
    assert route_map.entries[20].action == "deny"


def test_route_map_getitem():
    """Test RouteMap __getitem__ method."""
    route_map = RouteMap(name="TEST_MAP")
    assert route_map["name"] == "TEST_MAP"
    assert route_map.entries_list == []
