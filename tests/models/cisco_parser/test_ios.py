"""Test Cisco IOS functionality."""
import pytest
from models.cisco_parser.ios import CiscoIOS


@pytest.fixture
def ios_config():
    """Load IOS configuration file."""
    with open("tests/models/cisco_parser/examples/ROUTER-DC01.txt", "r") as f:
        return f.read()


@pytest.fixture
def ios(ios_config):
    """Create a Cisco IOS device instance."""
    return CiscoIOS(config=ios_config)


def test_ios_str(ios):
    """Test string representation."""
    assert str(ios) == "CiscoIOS(hostname=ROUTER-DC01, interfaces=10)"


def test_ios_repr(ios):
    """Test repr representation."""
    assert repr(ios) == "CiscoIOS(hostname=ROUTER-DC01, interfaces=10)"


def test_ios_hostname(ios):
    """Test hostname parsing."""
    assert ios.hostname == "ROUTER-DC01"


def test_ios_interfaces(ios):
    """Test interface parsing."""
    interfaces = ios.interfaces
    assert len(interfaces) >= 6  # Minimum number of interfaces
    
    # Test specific interface properties
    gi0_0 = interfaces.get("GigabitEthernet0/0")
    assert gi0_0 is not None
    assert gi0_0.description == "WAN Interface"
    assert gi0_0.ip_address == "192.168.1.1"
    assert gi0_0.subnet_mask == "255.255.255.0"
    assert gi0_0.access_groups.get("in") == "MGMT_ACCESS"

    gi0_1 = interfaces.get("GigabitEthernet0/1")
    assert gi0_1 is not None
    assert gi0_1.description == "Customer A Interface"
    assert gi0_1.ip_address == "10.1.1.1"
    assert gi0_1.subnet_mask == "255.255.255.0"
    assert gi0_1.vrf == "CUSTOMER_A"
    assert gi0_1.access_groups.get("in") == "CUSTOMER_A_FILTER"


def test_ios_vrfs(ios):
    """Test VRF parsing."""
    vrfs = ios.vrfs
    assert len(vrfs) >= 2  # At least CUSTOMER_A and CUSTOMER_B
    
    vrf_a = vrfs.get("CUSTOMER_A")
    assert vrf_a is not None
    assert vrf_a.description == "Customer A VRF"
    assert vrf_a.rd == "65000:1"
    assert len(vrf_a.route_targets["import"]) >= 1
    assert len(vrf_a.route_targets["export"]) >= 1

    vrf_b = vrfs.get("CUSTOMER_B")
    assert vrf_b is not None
    assert vrf_b.description == "Customer B VRF"
    assert vrf_b.rd == "65000:2"
    assert len(vrf_b.route_targets["import"]) >= 1
    assert len(vrf_b.route_targets["export"]) >= 1


def test_ios_bgp_config(ios):
    """Test BGP configuration parsing."""
    bgp = ios.get_bgp_config()
    assert bgp is not None
    assert bgp.asn == 65000
    assert len(bgp.vrfs) >= 2  # At least CUSTOMER_A and CUSTOMER_B
    
    # Test global BGP properties
    assert bgp.router_id == "192.168.1.1"
    assert len(bgp.neighbors) >= 2  # At least 2 neighbors
    
    # Test VRF BGP properties
    vrf_a = bgp.vrfs.get("CUSTOMER_A")
    assert vrf_a is not None
    assert len(vrf_a.neighbors) >= 1
    assert vrf_a.rd == "65000:1"

    vrf_b = bgp.vrfs.get("CUSTOMER_B")
    assert vrf_b is not None
    assert len(vrf_b.neighbors) >= 1
    assert vrf_b.rd == "65000:2"


def test_ios_ospf_config(ios):
    """Test OSPF configuration parsing."""
    ospf = ios.get_ospf_config()
    assert ospf is not None
    assert ospf.process_id == 1
    assert ospf.router_id == "192.168.1.1"
    assert len(ospf.networks) >= 1


def test_ios_acls(ios):
    """Test ACL parsing."""
    acls = ios.get_acls()
    assert len(acls) >= 3  # At least MGMT_ACCESS, CUSTOMER_A_FILTER, CUSTOMER_B_FILTER
    
    mgmt_acl = acls.get("MGMT_ACCESS")
    assert mgmt_acl is not None
    assert len(mgmt_acl.entries) >= 2  # At least permit and deny entries
    
    customer_a_acl = acls.get("CUSTOMER_A_FILTER")
    assert customer_a_acl is not None
    assert len(customer_a_acl.entries) >= 1


def test_ios_prefix_lists(ios):
    """Test prefix-list parsing."""
    prefix_lists = ios.get_prefix_lists()
    assert len(prefix_lists) >= 2  # At least CUSTOMER_A_PREFIXES and CUSTOMER_B_PREFIXES
    
    customer_a_pl = prefix_lists.get("CUSTOMER_A_PREFIXES")
    assert customer_a_pl is not None
    assert len(customer_a_pl.entries) >= 1

    customer_b_pl = prefix_lists.get("CUSTOMER_B_PREFIXES")
    assert customer_b_pl is not None
    assert len(customer_b_pl.entries) >= 1


def test_ios_route_maps(ios):
    """Test route-map parsing."""
    route_maps = ios.get_route_maps()
    assert len(route_maps) >= 4  # At least import/export maps for both customers
    
    customer_a_import = route_maps.get("CUSTOMER_A_IMPORT")
    assert customer_a_import is not None
    assert len(customer_a_import.entries) >= 1

    customer_a_export = route_maps.get("CUSTOMER_A_EXPORT")
    assert customer_a_export is not None
    assert len(customer_a_export.entries) >= 1
