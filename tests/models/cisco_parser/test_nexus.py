"""Test Cisco Nexus functionality."""

import pytest
from models.cisco_parser.nexus import CiscoNXOS


@pytest.fixture
def nexus_config():
    """Load Nexus configuration file."""
    with open("tests/models/cisco_parser/examples/NEXUS-DC01.txt", "r") as f:
        return f.read()


@pytest.fixture
def nexus(nexus_config):
    """Create a Nexus device instance."""
    return CiscoNXOS(nexus_config)


def test_nexus_str(nexus):
    """Test string representation."""
    assert str(nexus) == "CiscoNXOS(hostname=NEXUS-DC01, interfaces=10)"


def test_nexus_repr(nexus):
    """Test repr representation."""
    assert repr(nexus) == "CiscoNXOS(hostname=NEXUS-DC01, interfaces=10)"


def test_nexus_hostname(nexus):
    """Test hostname parsing."""
    assert nexus.hostname == "NEXUS-DC01"


def test_nexus_features(nexus):
    """Test feature parsing."""
    features = nexus.get_features()
    assert "bgp" in features
    assert "ospf" in features
    assert "interface-vlan" in features
    assert "vpc" in features
    assert len(features) >= 20  # Minimum number of features


def test_nexus_system_config(nexus):
    """Test system configuration parsing."""
    system_config = nexus.get_system_config()
    assert "default switchport" in system_config
    assert "jumbomtu" in system_config
    assert "qos" in system_config


def test_nexus_interfaces(nexus):
    """Test interface parsing."""
    interfaces = nexus.interfaces
    assert len(interfaces) >= 10  # Minimum number of interfaces
    
    # Test VLAN interface
    vlan2203 = interfaces.get("Vlan2203")
    assert vlan2203 is not None
    assert vlan2203.description == "L3BPD-SNSL_Front-COMMSEC-10.246.128.8/29"
    assert vlan2203.mtu == "9216"
    assert vlan2203.bandwidth == "1000000"

    # Test port-channel interface
    po205 = interfaces.get("port-channel205")
    assert po205 is not None
    assert po205.description == "SLAC-UPD-CBPSNSIP-N48GE2C-CH01&CH02-SNSL-DataIN_FRONT-CM0761112"
    assert po205.switchport_mode == "trunk"


def test_nexus_vlans(nexus):
    """Test VLAN parsing."""
    vlans = nexus.vlans
    assert len(vlans) >= 50  # Minimum number of VLANs
    
    # Test specific VLAN
    vlan50 = vlans.get("50")
    assert vlan50 is not None
    assert vlan50.name == "10.30.50.0/24_DATA_CommSec_LB-ex"
    assert vlan50.state == "active"
    assert vlan50.mode == "ce"


def test_nexus_vrfs(nexus):
    """Test VRF parsing."""
    vrfs = nexus.vrfs
    assert len(vrfs) >= 2  # At least CBA-DCN and CBA_DCN
    
    vrf_dcn = vrfs.get("CBA-DCN")
    assert vrf_dcn is not None
    assert vrf_dcn.description == "CBA-DCN"
    assert vrf_dcn.vni == "30001"
    assert len(vrf_dcn.static_routes) >= 10


def test_nexus_bgp_config(nexus):
    """Test BGP configuration parsing."""
    bgp = nexus.get_bgp_config()
    assert bgp is not None
    assert len(bgp.vrfs) >= 2
    assert len(bgp.neighbors) >= 5


def test_nexus_ospf_config(nexus):
    """Test OSPF configuration parsing."""
    ospf = nexus.get_ospf_config()
    assert ospf is not None
    assert len(ospf.networks) >= 1


def test_nexus_prefix_lists(nexus):
    """Test prefix-list parsing."""
    prefix_lists = nexus.get_prefix_lists()
    assert len(prefix_lists) >= 10
    
    # Test specific prefix list
    pl_emf = prefix_lists.get("pl-EMF-CPU-D-Batch-Routes")
    assert pl_emf is not None
    assert len(pl_emf.entries) >= 1


def test_nexus_route_maps(nexus):
    """Test route-map parsing."""
    route_maps = nexus.get_route_maps()
    assert len(route_maps) >= 5
    
    # Test specific route map
    rm_emf = route_maps.get("rm-pod-EMF-PRU-in")
    assert rm_emf is not None
    assert len(rm_emf.entries) >= 1


def test_nexus_acls(nexus):
    """Test ACL parsing."""
    acls = nexus.get_acls()
    assert len(acls) >= 10
    
    # Test specific ACL
    acl_22 = acls.get("22")
    assert acl_22 is not None
    assert len(acl_22.entries) >= 4
    assert "permit ip 10.25.0.51/32 any" in str(acl_22.entries[0])
