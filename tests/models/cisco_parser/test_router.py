import pytest
from src.models.cisco_parser.router import CiscoRouter


@pytest.fixture
def router():
    # Read the example configuration
    with open('tests/models/cisco_parser/examples/ROUTER-DC01.txt', 'r') as f:
        config_text = f.read()

    # Create router instance
    return CiscoRouter(config_text)

def test_router_str(router):
    """Test __str__ method."""
    assert str(router) == "CiscoRouter(hostname=ROUTER-DC01, interfaces=6)"

def test_router_hostname(router):
    """Test basic router attributes."""
    assert router.config.hostname == "ROUTER-DC01"

def test_router_interfaces(router):
    """Test interface parsing."""
    interfaces = router.interfaces
    assert len(interfaces) >= 6  # Loopback0, Gi0/0, Gi0/1, Gi0/2, Eth101/1/1, Eth102/1/1

def test_wan_interface(router):
    """Test WAN interface."""
    wan_interface = router.get_interface('GigabitEthernet0/0')
    assert wan_interface is not None
    assert wan_interface.description == "WAN Interface"
    assert wan_interface.ip_address == "192.168.1.1"
    assert wan_interface.subnet_mask == "255.255.255.0"
    assert 'in' in wan_interface.access_groups
    assert wan_interface.access_groups['in'] == "MGMT_ACCESS"

def test_customer_a_interface(router):
    """Test Customer A interface."""
    customer_a_interface = router.get_interface('GigabitEthernet0/1')
    assert customer_a_interface is not None
    assert customer_a_interface.description == "Customer A Interface"
    assert customer_a_interface.ip_address == "10.1.1.1"
    assert customer_a_interface.subnet_mask == "255.255.255.0"
    assert customer_a_interface.vrf == "CUSTOMER_A"
    assert 'in' in customer_a_interface.access_groups
    assert customer_a_interface.access_groups['in'] == "CUSTOMER_A_FILTER"

def test_fex_interface(router):
    """Test FEX interface."""
    fex_interface = router.get_interface('Ethernet101/1/1')
    assert fex_interface is not None
    assert fex_interface.description == "FEX101 Uplink"
    assert fex_interface.switchport_mode == "trunk"
    assert fex_interface.allowed_vlans == "10-20"
    assert fex_interface.fex_associate == 101

def test_vrfs(router):
    """Test VRFs."""
    vrfs = router.vrfs
    assert len(vrfs) == 2  # CUSTOMER_A and CUSTOMER_B

def test_customer_a_vrf(router):
    """Test Customer A VRF."""
    customer_a_vrf = router.get_vrf('CUSTOMER_A')
    assert customer_a_vrf is not None
    assert customer_a_vrf.rd == "65000:1"
    assert "65000:1" in customer_a_vrf.route_targets['import']
    assert "65000:1" in customer_a_vrf.route_targets['export']

def test_customer_b_vrf(router):
    """Test Customer B VRF."""
    customer_b_vrf = router.get_vrf('CUSTOMER_B')
    assert customer_b_vrf is not None
    assert customer_b_vrf.rd == "65000:2"
    assert "65000:2" in customer_b_vrf.route_targets['import']
    assert "65000:2" in customer_b_vrf.route_targets['export']

def test_vlans(router):
    """Test VLANs."""
    vlans = router.vlans
    assert len(vlans) == 4  # VLANs 10, 20, 30, 40

def test_vlan10(router):
    """Test VLAN 10."""
    vlan10 = router.get_vlan(10)
    assert vlan10 is not None
    assert vlan10["vlan_id"] == 10
    assert vlan10["name"] == "CUSTOMER_A_DATA"
    assert vlan10["state"] == "active"

def test_vlan20(router):
    """Test VLAN 20."""
    vlan20 = router.get_vlan(20)
    assert vlan20 is not None
    assert vlan20["vlan_id"] == 20
    assert vlan20["name"] == "CUSTOMER_A_VOICE"
    assert vlan20["state"] == "active"

def test_fex_units(router):
    """Test FEX units."""
    fex_units = router.fex_units
    assert len(fex_units) == 2  # FEX 101 and 102

def test_fex101(router):
    """Test FEX 101."""
    fex101 = router.get_fex(101)
    assert fex101 is not None
    assert fex101.description == "Customer A FEX"
    assert fex101.type == "Nexus-2248TP"
    assert fex101.max_links == 1

def test_fex102(router):
    """Test FEX 102."""
    fex102 = router.get_fex(102)
    assert fex102 is not None
    assert fex102.description == "Customer B FEX"
    assert fex102.type == "Nexus-2248TP"
    assert fex102.max_links == 1

def test_bgp_config(router):
    """Test BGP configuration."""
    bgp_config = router.bgp_config
    assert bgp_config is not None
    # Test direct property access
    assert bgp_config.as_number == 65000
    assert bgp_config.router_id == "1.1.1.1"
    # Test dictionary-style access
    assert bgp_config["as_number"] == 65000
    assert bgp_config["asn"] == 65000
    assert bgp_config["router_id"] == "1.1.1.1"

def test_customer_a_bgp(router):
    """Test BGP VRF CUSTOMER_A configuration."""
    bgp_config = router.bgp_config
    customer_a_bgp = bgp_config.vrf_configs.get('CUSTOMER_A')
    assert customer_a_bgp is not None
    assert len(customer_a_bgp.neighbors) == 1
    neighbor = customer_a_bgp.neighbors[0]
    assert neighbor.address == neighbor["address"] == "10.1.1.2"
    assert neighbor.remote_as == neighbor["remote_as"] == 65001
    assert neighbor.route_maps['in'] == neighbor["route_maps"]['in'] == "CUSTOMER_A_IMPORT"

def test_ospf_config(router):
    """Test OSPF configuration."""
    ospf_configs = router.ospf_config
    assert len(ospf_configs) == 1  # One OSPF process
    ospf_config = ospf_configs["1"]  # Process ID 1
    assert ospf_config is not None
    assert ospf_config.process_id == 1
    assert ospf_config.router_id == "1.1.1.1"
    assert ospf_config.reference_bandwidth == 100000
    assert len(ospf_config.networks) == 2
    networks = [(n.network, n.wildcard, n.area) for n in ospf_config.networks]
    assert ("1.1.1.1", "0.0.0.0", 0) in networks
    assert ("192.168.1.0", "0.0.0.255", 0) in networks
    assert "default" in ospf_config.passive_interfaces
    assert "GigabitEthernet0/0" not in ospf_config.passive_interfaces
    assert ospf_config.area_auth["0"] == "message-digest"

def test_prefix_lists(router):
    """Test prefix lists."""
    prefix_lists = router.prefix_lists
    assert "ALLOWED_PREFIXES" in prefix_lists
    allowed_prefixes = prefix_lists["ALLOWED_PREFIXES"]
    assert len(allowed_prefixes.entries) == 4
    # Test first entry
    assert allowed_prefixes.entries[0].sequence == 5
    assert allowed_prefixes.entries[0].action == "permit"
    assert allowed_prefixes.entries[0].prefix == "10.0.0.0/8"
    assert allowed_prefixes.entries[0].le == 24
    # Test second entry
    assert allowed_prefixes.entries[1].sequence == 10
    assert allowed_prefixes.entries[1].action == "permit"
    assert allowed_prefixes.entries[1].prefix == "172.16.0.0/12"
    assert allowed_prefixes.entries[1].le == 24
    # Test third entry
    assert allowed_prefixes.entries[2].sequence == 15
    assert allowed_prefixes.entries[2].action == "permit"
    assert allowed_prefixes.entries[2].prefix == "192.168.0.0/16"
    assert allowed_prefixes.entries[2].le == 24
    # Test fourth entry
    assert allowed_prefixes.entries[3].sequence == 20
    assert allowed_prefixes.entries[3].action == "deny"
    assert allowed_prefixes.entries[3].prefix == "0.0.0.0/0"
    assert allowed_prefixes.entries[3].le == 32

def test_route_maps(router):
    """Test route maps."""
    route_maps = router.config.route_maps
    assert len(route_maps) == 4  # CUSTOMER_A_IMPORT, CUSTOMER_A_EXPORT, CUSTOMER_B_IMPORT, CUSTOMER_B_EXPORT
    expected_maps = {
        'CUSTOMER_A_IMPORT',
        'CUSTOMER_A_EXPORT',
        'CUSTOMER_B_IMPORT',
        'CUSTOMER_B_EXPORT'
    }
    assert set(route_maps.keys()) == expected_maps

def test_customer_a_import_route_map(router):
    """Test CUSTOMER_A_IMPORT route-map."""
    route_map = router.config.route_maps['CUSTOMER_A_IMPORT']
    assert len(route_map.entries) == 3

    # Test sequence 10 (permit entry)
    entry10 = route_map.entries[0]
    assert entry10.sequence == 10
    assert entry10.action == 'permit'
    assert entry10.description == 'Allow prefixes in ALLOWED_PREFIXES list'
    assert entry10.match_statements == {
        'ip address': ['prefix-list', 'ALLOWED_PREFIXES'],
        'community': ['CUSTOMER_A']
    }
    assert entry10.set_statements == {
        'local-preference': ['200'],
        'weight': ['100'],
        'origin': ['igp']
    }

    # Test sequence 20 (permit entry with AS path)
    entry20 = route_map.entries[1]
    assert entry20.sequence == 20
    assert entry20.action == 'permit'
    assert entry20.description == 'Allow other prefixes with lower preference'
    assert entry20.match_statements == {
        'as-path': ['100']
    }
    assert entry20.set_statements == {
        'local-preference': ['150'],
        'weight': ['50'],
        'community': ['65000:100', 'additive']
    }

    # Test sequence 100 (deny entry)
    entry100 = route_map.entries[2]
    assert entry100.sequence == 100
    assert entry100.action == 'deny'
    assert entry100.description == 'Deny everything else'
    assert not entry100.match_statements
    assert not entry100.set_statements

def test_customer_a_export_route_map(router):
    """Test CUSTOMER_A_EXPORT route-map."""
    route_map = router.config.route_maps['CUSTOMER_A_EXPORT']
    assert len(route_map.entries) == 1

    # Test sequence 10 (permit entry)
    entry10 = route_map.entries[0]
    assert entry10.sequence == 10
    assert entry10.action == 'permit'
    assert entry10.description == 'Set attributes for exported routes'
    assert entry10.match_statements == {
        'ip address': ['prefix-list', 'ALLOWED_PREFIXES']
    }
    assert entry10.set_statements == {
        'community': ['65000:100', 'no-export', 'additive'],
        'as-path': ['prepend', '65000', '65000'],
        'metric': ['100']
    }

def test_customer_b_import_route_map(router):
    """Test CUSTOMER_B_IMPORT route-map."""
    route_map = router.config.route_maps['CUSTOMER_B_IMPORT']
    assert len(route_map.entries) == 3

    # Test sequence 10 (permit entry)
    entry10 = route_map.entries[0]
    assert entry10.sequence == 10
    assert entry10.action == 'permit'
    assert entry10.description == 'Allow prefixes in ALLOWED_PREFIXES list'
    assert entry10.match_statements == {
        'ip address': ['prefix-list', 'ALLOWED_PREFIXES'],
        'community': ['CUSTOMER_B']
    }
    assert entry10.set_statements == {
        'local-preference': ['150'],
        'weight': ['100'],
        'origin': ['igp']
    }

    # Test sequence 20 (permit entry with AS path)
    entry20 = route_map.entries[1]
    assert entry20.sequence == 20
    assert entry20.action == 'permit'
    assert entry20.description == 'Allow other prefixes with lower preference'
    assert entry20.match_statements == {
        'as-path': ['200']
    }
    assert entry20.set_statements == {
        'local-preference': ['100'],
        'weight': ['50'],
        'community': ['65000:200', 'additive']
    }

    # Test sequence 100 (deny entry)
    entry100 = route_map.entries[2]
    assert entry100.sequence == 100
    assert entry100.action == 'deny'
    assert entry100.description == 'Deny everything else'
    assert not entry100.match_statements
    assert not entry100.set_statements

def test_customer_b_export_route_map(router):
    """Test CUSTOMER_B_EXPORT route-map."""
    route_map = router.config.route_maps['CUSTOMER_B_EXPORT']
    assert len(route_map.entries) == 1

    # Test sequence 10 (permit entry)
    entry10 = route_map.entries[0]
    assert entry10.sequence == 10
    assert entry10.action == 'permit'
    assert entry10.description == 'Set attributes for exported routes'
    assert entry10.match_statements == {
        'ip address': ['prefix-list', 'ALLOWED_PREFIXES']
    }
    assert entry10.set_statements == {
        'community': ['65000:200', 'no-export', 'additive'],
        'as-path': ['prepend', '65000'],
        'metric': ['200']
    }

def test_route_map_references(router):
    """Test route-map references in BGP configuration."""
    bgp_config = router.bgp_config
    
    # Test Customer A BGP neighbor route-map references
    customer_a_bgp = bgp_config.vrf_configs.get('CUSTOMER_A')
    assert customer_a_bgp is not None
    assert len(customer_a_bgp.neighbors) == 1
    neighbor = customer_a_bgp.neighbors[0]
    assert neighbor.route_maps['in'] == 'CUSTOMER_A_IMPORT'
    assert neighbor.route_maps['out'] == 'CUSTOMER_A_EXPORT'

    # Test Customer B BGP neighbor route-map references
    customer_b_bgp = bgp_config.vrf_configs.get('CUSTOMER_B')
    assert customer_b_bgp is not None
    assert len(customer_b_bgp.neighbors) == 1
    neighbor = customer_b_bgp.neighbors[0]
    assert neighbor.route_maps['in'] == 'CUSTOMER_B_IMPORT'
    assert neighbor.route_maps['out'] == 'CUSTOMER_B_EXPORT'

def test_acls(router):
    """Test access lists."""
    acls = router.config.acls
    assert len(acls) >= 2  # MGMT_ACCESS and CUSTOMER_A_FILTER

    # Test MGMT_ACCESS ACL
    mgmt_acl = acls['MGMT_ACCESS']
    assert mgmt_acl.type == 'extended'
    assert len(mgmt_acl.entries) >= 5

    # Test SSH entry
    ssh_entry = mgmt_acl.entries[0]
    assert ssh_entry.action == 'permit'
    assert ssh_entry.protocol == 'tcp'
    assert ssh_entry.source_ip == 'any'
    assert ssh_entry.source_wildcard is None
    assert ssh_entry.destination_ip == '192.168.1.1'
    assert ssh_entry.destination_wildcard is None
    assert ssh_entry.destination_port == '22'
    assert not ssh_entry.log

    # Test HTTPS entry
    https_entry = mgmt_acl.entries[1]
    assert https_entry.action == 'permit'
    assert https_entry.protocol == 'tcp'
    assert https_entry.source_ip == 'any'
    assert https_entry.destination_ip == '192.168.1.1'
    assert https_entry.destination_wildcard is None
    assert https_entry.destination_port == '443'
    assert not https_entry.log

    # Test ICMP entries
    icmp_entry = mgmt_acl.entries[2]
    assert icmp_entry.action == 'permit'
    assert icmp_entry.protocol == 'icmp'
    assert icmp_entry.source_ip == 'any'
    assert icmp_entry.destination_ip == 'any'
    assert icmp_entry.protocol_option == 'echo'
    assert not icmp_entry.log

    # Test deny entry with log
    deny_entry = mgmt_acl.entries[4]
    assert deny_entry.action == 'deny'
    assert deny_entry.protocol == 'ip'
    assert deny_entry.source_ip == 'any'
    assert deny_entry.destination_ip == 'any'
    assert deny_entry.log

    # Test CUSTOMER_A_FILTER ACL
    customer_acl = acls['CUSTOMER_A_FILTER']
    assert customer_acl.type == 'extended'
    assert len(customer_acl.entries) >= 3

    # Test network with wildcard mask
    network_entry = customer_acl.entries[0]
    assert network_entry.action == 'permit'
    assert network_entry.protocol == 'ip'
    assert network_entry.source_ip == '10.1.0.0'
    assert network_entry.source_wildcard == '0.0.255.255'
    assert network_entry.destination_ip == 'any'
    assert network_entry.destination_wildcard is None
    assert not network_entry.log

    # Test another network entry
    network_entry2 = customer_acl.entries[1]
    assert network_entry2.action == 'permit'
    assert network_entry2.protocol == 'ip'
    assert network_entry2.source_ip == '172.16.0.0'
    assert network_entry2.source_wildcard == '0.0.255.255'
    assert network_entry2.destination_ip == 'any'
    assert not network_entry2.log

    # Test deny any entry with log
    deny_entry = customer_acl.entries[2]
    assert deny_entry.action == 'deny'
    assert deny_entry.protocol == 'ip'
    assert deny_entry.source_ip == 'any'
    assert deny_entry.destination_ip == 'any'
    assert deny_entry.log

def test_mgmt_access_acl(router):
    """Test MGMT_ACCESS ACL specifically."""
    # Test dictionary-like access
    mgmt_acl = router.acls["MGMT_ACCESS"]
    assert mgmt_acl is not None
    
    # Test __getitem__ method directly
    assert mgmt_acl["type"] == 'extended'
    assert len(mgmt_acl.entries) == 5

    # Verify SSH entry
    assert mgmt_acl.entries[0].action == 'permit'
    assert mgmt_acl.entries[0].protocol == 'tcp'
    assert mgmt_acl.entries[0].destination_port == '22'

    # Verify HTTPS entry
    assert mgmt_acl.entries[1].action == 'permit'
    assert mgmt_acl.entries[1].protocol == 'tcp'
    assert mgmt_acl.entries[1].destination_port == '443'

    # Verify ICMP echo entry
    assert mgmt_acl.entries[2].action == 'permit'
    assert mgmt_acl.entries[2].protocol == 'icmp'
    assert mgmt_acl.entries[2].protocol_option == 'echo'

    # Verify ICMP echo-reply entry
    assert mgmt_acl.entries[3].action == 'permit'
    assert mgmt_acl.entries[3].protocol == 'icmp'
    assert mgmt_acl.entries[3].protocol_option == 'echo-reply'

    # Verify deny entry
    assert mgmt_acl.entries[4].action == 'deny'
    assert mgmt_acl.entries[4].protocol == 'ip'
    assert mgmt_acl.entries[4].log is True

def test_snmp_config(router):
    """Test SNMP configuration."""
    snmp_config = router.config.snmp
    assert snmp_config is not None
    assert snmp_config["community"]["public"] == "RO"
    assert snmp_config["community"]["private"] == "RW"
    assert snmp_config["location"] == "Data Center 1"
    assert snmp_config["contact"] == "NOC Team"
    assert "bgp" in snmp_config["traps"]
    assert "ospf" in snmp_config["traps"]
    assert snmp_config["host"] == {
        "192.168.1.100": {
            "version": "2c",
            "community": "public"
        }
    }

def test_ntp_config(router):
    """Test NTP configuration."""
    ntp_config = router.config.ntp_servers
    assert len(ntp_config) == 2
    # Test first NTP server
    assert ntp_config[0]["server"] == "192.168.1.200"
    assert ntp_config[0]["key"] == "1"
    assert ntp_config[0]["prefer"] is True
    # Test second NTP server
    assert ntp_config[1]["server"] == "192.168.1.201"
    assert ntp_config[1]["key"] == "1"
    assert ntp_config[1]["prefer"] is False

def test_logging_config(router):
    """Test logging configuration."""
    logging_config = router.config.logging
    assert logging_config["buffer_size"] == 16384
    assert logging_config["console"] == "critical"
    assert logging_config["monitor"] == "informational"
    assert logging_config["trap"] == "informational"
    assert logging_config["facility"] == "local6"
    assert "192.168.1.100" in logging_config["hosts"]
    assert "192.168.1.101" in logging_config["hosts"]

def test_aaa_config(router):
    """Test AAA configuration."""
    aaa_config = router.config.aaa
    assert aaa_config is not None
    assert aaa_config["authentication"]["login"]["default"] == ["group tacacs+", "local"]
    assert aaa_config["authorization"]["exec"]["default"] == ["group tacacs+", "local"]
    assert aaa_config["accounting"]["exec"]["default"] == {
        "record_type": "start-stop",
        "methods": ["group tacacs+"]
    }
    assert aaa_config["tacacs"]["hosts"] == {
        "192.168.1.150": {
            "key": "secretkey"
        }
    }
    assert aaa_config["tacacs"]["timeout"] == 5

def test_community_lists(router):
    """Test community lists."""
    community_lists = router.config.community_lists
    assert len(community_lists) == 3  # NO_EXPORT, CUSTOMER_A, CUSTOMER_B

    # Test NO_EXPORT community list
    no_export = community_lists['NO_EXPORT']
    assert no_export.name == 'NO_EXPORT'
    assert no_export.type == 'standard'
    assert len(no_export.entries) == 1
    entry = no_export.entries[0]
    assert entry.action == 'permit'
    assert entry.communities == ['65000:0']

    # Test CUSTOMER_A community list
    customer_a = community_lists['CUSTOMER_A']
    assert customer_a.name == 'CUSTOMER_A'
    assert customer_a.type == 'standard'
    assert len(customer_a.entries) == 1
    entry = customer_a.entries[0]
    assert entry.action == 'permit'
    assert entry.communities == ['65000:100']

    # Test CUSTOMER_B community list
    customer_b = community_lists['CUSTOMER_B']
    assert customer_b.name == 'CUSTOMER_B'
    assert customer_b.type == 'standard'
    assert len(customer_b.entries) == 1
    entry = customer_b.entries[0]
    assert entry.action == 'permit'
    assert entry.communities == ['65000:200']

def test_as_path_lists(router):
    """Test AS path access lists."""
    as_path_lists = router.config.as_path_lists
    assert len(as_path_lists) == 2  # Lists 100 and 200

    # Test AS path list 100
    list_100 = as_path_lists['100']
    assert list_100.name == '100'
    assert len(list_100.entries) == 2

    # Test permit entry
    permit_entry = list_100.entries[0]
    assert permit_entry.action == 'permit'
    assert permit_entry.regex == '^65100_'
    assert permit_entry.sequence is None

    # Test deny entry
    deny_entry = list_100.entries[1]
    assert deny_entry.action == 'deny'
    assert deny_entry.regex == '.*'
    assert deny_entry.sequence is None

    # Test AS path list 200
    list_200 = as_path_lists['200']
    assert list_200.name == '200'
    assert len(list_200.entries) == 2

    # Test permit entry
    permit_entry = list_200.entries[0]
    assert permit_entry.action == 'permit'
    assert permit_entry.regex == '^65200_'
    assert permit_entry.sequence is None

    # Test deny entry
    deny_entry = list_200.entries[1]
    assert deny_entry.action == 'deny'
    assert deny_entry.regex == '.*'
    assert deny_entry.sequence is None

def test_community_list_references(router):
    """Test community list references in route maps."""
    route_maps = router.config.route_maps

    # Test CUSTOMER_A_IMPORT references
    customer_a_import = route_maps['CUSTOMER_A_IMPORT']
    entry = customer_a_import.entries[0]
    assert 'community' in entry.match_statements
    assert entry.match_statements['community'] == ['CUSTOMER_A']

    # Test CUSTOMER_B_IMPORT references
    customer_b_import = route_maps['CUSTOMER_B_IMPORT']
    entry = customer_b_import.entries[0]
    assert 'community' in entry.match_statements
    assert entry.match_statements['community'] == ['CUSTOMER_B']

def test_as_path_list_references(router):
    """Test AS path list references in route maps."""
    route_maps = router.config.route_maps

    # Test CUSTOMER_A_IMPORT references
    customer_a_import = route_maps['CUSTOMER_A_IMPORT']
    entry = customer_a_import.entries[1]
    assert 'as-path' in entry.match_statements
    assert entry.match_statements['as-path'] == ['100']

    # Test CUSTOMER_B_IMPORT references
    customer_b_import = route_maps['CUSTOMER_B_IMPORT']
    entry = customer_b_import.entries[1]
    assert 'as-path' in entry.match_statements
    assert entry.match_statements['as-path'] == ['200']

def test_prefix_list_getitem(router):
    """Test PrefixList __getitem__ method."""
    prefix_list = router.prefix_lists["ALLOWED_PREFIXES"]
    assert prefix_list["name"] == "ALLOWED_PREFIXES"
    # Test accessing entries directly
    assert isinstance(prefix_list["entries"], list)

def test_fex_config_getitem(router):
    """Test FexConfig __getitem__ method."""
    fex = router.config.fex["101"]
    assert fex["description"] == "Customer A FEX"
    assert fex["type"] == "Nexus-2248TP"
    assert fex["serial"] is None
    assert fex["max_links"] == 1

def test_interface_getitem(router):
    """Test Interface __getitem__ method."""
    interface = router.get_interface("GigabitEthernet0/0")
    assert interface["name"] == "GigabitEthernet0/0"
    assert interface["description"] == "WAN Interface"
    assert interface["ip_address"] == "192.168.1.1"
    assert interface["subnet_mask"] == "255.255.255.0"
    assert interface["enabled"] is False
    assert interface["speed"] == "1000"
    assert interface["duplex"] == "full"
    assert interface["vrf"] is None
    assert interface["access_groups"]["in"] == "MGMT_ACCESS"

def test_vrf_config_getitem(router):
    """Test VrfConfig __getitem__ method."""
    vrf = router.get_vrf("CUSTOMER_A")
    assert vrf["name"] == "CUSTOMER_A"
    assert vrf["rd"] == "65000:1"
    assert vrf["route_targets"]["import"] == ["65000:1"]
    assert vrf["route_targets"]["export"] == ["65000:1"]
    assert "GigabitEthernet0/1" in vrf["interfaces"]

def test_bgp_config_getitem(router):
    """Test BgpConfig __getitem__ method."""
    bgp = router.config.bgp
    assert bgp is not None
    assert bgp["asn"] == 65000
    assert bgp["as_number"] == 65000  # Test the as_number alias
    assert bgp["router_id"] == "1.1.1.1"

def test_vlan_config_getitem(router):
    """Test VlanConfig __getitem__ method."""
    vlan = router.get_vlan(10)  # Using VLAN 10 from the test fixture
    assert vlan is not None
    assert vlan["vlan_id"] == 10
    assert vlan["name"] == "CUSTOMER_A_DATA"
    assert vlan["state"] == "active"

def test_ntp_server_getitem(router):
    """Test NtpServer __getitem__ method."""
    ntp_server = router.config.ntp_servers[0]
    assert ntp_server["server"] == "192.168.1.200"
    assert ntp_server["key"] == "1"
    assert ntp_server["prefer"] is True

def test_bgp_vrf_config_getitem(router):
    """Test BgpVrfConfig __getitem__ method."""
    bgp_config = router.bgp_config
    customer_a_bgp = bgp_config.vrf_configs.get('CUSTOMER_A')
    assert customer_a_bgp is not None
    assert customer_a_bgp["rd"] is None
    assert len(customer_a_bgp["neighbors"]) == 1
    assert customer_a_bgp["redistribute"] == ["connected", "static"]
    assert customer_a_bgp["maximum_paths"] == 2

if __name__ == "__main__":
    pytest.main([__file__])
