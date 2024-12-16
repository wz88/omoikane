import pytest
from src.models.cisco_parser.router import CiscoRouter

@pytest.fixture
def router():
    # Read the example configuration
    with open('tests/models/cisco_parser/examples/ROUTER-DC01.txt', 'r') as f:
        config_text = f.read()

    # Create router instance
    return CiscoRouter(config_text)

@pytest.fixture
def routing_table():
    return """
Routing Table: VRF default
Codes: C - connected, S - static, K - kernel, 
       O - OSPF, IA - OSPF inter area, E1 - OSPF external type 1,
       E2 - OSPF external type 2, N1 - OSPF NSSA external type 1,
       N2 - OSPF NSSA external type2, B - BGP, B I - iBGP, B E - eBGP
       * - candidate default

Gateway of last resort is not set

C    10.1.1.0/24 is directly connected, GigabitEthernet0/1
     Known via "connected", distance 0, metric 0, best
     * directly connected, via GigabitEthernet0/1
     Age: 2d3h

O    10.2.2.0/24 [110/2]
     Routing Descriptor Blocks:
     * via 10.1.1.2, GigabitEthernet0/1, 00:00:03
       from 192.168.1.1 (192.168.1.1)
       Route metric is 2, traffic share count is 1
       Route tag 100
       Age: 00:00:03
       MPLS label: none

B    10.3.3.0/24 [20/0]
     Routing Descriptor Blocks:
     * via 192.168.1.2
       from 192.168.1.2 (192.168.1.2)
       Route metric is 0
       Route tag 200
       Age: 1d2h
       AS path: 65001 65002 65003
       MPLS label: none
     via 192.168.1.3
       from 192.168.1.3 (192.168.1.3)
       Route metric is 0
       Route tag 200
       Age: 1d2h
       AS path: 65001 65002 65003
       MPLS label: none

S    10.4.4.0/24 [1/0]
     Known via "static", distance 1, metric 0, best
     * via 10.1.1.254
     Age: 5d4h
"""

def test_parse_routing_table(router, routing_table):
    """Test parsing of routing table."""
    router.parse_routing_table(routing_table)
    routes = router.get_routes()
    
    assert len(routes) == 5  # 1 connected, 1 OSPF, 2 BGP (same network), 1 static
    
    # Test connected route
    connected = router.get_routes_by_protocol('C')[0]
    assert connected.network == '10.1.1.0/24'
    assert connected.protocol == 'C'
    assert connected.interface == 'GigabitEthernet0/1'
    assert connected.is_best
    assert connected.admin_distance == 0
    assert connected.metric == 0
    assert connected.age == '2d3h'
    
    # Test OSPF route
    ospf = router.get_routes_by_protocol('O')[0]
    assert ospf.network == '10.2.2.0/24'
    assert ospf.protocol == 'O'
    assert ospf.next_hop == '10.1.1.2'
    assert ospf.interface == 'GigabitEthernet0/1'
    assert ospf.admin_distance == 110
    assert ospf.metric == 2
    assert ospf.is_best
    assert ospf.source_rid == '192.168.1.1'
    assert ospf.tag == 100
    assert ospf.age == '00:00:03'
    
    # Test BGP routes
    bgp_routes = router.get_routes_by_protocol('B')
    assert len(bgp_routes) == 2
    best_bgp = next(r for r in bgp_routes if r.is_best)
    non_best_bgp = next(r for r in bgp_routes if not r.is_best)
    
    assert best_bgp.network == '10.3.3.0/24'
    assert best_bgp.next_hop == '192.168.1.2'
    assert best_bgp.admin_distance == 20
    assert best_bgp.metric == 0
    assert best_bgp.source_rid == '192.168.1.2'
    assert best_bgp.tag == 200
    assert best_bgp.age == '1d2h'
    assert 'AS path: 65001 65002 65003' in best_bgp.attributes
    
    assert non_best_bgp.network == '10.3.3.0/24'
    assert non_best_bgp.next_hop == '192.168.1.3'
    assert not non_best_bgp.is_best
    assert non_best_bgp.age == '1d2h'
    
    # Test static route
    static = router.get_routes_by_protocol('S')[0]
    assert static.network == '10.4.4.0/24'
    assert static.protocol == 'S'
    assert static.next_hop == '10.1.1.254'
    assert static.admin_distance == 1
    assert static.metric == 0
    assert static.is_best
    assert static.age == '5d4h'

def test_get_routes_by_network(router, routing_table):
    """Test filtering routes by network."""
    router.parse_routing_table(routing_table)
    
    # Test network with multiple routes
    bgp_routes = router.get_routes_by_network('10.3.3.0/24')
    assert len(bgp_routes) == 2
    assert sum(1 for r in bgp_routes if r.is_best) == 1
    
    # Test network with single route
    ospf_routes = router.get_routes_by_network('10.2.2.0/24')
    assert len(ospf_routes) == 1
    assert ospf_routes[0].is_best

def test_get_routes_by_protocol(router, routing_table):
    """Test filtering routes by protocol."""
    router.parse_routing_table(routing_table)
    
    ospf_routes = router.get_routes_by_protocol('O')
    assert len(ospf_routes) == 1
    assert ospf_routes[0].network == '10.2.2.0/24'
    assert ospf_routes[0].next_hop == '10.1.1.2'
    
    bgp_routes = router.get_routes_by_protocol('B')
    assert len(bgp_routes) == 2
    assert all(r.network == '10.3.3.0/24' for r in bgp_routes)
    assert len([r for r in bgp_routes if r.is_best]) == 1

def test_get_best_routes(router, routing_table):
    """Test getting only the best routes."""
    router.parse_routing_table(routing_table)
    
    best_routes = router.get_best_routes()
    assert len(best_routes) == 4  # One best route for each unique network
    
    networks = {r.network for r in best_routes}
    assert networks == {'10.1.1.0/24', '10.2.2.0/24', '10.3.3.0/24', '10.4.4.0/24'}
