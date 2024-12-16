import pytest
from src.models.cisco_parser.router import CiscoRouter
from src.models.base.route import Route


@pytest.fixture
def router():
    """Create a router instance."""
    return CiscoRouter()


def test_parse_connected_route(router):
    """Test parsing a connected route."""
    route_output = """
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area 
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2

C    10.1.1.0/24 [0/0] via GigabitEthernet0/1
"""
    router.parse_routing_table(route_output)
    routes = router.get_routes()
    assert len(routes) == 1
    assert routes[0].protocol == 'C'
    assert routes[0].network == '10.1.1.0/24'
    assert routes[0].interface == 'GigabitEthernet0/1'
    assert routes[0].admin_distance == 0
    assert routes[0].metric == 0
    assert routes[0].is_best is True


def test_parse_bgp_route(router):
    """Test parsing a BGP route with multiple paths."""
    route_output = """
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area 
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2

B    172.16.0.0/24 [200/0] via 192.168.1.1, 00:01:00, GigabitEthernet0/1
     [200/0] via 192.168.1.2, 00:02:00, GigabitEthernet0/1
"""
    router.parse_routing_table(route_output)
    routes = router.get_routes()
    assert len(routes) == 2
    
    # Check best route
    best_route = next(r for r in routes if r.is_best)
    assert best_route.protocol == 'B'
    assert best_route.network == '172.16.0.0/24'
    assert best_route.next_hop == '192.168.1.1'
    assert best_route.interface == 'GigabitEthernet0/1'
    assert best_route.admin_distance == 200
    assert best_route.metric == 0
    assert best_route.age == '00:01:00'
    
    # Check non-best route
    alt_route = next(r for r in routes if not r.is_best)
    assert alt_route.protocol == 'B'
    assert alt_route.network == '172.16.0.0/24'
    assert alt_route.next_hop == '192.168.1.2'
    assert alt_route.interface == 'GigabitEthernet0/1'
    assert alt_route.admin_distance == 200
    assert alt_route.metric == 0
    assert alt_route.age == '00:02:00'


def test_parse_ospf_route(router):
    """Test parsing an OSPF route."""
    route_output = """
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area 
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2

O    192.168.0.0/24 [110/20] via 10.0.0.1, 00:05:00, GigabitEthernet0/1
"""
    router.parse_routing_table(route_output)
    routes = router.get_routes()
    assert len(routes) == 1
    route = routes[0]
    assert route.protocol == 'O'
    assert route.network == '192.168.0.0/24'
    assert route.next_hop == '10.0.0.1'
    assert route.interface == 'GigabitEthernet0/1'
    assert route.admin_distance == 110
    assert route.metric == 20
    assert route.age == '00:05:00'
    assert route.is_best is True


def test_parse_empty_routing_table(router):
    """Test parsing an empty routing table."""
    router.parse_routing_table("")
    assert len(router.get_routes()) == 0


def test_get_routes_by_protocol(router):
    """Test getting routes filtered by protocol."""
    route_output = """
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area 
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2

C    10.1.1.0/24 [0/0] via GigabitEthernet0/1
B    172.16.0.0/24 [200/0] via 192.168.1.1, 00:01:00, GigabitEthernet0/1
"""
    router.parse_routing_table(route_output)
    
    # Test getting connected routes
    connected_routes = router.get_routes_by_protocol('C')
    assert len(connected_routes) == 1
    assert connected_routes[0].network == '10.1.1.0/24'
    
    # Test getting BGP routes
    bgp_routes = router.get_routes_by_protocol('B')
    assert len(bgp_routes) == 1
    assert bgp_routes[0].network == '172.16.0.0/24'
    
    # Test getting non-existent protocol
    assert len(router.get_routes_by_protocol('X')) == 0


def test_get_routes_by_network(router):
    """Test getting routes by network."""
    route_output = """
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area 
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2

C    10.1.1.0/24 [0/0] via GigabitEthernet0/1
B    172.16.0.0/24 [200/0] via 192.168.1.1, 00:01:00, GigabitEthernet0/1
"""
    router.parse_routing_table(route_output)
    
    # Test getting existing network
    routes = router.get_routes_by_network('10.1.1.0/24')
    assert len(routes) == 1
    assert routes[0].protocol == 'C'
    
    # Test getting non-existent network
    assert len(router.get_routes_by_network('192.168.0.0/24')) == 0


def test_get_best_routes(router):
    """Test getting only the best routes."""
    route_output = """
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area 
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2

B    172.16.0.0/24 [200/0] via 192.168.1.1, 00:01:00, GigabitEthernet0/1
     [200/0] via 192.168.1.2, 00:02:00, GigabitEthernet0/1
C    10.1.1.0/24 [0/0] via GigabitEthernet0/1
"""
    router.parse_routing_table(route_output)
    
    best_routes = router.get_best_routes()
    assert len(best_routes) == 2
    assert all(route.is_best for route in best_routes)
    networks = {route.network for route in best_routes}
    assert networks == {'172.16.0.0/24', '10.1.1.0/24'}


def test_parse_route_with_attributes(router):
    """Test parsing a route with attributes like AS path and tags."""
    route_output = """
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area 

B    172.16.0.0/24 [20/0]
     via 192.168.1.1, 00:01:00
       from 192.168.1.1 (10.0.0.1)
       Route metric is 0
       Route tag 100
       AS path: 65001 65002 65003
       MPLS label: none
"""
    router.parse_routing_table(route_output)
    routes = router.get_routes()
    assert len(routes) == 1
    route = routes[0]
    assert route.protocol == 'B'
    assert route.network == '172.16.0.0/24'
    assert route.next_hop == '192.168.1.1'
    assert route.admin_distance == 20
    assert route.metric == 0
    assert route.age == '00:01:00'
    assert route.source_rid == '10.0.0.1'
    assert route.tag == 100
    assert 'AS path: 65001 65002 65003' in route.attributes
    assert 'MPLS label: none' in route.attributes


def test_parse_route_with_source_protocol(router):
    """Test parsing a route with source protocol information."""
    route_output = """
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area 

O E2 172.16.0.0/24 [110/20]
     via 192.168.1.1, 00:01:00
       from 10.0.0.1 (10.0.0.1)
       Route metric is 20
       Route type external type 2
       Last updated 00:01:00 ago
"""
    router.parse_routing_table(route_output)
    routes = router.get_routes()
    assert len(routes) == 1
    route = routes[0]
    assert route.protocol == 'O'
    assert route.network == '172.16.0.0/24'
    assert route.next_hop == '192.168.1.1'
    assert route.admin_distance == 110
    assert route.metric == 20
    assert route.age == '00:01:00'
    assert route.source_rid == '10.0.0.1'
    assert 'Route type external type 2' in route.attributes


def test_parse_route_with_vrf(router):
    """Test parsing routes from multiple VRF tables."""
    route_output = """
Routing Table: VRF customer1
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP

C    10.1.1.0/24 [0/0] via GigabitEthernet0/1

Routing Table: VRF customer2
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP

C    10.2.2.0/24 [0/0] via GigabitEthernet0/2
"""
    router.parse_routing_table(route_output)
    routes = router.get_routes()
    assert len(routes) == 2
    networks = {route.network for route in routes}
    assert networks == {'10.1.1.0/24', '10.2.2.0/24'}


def test_parse_route_with_various_age_formats(router):
    """Test parsing routes with different age formats."""
    route_output = """
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP

C    10.1.1.0/24 [0/0] via GigabitEthernet0/1, 00:01:00
B    10.2.2.0/24 [200/0] via 192.168.1.1, 1d2h
O    10.3.3.0/24 [110/2] via 192.168.1.2, 1w3d
S    10.4.4.0/24 [1/0] via 192.168.1.3, 2y5m
"""
    router.parse_routing_table(route_output)
    routes = router.get_routes()
    assert len(routes) == 4
    age_formats = {route.age for route in routes}
    assert age_formats == {'00:01:00', '1d2h', '1w3d', '2y5m'}


def test_parse_route_with_descriptor_blocks(router):
    """Test parsing routes with detailed descriptor blocks."""
    route_output = """
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP

O    10.1.1.0/24 [110/2]
     Routing Descriptor Blocks:
     * via 192.168.1.1, GigabitEthernet0/1
       Route metric is 2, traffic share count is 1
       Total delay is 20 microseconds
       Minimum bandwidth is 100000 Kbit
       Reliability 255/255, minimum MTU 1500 bytes
       Loading 1/255
"""
    router.parse_routing_table(route_output)
    routes = router.get_routes()
    assert len(routes) == 1
    route = routes[0]
    assert route.protocol == 'O'
    assert route.network == '10.1.1.0/24'
    assert route.next_hop == '192.168.1.1'
    assert route.interface == 'GigabitEthernet0/1'
    assert route.admin_distance == 110
    assert route.metric == 2
    assert route.is_best is True
    assert any('Route metric is 2' in attr for attr in route.attributes)
    assert any('Total delay is 20 microseconds' in attr for attr in route.attributes)
