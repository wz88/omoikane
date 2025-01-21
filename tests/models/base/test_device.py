from functools import cached_property
import pytest
from models.base.core.device import Device
from models.base.routing_protocols.route import Route
from typing import Any, Dict, List, Optional


class MockDevice(Device):
    """Mock device for testing."""

    def __init__(self, config_text: str = None, hostname: str = None, num_interfaces: int = 4):
        """Initialize mock device."""
        super().__init__(config_text, hostname)
        self._num_interfaces = num_interfaces
        # Initialize with empty interfaces and VRFs
        self._interfaces = {}
        self._vrfs = {}
        self._routes = []  # Changed from dict to list
        # Only parse config if provided
        if config_text is not None:
            self.parse_config()

    def parse_config(self) -> None:
        """Parse configuration text."""
        # Only set hostname if it's not already set
        if not self._hostname:
            self._hostname = "MOCK-DEVICE"
        
        # Initialize interfaces based on num_interfaces
        self._interfaces = {}
        for i in range(self._num_interfaces):
            interface_name = f'GigabitEthernet0/{i}'
            self._interfaces[interface_name] = {
                'name': interface_name,
                'description': f'Test Interface {i+1}'
            }
        
        self._vrfs = {
            'default': {'name': 'default'},
            'CUSTOMER_A': {'name': 'CUSTOMER_A'},
            'CUSTOMER_B': {'name': 'CUSTOMER_B'}
        }

    def parse_routing_table(self, routing_table_text: str) -> None:
        """Parse routing table text."""
        # Create a test route
        route = Route(
            protocol="C",
            network="10.0.0.0/24",
            next_hop=None,
            interface=None,
            admin_distance=0,  # Default value
            metric=0,  # Default value
            is_best=True,  # Set is_best to True for this route
            source_protocol=None,
            source_rid=None,
            tag=None,
            age=None,
            attributes=[],
            vrf='default'
        )
        self._routes = [route]  # Replace existing routes with this one

    @cached_property
    def interfaces(self) -> Dict[str, Any]:
        """Return all interfaces configured on the device."""
        return self._interfaces

    @cached_property
    def vrfs(self) -> Dict[str, Any]:
        """Return all VRFs configured on the device."""
        return self._vrfs

    @cached_property
    def interface_list(self) -> List[str]:
        """Return a list of all interfaces configured on the device."""
        return list(self._interfaces.keys())

    @cached_property
    def vrf_list(self) -> List[str]:
        """Return a list of all VRFs configured on the device."""
        return list(self._vrfs.keys())

    def get_interface(self, name: str) -> Optional[Dict[str, Any]]:
        """Return interface by name."""
        return self._interfaces.get(name)

    def get_vrf(self, name: str) -> Optional[Dict[str, Any]]:
        """Return VRF by name."""
        return self._vrfs.get(name)

    def get_routes(self) -> List[Any]:
        """Return all routes."""
        return self._routes

    def get_routes_by_protocol(self, protocol: str) -> List[Any]:
        """Return routes by protocol."""
        return [r for r in self._routes if r.protocol == protocol]

    def get_routes_by_network(self, network: str) -> List[Any]:
        """Return routes by network."""
        return [r for r in self._routes if r.network == network]

    def get_best_routes(self) -> List[Any]:
        """Return best routes."""
        return [r for r in self._routes if r.is_best]

    def get_interfaces(self) -> Dict[str, Any]:
        """Return all interfaces."""
        return self._interfaces

    def get_vrfs(self) -> Dict[str, Any]:
        """Return all VRFs."""
        return self._vrfs

    def get_bgp_config(self) -> Dict[str, Any]:
        """Return BGP configuration."""
        return {}

    def get_ospf_config(self) -> Dict[str, Any]:
        """Return OSPF configuration."""
        return {}

    def get_acls(self) -> Dict[str, Any]:
        """Return ACLs."""
        return {}

    def get_route_maps(self) -> Dict[str, Any]:
        """Return route maps."""
        return {}

    def get_prefix_lists(self) -> Dict[str, Any]:
        """Return prefix lists."""
        return {}

    def __str__(self) -> str:
        """Return string representation."""
        return f"MockDevice(hostname={self._hostname}, interfaces={len(self._interfaces)})"

    def __repr__(self) -> str:
        """Return string representation."""
        return str(self)


class IncompleteDevice(Device):
    """Test class that doesn't implement all abstract methods."""
    pass


@pytest.fixture
def device():
    """Create a test device."""
    device = MockDevice(num_interfaces=4)
    device.parse_config()  # Initialize with default config
    return device


def test_device_initialization():
    """Test device initialization with default values."""
    device = MockDevice()
    assert device._hostname is None
    assert device.interfaces == {}
    assert device.vrfs == {}


def test_device_with_hostname():
    """Test device initialization with hostname."""
    device = MockDevice(hostname="MOCK-DEVICE")
    assert device._hostname == "MOCK-DEVICE"


def test_device_parse_config(device):
    """Test parsing device configuration."""
    device.parse_config()
    assert device._hostname == "MOCK-DEVICE"
    assert len(device.interfaces) == 4
    assert len(device.vrfs) == 3


def test_device_parse_routing_table(device):
    """Test parsing routing table."""
    device.parse_routing_table("")
    assert len(device.get_routes()) == 1


def test_device_interface_list(device):
    """Test getting list of interfaces."""
    device.parse_config()
    interfaces = device.interface_list
    assert len(interfaces) == 4
    assert 'GigabitEthernet0/0' in interfaces
    assert 'GigabitEthernet0/1' in interfaces
    assert 'GigabitEthernet0/2' in interfaces
    assert 'GigabitEthernet0/3' in interfaces


def test_device_vrf_list(device):
    """Test getting list of VRFs."""
    device.parse_config()
    vrfs = device.vrf_list
    assert len(vrfs) == 3
    assert 'default' in vrfs
    assert 'CUSTOMER_A' in vrfs
    assert 'CUSTOMER_B' in vrfs


def test_device_get_interface(device):
    """Test getting interface by name."""
    device.parse_config()
    interface = device.get_interface("GigabitEthernet0/0")
    assert interface is not None
    assert interface == {'name': 'GigabitEthernet0/0', 'description': 'Test Interface 1'}


def test_device_get_vrf(device):
    """Test getting VRF by name."""
    device.parse_config()
    vrf = device.get_vrf("default")
    assert vrf is not None
    assert vrf == {'name': 'default'}


def test_device_get_routes(device):
    """Test getting all routes."""
    device.parse_routing_table("")
    routes = device.get_routes()
    assert len(routes) == 1


def test_device_get_routes_by_protocol(device):
    """Test getting routes by protocol."""
    device.parse_routing_table("")
    routes = device.get_routes_by_protocol("C")
    assert len(routes) == 1
    
    # Test non-existent protocol
    assert len(device.get_routes_by_protocol("O")) == 0


def test_device_get_routes_by_network(device):
    """Test getting routes by network."""
    device.parse_routing_table("")
    routes = device.get_routes_by_network("10.0.0.0/24")
    assert len(routes) == 1
    
    # Test non-existent network
    assert len(device.get_routes_by_network("192.168.0.0/24")) == 0


def test_device_get_best_routes(device):
    """Test getting best routes."""
    device.parse_routing_table("")
    routes = device.get_best_routes()
    assert len(routes) == 1


def test_device_str(device):
    """Test string representation."""
    device.parse_config()
    assert str(device) == "MockDevice(hostname=MOCK-DEVICE, interfaces=4)"


def test_device_repr(device):
    """Test repr representation."""
    device.parse_config()
    assert repr(device) == "MockDevice(hostname=MOCK-DEVICE, interfaces=4)"


def test_device_abstract_class():
    """Test that Device cannot be instantiated directly."""
    with pytest.raises(TypeError, match=r"abstract"):
        Device()


def test_incomplete_device():
    """Test that a class must implement all abstract methods."""
    with pytest.raises(TypeError, match=r"abstract"):
        IncompleteDevice()


def test_abstract_methods():
    """Test that abstract methods raise NotImplementedError."""
    # Create a base class that implements all methods to return None
    class BaseTestDevice(Device):
        def parse_config(self) -> None:
            pass
        def parse_routing_table(self, routing_table_text: str) -> None:
            pass
        @cached_property
        def interfaces(self) -> Dict[str, Any]:
            return {}
        @cached_property
        def vrfs(self) -> Dict[str, Any]:
            return {}
        @cached_property
        def interface_list(self) -> List[Any]:
            return []
        @cached_property
        def vrf_list(self) -> List[Any]:
            return []
        def get_interface(self, name: str) -> Optional[Any]:
            pass
        def get_vrf(self, name: str) -> Optional[Any]:
            pass
        def get_routes(self) -> List[Any]:
            return []
        def get_routes_by_protocol(self, protocol: str) -> List[Any]:
            return []
        def get_routes_by_network(self, network: str) -> List[Any]:
            return []
        def get_best_routes(self) -> List[Any]:
            return []
        def get_interfaces(self) -> Dict[str, Any]:
            return {}
        def get_vrfs(self) -> Dict[str, Any]:
            return {}
        def get_bgp_config(self) -> Dict[str, Any]:
            return {}
        def get_ospf_config(self) -> Dict[str, Any]:
            return {}
        def get_acls(self) -> Dict[str, Any]:
            return {}
        def get_route_maps(self) -> Dict[str, Any]:
            return {}
        def get_prefix_lists(self) -> Dict[str, Any]:
            return {}

    # Test each method one at a time by removing it from the implementation
    methods_to_test = {
        "parse_config": lambda d: d.parse_config(),
        "parse_routing_table": lambda d: d.parse_routing_table(""),
        "get_interface": lambda d: d.get_interface("test"),
        "get_vrf": lambda d: d.get_vrf("test"),
        "get_routes": lambda d: d.get_routes(),
        "get_routes_by_protocol": lambda d: d.get_routes_by_protocol("test"),
        "get_routes_by_network": lambda d: d.get_routes_by_network("test"),
        "get_best_routes": lambda d: d.get_best_routes(),
        "get_interfaces": lambda d: d.get_interfaces(),
        "get_vrfs": lambda d: d.get_vrfs(),
        "get_bgp_config": lambda d: d.get_bgp_config(),
        "get_ospf_config": lambda d: d.get_ospf_config(),
        "get_acls": lambda d: d.get_acls(),
        "get_route_maps": lambda d: d.get_route_maps(),
        "get_prefix_lists": lambda d: d.get_prefix_lists()
    }

    for method_name, test_func in methods_to_test.items():
        # Create a class that implements all methods except the one we're testing
        attrs = {k: v for k, v in BaseTestDevice.__dict__.items()
                if not k.startswith('_')}
        del attrs[method_name]
        TestDevice = type("TestDevice", (Device,), attrs)

        # Try to instantiate it - should raise TypeError
        try:
            device = TestDevice(config_text="")
            test_func(device)  # This should never execute
            pytest.fail(f"Expected TypeError for missing method {method_name}")
        except TypeError as e:
            assert "Can't instantiate abstract class" in str(e)


class TestDevice(Device):
    """Test device class for testing."""

    def __init__(self, config_text: Optional[str] = None):
        """Initialize test device."""
        super().__init__(config=config_text)
        self._hostname = "MOCK-DEVICE"
        self._interfaces = {
            'GigabitEthernet0/0': {'name': 'GigabitEthernet0/0', 'description': 'Test Interface'},
        }
        self._vrfs = {
            'default': {'name': 'default'},
        }
        self._routes = []

    def parse_config(self) -> None:
        """Parse device configuration."""
        pass

    def parse_routing_table(self) -> None:
        """Parse device routing table."""
        self._routes = [Route(protocol="C", network="10.0.0.0/24")]

    @cached_property
    def interfaces(self) -> Dict[str, Any]:
        """Get device interfaces."""
        return self._interfaces

    @cached_property
    def vrfs(self) -> Dict[str, Any]:
        """Get device VRFs."""
        return self._vrfs

    @cached_property
    def interface_list(self) -> List[str]:
        """Get device interface list."""
        return list(self._interfaces.keys())

    @cached_property
    def vrf_list(self) -> List[str]:
        """Get device VRF list."""
        return list(self._vrfs.keys())

    def get_interface(self, name: str) -> Optional[Any]:
        """Get device interface by name."""
        return self._interfaces.get(name)

    def get_vrf(self, name: str) -> Optional[Any]:
        """Get device VRF by name."""
        return self._vrfs.get(name)

    def get_routes(self) -> List[Any]:
        """Get device routes."""
        return self._routes

    def get_routes_by_protocol(self, protocol: str) -> List[Any]:
        """Get device routes by protocol."""
        return [r for r in self._routes if r.protocol == protocol]

    def get_routes_by_network(self, network: str) -> List[Any]:
        """Get device routes by network."""
        return [r for r in self._routes if r.network == network]

    def get_best_routes(self) -> List[Any]:
        """Get device best routes."""
        return self._routes

    def get_bgp_config(self) -> Dict[str, Any]:
        """Get device BGP configuration."""
        return {}

    def get_ospf_config(self) -> Dict[str, Any]:
        """Get device OSPF configuration."""
        return {}

    def get_acls(self) -> Dict[str, Any]:
        """Get device ACLs."""
        return {}

    def get_route_maps(self) -> Dict[str, Any]:
        """Get device route maps."""
        return {}

    def get_prefix_lists(self) -> Dict[str, Any]:
        """Get device prefix lists."""
        return {}

    def get_interfaces(self) -> Dict[str, Any]:
        """Get device interfaces."""
        return self._interfaces

    def get_vrfs(self) -> Dict[str, Any]:
        """Get device VRFs."""
        return self._vrfs

    def __str__(self) -> str:
        """Return string representation of device."""
        return f"MockDevice(hostname={self._hostname}, interfaces={len(self._interfaces)})"

    def __repr__(self) -> str:
        """Return string representation of device."""
        return self.__str__()


def test_device_creation(device):
    """Test device creation."""
    assert isinstance(device, Device)


def test_device_parse_config():
    """Test device config parsing."""
    config = """
    hostname test-device
    !
    interface GigabitEthernet0/1
     ip address 10.1.1.1 255.255.255.0
     no shutdown
    !
    """
    device = TestDevice(config_text=config)
    device.parse_config()
    assert len(device.get_interfaces()) == 1


def test_device_get_interfaces(device):
    """Test getting device interfaces."""
    interfaces = device.get_interfaces()
    assert isinstance(interfaces, dict)
    assert len(interfaces) == 4  # Updated to expect 4 interfaces


def test_device_get_routes(device):
    """Test getting device routes."""
    routes = device.get_routes()
    assert isinstance(routes, list)
    assert len(routes) == 0  # Base device has no routes


def test_device_get_vrfs(device):
    """Test getting device VRFs."""
    vrfs = device.get_vrfs()
    assert isinstance(vrfs, dict)
    assert len(vrfs) == 3  # Updated to expect 3 VRFs


def test_device_get_bgp_config(device):
    """Test getting device BGP config."""
    bgp_config = device.get_bgp_config()
    assert bgp_config is not None  # Should return empty BGP config


def test_device_get_ospf_config(device):
    """Test getting device OSPF config."""
    ospf_config = device.get_ospf_config()
    assert ospf_config is not None  # Should return empty OSPF config


def test_device_get_acls(device):
    """Test getting device ACLs."""
    acls = device.get_acls()
    assert isinstance(acls, dict)
    assert len(acls) == 0  # Base device has no ACLs


def test_device_get_route_maps(device):
    """Test getting device route maps."""
    route_maps = device.get_route_maps()
    assert isinstance(route_maps, dict)
    assert len(route_maps) == 0  # Base device has no route maps


def test_device_get_prefix_lists(device):
    """Test getting device prefix lists."""
    prefix_lists = device.get_prefix_lists()
    assert isinstance(prefix_lists, dict)
    assert len(prefix_lists) == 0  # Base device has no prefix lists


def test_device_parse_routing_table(device):
    """Test parsing routing table."""
    device.parse_routing_table("")
    assert len(device.get_routes()) == 1
    route = device.get_routes()[0]
    assert route.protocol == "C"
    assert route.network == "10.0.0.0/24"


def test_device_get_routes_by_protocol(device):
    """Test getting routes by protocol."""
    device.parse_routing_table("")
    routes = device.get_routes_by_protocol("C")
    assert len(routes) == 1
    route = routes[0]
    assert route.protocol == "C"
    assert route.network == "10.0.0.0/24"


def test_device_get_routes_by_network(device):
    """Test getting routes by network."""
    device.parse_routing_table("")
    routes = device.get_routes_by_network("10.0.0.0/24")
    assert len(routes) == 1
    route = routes[0]
    assert route.protocol == "C"
    assert route.network == "10.0.0.0/24"


def test_device_get_best_routes(device):
    """Test getting best routes."""
    device.parse_routing_table("")
    routes = device.get_best_routes()
    assert len(routes) == 1
    route = routes[0]
    assert route.protocol == "C"
    assert route.network == "10.0.0.0/24"
