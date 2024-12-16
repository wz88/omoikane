import pytest
from typing import Any, Dict, List, Optional
from src.models.base.device import Device


class MockDevice(Device):
    """Mock device implementation for testing."""
    def __init__(self):
        super().__init__()
        self._interfaces: Dict[str, Any] = {}
        self._vrfs: Dict[str, Any] = {}
        self._routes: List[Any] = []

    def parse_config(self, config_text: str) -> None:
        self.hostname = "MOCK-DEVICE"
        self._interfaces = {"GigabitEthernet0/0": {"name": "GigabitEthernet0/0"}}
        self._vrfs = {"default": {"name": "default"}}
    
    def parse_routing_table(self, routing_table_text: str) -> None:
        self._routes = [{"protocol": "C", "network": "10.0.0.0/24"}]
    
    @property
    def interfaces(self) -> Dict[str, Any]:
        return self._interfaces

    @property
    def vrfs(self) -> Dict[str, Any]:
        return self._vrfs

    @property
    def interface_list(self) -> List[Any]:
        return list(self._interfaces.values())
    
    @property
    def vrf_list(self) -> List[Any]:
        return list(self._vrfs.values())
    
    def get_interface(self, name: str) -> Optional[Any]:
        return self._interfaces.get(name)
    
    def get_vrf(self, name: str) -> Optional[Any]:
        return self._vrfs.get(name)
    
    def get_routes(self) -> List[Any]:
        return self._routes
    
    def get_routes_by_protocol(self, protocol: str) -> List[Any]:
        return [r for r in self._routes if r["protocol"] == protocol]
    
    def get_routes_by_network(self, network: str) -> List[Any]:
        return [r for r in self._routes if r["network"] == network]
    
    def get_best_routes(self) -> List[Any]:
        return self._routes


class IncompleteDevice(Device):
    """A device class that doesn't implement all abstract methods."""
    def parse_config(self, config_text: str) -> None:
        pass


@pytest.fixture
def device():
    """Create a mock device instance."""
    return MockDevice()


def test_device_initialization(device):
    """Test device initialization with default values."""
    assert device.hostname is None
    assert device.interfaces == {}
    assert device.vrfs == {}
    assert device.get_routes() == []


def test_device_parse_config(device):
    """Test parsing device configuration."""
    device.parse_config("")
    assert device.hostname == "MOCK-DEVICE"
    assert "GigabitEthernet0/0" in device.interfaces
    assert "default" in device.vrfs


def test_device_parse_routing_table(device):
    """Test parsing routing table."""
    device.parse_routing_table("")
    assert len(device.get_routes()) == 1
    assert device.get_routes()[0]["protocol"] == "C"
    assert device.get_routes()[0]["network"] == "10.0.0.0/24"


def test_device_interface_list(device):
    """Test getting list of interfaces."""
    device.parse_config("")
    interfaces = device.interface_list
    assert len(interfaces) == 1
    assert interfaces[0]["name"] == "GigabitEthernet0/0"


def test_device_vrf_list(device):
    """Test getting list of VRFs."""
    device.parse_config("")
    vrfs = device.vrf_list
    assert len(vrfs) == 1
    assert vrfs[0]["name"] == "default"


def test_device_get_interface(device):
    """Test getting interface by name."""
    device.parse_config("")
    interface = device.get_interface("GigabitEthernet0/0")
    assert interface is not None
    assert interface["name"] == "GigabitEthernet0/0"
    
    # Test non-existent interface
    assert device.get_interface("NonExistent") is None


def test_device_get_vrf(device):
    """Test getting VRF by name."""
    device.parse_config("")
    vrf = device.get_vrf("default")
    assert vrf is not None
    assert vrf["name"] == "default"
    
    # Test non-existent VRF
    assert device.get_vrf("NonExistent") is None


def test_device_get_routes(device):
    """Test getting all routes."""
    device.parse_routing_table("")
    routes = device.get_routes()
    assert len(routes) == 1
    assert routes[0]["protocol"] == "C"
    assert routes[0]["network"] == "10.0.0.0/24"


def test_device_get_routes_by_protocol(device):
    """Test getting routes by protocol."""
    device.parse_routing_table("")
    routes = device.get_routes_by_protocol("C")
    assert len(routes) == 1
    assert routes[0]["protocol"] == "C"
    
    # Test non-existent protocol
    assert len(device.get_routes_by_protocol("O")) == 0


def test_device_get_routes_by_network(device):
    """Test getting routes by network."""
    device.parse_routing_table("")
    routes = device.get_routes_by_network("10.0.0.0/24")
    assert len(routes) == 1
    assert routes[0]["network"] == "10.0.0.0/24"
    
    # Test non-existent network
    assert len(device.get_routes_by_network("192.168.0.0/24")) == 0


def test_device_get_best_routes(device):
    """Test getting best routes."""
    device.parse_routing_table("")
    routes = device.get_best_routes()
    assert len(routes) == 1
    assert routes[0]["protocol"] == "C"
    assert routes[0]["network"] == "10.0.0.0/24"


def test_device_str(device):
    """Test string representation."""
    device.parse_config("")
    assert str(device) == "MockDevice(hostname=MOCK-DEVICE, interfaces=1)"


def test_device_repr(device):
    """Test repr representation."""
    device.parse_config("")
    assert repr(device) == "MockDevice(hostname=MOCK-DEVICE, interfaces=1)"


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
        def parse_config(self, config_text: str) -> None:
            pass
        def parse_routing_table(self, routing_table_text: str) -> None:
            pass
        @property
        def interfaces(self) -> Dict[str, Any]:
            return {}
        @property
        def vrfs(self) -> Dict[str, Any]:
            return {}
        @property
        def interface_list(self) -> List[Any]:
            return []
        @property
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

    # Test each method one at a time by removing it from the implementation
    methods_to_test = {
        "parse_config": lambda d: d.parse_config(""),
        "parse_routing_table": lambda d: d.parse_routing_table(""),
        "interfaces": lambda d: d.interfaces,
        "vrfs": lambda d: d.vrfs,
        "interface_list": lambda d: d.interface_list,
        "vrf_list": lambda d: d.vrf_list,
        "get_interface": lambda d: d.get_interface("test"),
        "get_vrf": lambda d: d.get_vrf("test"),
        "get_routes": lambda d: d.get_routes(),
        "get_routes_by_protocol": lambda d: d.get_routes_by_protocol("test"),
        "get_routes_by_network": lambda d: d.get_routes_by_network("test"),
        "get_best_routes": lambda d: d.get_best_routes()
    }

    for method_name, test_func in methods_to_test.items():
        # Create a class that implements all methods except the one we're testing
        attrs = {k: v for k, v in BaseTestDevice.__dict__.items() 
                if not k.startswith('_')}
        del attrs[method_name]
        TestDevice = type("TestDevice", (Device,), attrs)
        
        # Verify that we can't instantiate it
        with pytest.raises(TypeError, match=r"abstract"):
            TestDevice()
