# Cisco Router Configuration Parser

A Python module for parsing and managing Cisco router configurations using `ciscoconfparse2` and `pydantic`.

## Installation

```bash
pip install ciscoconfparse2 pydantic
```

## Overview

The `CiscoIOS` class provides a comprehensive interface for parsing and managing Cisco router configurations. It handles various configuration aspects including:

- Basic router configuration (hostname)
- Interfaces and VRFs
- VLANs and FEX units
- Routing protocols (BGP, OSPF)
- Access Control Lists (ACLs)
- Prefix Lists and Route Maps
- SNMP, NTP, and AAA configurations

## Usage

```python
from models import CiscoIOS

# Read configuration from file
with open('router_config.txt', 'r') as f:
    config_text = f.read()

# Create router instance
router = CiscoIOS(config_text)

# Access router configuration
hostname = router.config.hostname
interfaces = router.interfaces
bgp_config = router.bgp_config
```

## Models

### Interface Configuration

```python
class Interface(BaseModel):
    name: str
    description: Optional[str] = None
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    enabled: bool = True
    speed: Optional[str] = None
    duplex: Optional[str] = None
    vrf: Optional[str] = None
    access_groups: Dict[str, str] = {}
    switchport_mode: Optional[str] = None
    allowed_vlans: Optional[str] = None
    fex_associate: Optional[int] = None
```

### BGP Configuration

```python
class BgpConfig(BaseModel):
    asn: int
    router_id: Optional[str] = None
    vrf_configs: Dict[str, BgpVrfConfig] = {}

class BgpVrfConfig(BaseModel):
    rd: Optional[str] = None
    neighbors: List[BgpNeighbor] = []
    redistribute: List[str] = []
    maximum_paths: Optional[int] = None

class BgpNeighbor(BaseModel):
    address: str
    remote_as: int
    route_maps: Dict[str, str] = {}
```

### Access Control Lists

```python
class AclEntry(BaseModel):
    sequence: int = 0
    action: Literal["permit", "deny"]
    protocol: Literal["ip", "tcp", "udp", "icmp"]
    source_ip: str
    source_wildcard: Optional[str] = None
    destination_ip: str
    destination_wildcard: Optional[str] = None
    destination_port: Optional[str] = None
    protocol_option: Optional[str] = None
    log: bool = False
    options: Optional[str] = None

class Ipv4Acl(BaseModel):
    type: str
    entries: List[AclEntry] = []
```

### Community Lists

```python
class CommunityListEntry(BaseModel):
    action: str  # permit or deny
    communities: List[str]  # List of community values

class CommunityList(BaseModel):
    name: str  # Name of the community list
    type: str  # standard or expanded
    entries: List[CommunityListEntry]
```

### AS-Path Lists

```python
class AsPathListEntry(BaseModel):
    sequence: Optional[int]  # Optional sequence number
    action: str  # permit or deny
    regex: str  # Regular expression pattern

class AsPathList(BaseModel):
    name: str  # Name/number of the AS-path list
    entries: List[AsPathListEntry]
```

### OSPF Configuration

```python
class OspfConfig(BaseModel):
    process_id: int
    router_id: Optional[str] = None
    reference_bandwidth: Optional[int] = None
    networks: List[OspfNetwork] = []
    passive_interfaces: Set[str] = set()
    area_auth: Dict[str, str] = {}

class OspfNetwork(BaseModel):
    network: str
    wildcard: str
    area: int | str
```

## Key Methods

### Configuration Access

- `interfaces()`: List all configured interfaces
- `vrfs()`: List all VRF configurations
- `vlans()`: List all VLAN configurations
- `prefix_lists()`: Get all prefix lists
- `route_maps()`: Get all route maps
- `acls()`: Get all ACLs
- `fex_units()`: List all FEX units
- `bgp_config()`: Get BGP configuration
- `ospf_config()`: Get OSPF configuration
- `community_lists()`: Get all community lists
- `as_path_lists()`: Get all AS-path lists

### Getters

- `get_interface(name: str)`: Get interface by name
- `get_vrf(name: str)`: Get VRF by name
- `get_vlan(vlan_id: int)`: Get VLAN by ID
- `get_fex(fex_id: int)`: Get FEX configuration by ID
- `get_community_list(name: str)`: Get community list by name
- `get_as_path_list(name: str)`: Get AS-path list by name

## Example

```python
# Parse router configuration
router = CiscoIOS(config_text)

# Access interface configuration
wan_interface = router.get_interface('GigabitEthernet0/0')
print(f"WAN IP: {wan_interface.ip_address}/{wan_interface.subnet_mask}")

# Check BGP neighbors
bgp = router.bgp_config
for vrf, config in bgp.vrf_configs.items():
    print(f"VRF {vrf} BGP neighbors:")
    for neighbor in config.neighbors:
        print(f"  - {neighbor.address} (AS {neighbor.remote_as})")

# View ACLs
for acl_name, acl in router.config.acls.items():
    print(f"ACL: {acl_name}")
    for entry in acl.entries:
        print(f"  {entry.sequence}: {entry.action} {entry.protocol} {entry.source_ip} -> {entry.destination_ip}")

# Access community lists
community_lists = router.config.community_lists
for name, community_list in community_lists.items():
    print(f"Community List: {name}")
    for entry in community_list.entries:
        print(f"  {entry.action}: {entry.communities}")

# Access AS-path lists
as_path_lists = router.config.as_path_lists
for name, as_path_list in as_path_lists.items():
    print(f"AS-Path List: {name}")
    for entry in as_path_list.entries:
        print(f"  {entry.action}: {entry.regex}")
```

## Community Lists

The parser supports both standard and expanded community lists. Community lists are used to match BGP communities in route-maps.

### Standard Community Lists

```text
ip community-list standard NO_EXPORT permit 65000:0
ip community-list standard CUSTOMER_A permit 65000:100
ip community-list standard CUSTOMER_B permit 65000:200
```

### Expanded Community Lists

```text
ip community-list expanded COMPLEX_FILTER permit ^65000:[0-9]+$
```

### Example Usage

```python
router = CiscoIOS(config_text)
community_lists = router.config.community_lists

# Access a specific community list
customer_a_list = community_lists['CUSTOMER_A']
print(f"Type: {customer_a_list.type}")
print(f"Communities: {customer_a_list.entries[0].communities}")
```

## AS-Path Lists

AS-path lists are used to filter BGP routes based on AS path regular expressions.

### AS-Path List Configuration

```text
ip as-path access-list 100 permit ^65100_
ip as-path access-list 100 deny .*
ip as-path access-list 200 permit ^65200_
ip as-path access-list 200 deny .*
```

### Example Usage

```python
router = CiscoIOS(config_text)
as_path_lists = router.config.as_path_lists

# Access a specific AS-path list
list_100 = as_path_lists['100']
for entry in list_100.entries:
    print(f"Action: {entry.action}, Pattern: {entry.regex}")
```

### Integration with Route Maps

Both community lists and AS-path lists can be referenced in route-maps:

```text
route-map CUSTOMER_A_IMPORT permit 10
 match community CUSTOMER_A
 match as-path 100
 set local-preference 200
```

Access these references in the route-map model:

```python
route_map = router.config.route_maps['CUSTOMER_A_IMPORT']
entry = route_map.entries[0]

# Check community list reference
community_match = entry.match_statements.get('community')  # ['CUSTOMER_A']

# Check AS-path list reference
as_path_match = entry.match_statements.get('as-path')  # ['100']
