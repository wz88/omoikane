import re
from typing import Any, Dict, List, Optional, Set

from ciscoconfparse2 import CiscoConfParse
from pydantic import BaseModel, Field


class AclEntry(BaseModel):
    """Model for ACL entry."""
    sequence: int = 0
    action: str
    protocol: str
    source_ip: str
    source_wildcard: Optional[str] = None
    destination_ip: str
    destination_wildcard: Optional[str] = None
    destination_port: Optional[str] = None
    protocol_option: Optional[str] = None
    log: bool = False
    options: Optional[str] = None

class Acl(BaseModel):
    """Model for ACL configuration."""
    type: str
    entries: List[AclEntry] = Field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)

class PrefixListEntry(BaseModel):
    """Model for a prefix list entry."""
    sequence: int
    action: str
    prefix: str
    ge: int | None = None
    le: int | None = None

class PrefixList(BaseModel):
    """Model for a prefix list."""
    name: str
    entries: List[PrefixListEntry] = Field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)

class RouteMapEntry(BaseModel):
    """Model for route-map entry."""
    sequence: int
    action: str
    description: Optional[str] = None
    match_statements: Dict[str, List[str]] = Field(default_factory=dict)
    set_statements: Dict[str, List[str]] = Field(default_factory=dict)

class RouteMap(BaseModel):
    """Model for route-map configuration."""
    entries: List[RouteMapEntry] = Field(default_factory=list)

class FexConfig(BaseModel):
    """Model for FEX configuration."""
    description: Optional[str] = None
    type: Optional[str] = None
    serial: Optional[str] = None
    max_links: int = 1
    
    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)

class Interface(BaseModel):
    """Model for interface configuration."""
    name: str
    description: Optional[str] = None
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    enabled: bool = True
    speed: Optional[str] = None
    duplex: Optional[str] = None
    vrf: Optional[str] = None
    access_groups: Dict[str, str] = Field(default_factory=dict)  # direction -> acl_name
    switchport_mode: Optional[str] = None
    allowed_vlans: Optional[str] = None
    fex_associate: Optional[int] = None

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)

class VlanConfig(BaseModel):
    """Model for VLAN configuration."""
    vlan_id: int
    name: Optional[str] = None
    state: str = "active"
    interfaces: List[str] = Field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)

class VrfConfig(BaseModel):
    """Model for VRF configuration."""
    name: str
    rd: Optional[str] = None
    route_targets: Dict[str, List[str]] = Field(default_factory=lambda: {"import": [], "export": []})
    interfaces: List[str] = Field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)

class BgpNeighbor(BaseModel):
    """Model for BGP neighbor configuration."""
    address: str
    remote_as: int
    description: Optional[str] = None
    route_maps: Dict[str, str] = Field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)

class BgpVrfConfig(BaseModel):
    """Model for BGP VRF configuration."""
    rd: Optional[str] = None
    neighbors: List[BgpNeighbor] = Field(default_factory=list)
    redistribute: List[str] = Field(default_factory=list)
    maximum_paths: Optional[int] = None

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)

class BgpConfig(BaseModel):
    """Model for BGP configuration."""
    asn: int
    router_id: Optional[str] = None
    vrf_configs: Dict[str, BgpVrfConfig] = Field(default_factory=dict)

    @property
    def as_number(self) -> int:
        """Alias for asn for backward compatibility."""
        return self.asn

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        if key == "as_number":
            return self.asn
        return getattr(self, key)

class OspfNetwork(BaseModel):
    """Model for OSPF network."""
    network: str
    wildcard: str
    area: int | str

class OspfConfig(BaseModel):
    """Model for OSPF configuration."""
    process_id: int
    router_id: Optional[str] = None
    reference_bandwidth: Optional[int] = None
    networks: List[OspfNetwork] = Field(default_factory=list)
    passive_interfaces: Set[str] = Field(default_factory=set)
    area_auth: Dict[str, str] = Field(default_factory=dict)

class SnmpConfig(BaseModel):
    """Model for SNMP configuration."""
    community: Dict[str, str] = Field(default_factory=dict)
    location: Optional[str] = None
    contact: Optional[str] = None
    traps: List[str] = Field(default_factory=list)
    host: Dict[str, Dict[str, str]] = Field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)

class LoggingConfig(BaseModel):
    """Model for logging configuration."""
    buffer_size: Optional[int] = None
    console: Optional[str] = None
    monitor: Optional[str] = None
    hosts: List[str] = Field(default_factory=list)
    trap_level: Optional[str] = None
    trap: Optional[str] = None  # Alias for trap_level
    facility: Optional[str] = None

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        if key == "trap":
            return self.trap_level
        return getattr(self, key)

class NtpServer(BaseModel):
    """Model for NTP server configuration."""
    server: str
    key: Optional[str] = None
    prefer: Optional[bool] = None
    source_interface: Optional[str] = None
    vrf: Optional[str] = None

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)

class AaaConfig(BaseModel):
    """Model for AAA configuration."""
    authentication: Dict[str, Dict[str, List[str]]] = Field(default_factory=lambda: {"login": {}, "enable": {}})
    authorization: Dict[str, Dict[str, List[str]]] = Field(default_factory=lambda: {"exec": {}})
    accounting: Dict[str, Dict[str, Dict[str, Any]]] = Field(default_factory=lambda: {"exec": {}})
    tacacs: Dict[str, Any] = Field(default_factory=lambda: {"hosts": {}, "timeout": 5})

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)

class CommunityListEntry(BaseModel):
    """Model for a community list entry."""
    action: str
    communities: List[str]

class CommunityList(BaseModel):
    """Model for a community list."""
    name: str
    type: str  # standard or expanded
    entries: List[CommunityListEntry] = Field(default_factory=list)

class AsPathListEntry(BaseModel):
    """Model for an AS-path access list entry."""
    sequence: Optional[int]
    action: str
    regex: str

class AsPathList(BaseModel):
    """Model for an AS-path access list."""
    name: str
    entries: List[AsPathListEntry] = Field(default_factory=list)

class RouterConfig(BaseModel):
    """Model for router configuration."""
    hostname: Optional[str] = None
    interfaces: Dict[str, Interface] = Field(default_factory=dict)
    vrfs: Dict[str, VrfConfig] = Field(default_factory=dict)
    vlans: Dict[int, VlanConfig] = Field(default_factory=dict)
    acls: Dict[str, Acl] = Field(default_factory=dict)
    prefix_lists: Dict[str, PrefixList] = Field(default_factory=dict)
    route_maps: Dict[str, RouteMap] = Field(default_factory=dict)
    bgp: Optional[BgpConfig] = None
    ospf: Dict[str, OspfConfig] = Field(default_factory=dict)
    snmp: SnmpConfig = Field(default_factory=SnmpConfig)
    ntp_servers: List[NtpServer] = Field(default_factory=list)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    aaa: AaaConfig = Field(default_factory=AaaConfig)
    fex: Dict[str, FexConfig] = Field(default_factory=dict)
    community_lists: Dict[str, CommunityList] = Field(default_factory=dict)
    as_path_lists: Dict[str, AsPathList] = Field(default_factory=dict)

class CiscoRouter:
    def __init__(self, config_text: str):
        """Initialize CiscoRouter with configuration text."""
        self.config = self._parse_config(config_text)

    def _parse_config(self, config_text: str) -> RouterConfig:
        """Parse configuration text into RouterConfig object."""
        parse = CiscoConfParse(config_text.splitlines())
        return RouterConfig(
            hostname=self._get_hostname(parse),
            interfaces=self._process_interfaces(parse),
            vrfs=self._process_vrfs(parse),
            vlans=self._process_vlans(parse),
            acls=self._process_acls(parse),
            prefix_lists=self._process_prefix_lists(parse),
            route_maps=self._process_route_maps(parse),
            bgp=self._process_bgp(parse),
            ospf=self._process_ospf(parse),
            snmp=self._process_snmp(parse),
            ntp_servers=self._process_ntp(parse),
            logging=self._process_logging(parse),
            aaa=self._process_aaa(parse),
            fex=self._process_fex(parse),
            community_lists=self._process_community_lists(parse),
            as_path_lists=self._process_as_path_lists(parse)
        )

    def _get_hostname(self, parse: CiscoConfParse) -> str:
        """Get hostname from configuration."""
        hostname_obj = parse.find_objects(r'^hostname\s+\S+')
        if hostname_obj:
            return hostname_obj[0].text.split()[1]
        return ''

    def _process_interfaces(self, parse: CiscoConfParse) -> Dict[str, Interface]:
        """Process interface information."""
        interfaces = {}
        for interface in parse.find_objects(r'^interface\s+\S+(?:\s+\S+)?'):
            name = ' '.join(interface.text.split()[1:])
            description = None
            ip_address = None
            subnet_mask = None
            enabled = True
            speed = None
            duplex = None
            vrf = None
            access_groups = {}
            switchport_mode = None
            allowed_vlans = None
            fex_associate = None

            for line in interface.children:
                if 'description' in line.text:
                    match = re.match(r'\s*description\s+(.+)$', line.text)
                    if match:
                        description = match.group(1)
                elif 'ip address' in line.text:
                    match = re.match(r'\s*ip\s+address\s+(\S+)\s+(\S+)', line.text)
                    if match:
                        ip_address, subnet_mask = match.groups()
                elif 'shutdown' in line.text:
                    enabled = False
                elif 'speed' in line.text:
                    match = re.match(r'\s*speed\s+(\S+)', line.text)
                    if match:
                        speed = match.group(1)
                elif 'duplex' in line.text:
                    match = re.match(r'\s*duplex\s+(\S+)', line.text)
                    if match:
                        duplex = match.group(1)
                elif 'vrf forwarding' in line.text:
                    match = re.match(r'\s*vrf\s+forwarding\s+(\S+)', line.text)
                    if match:
                        vrf = match.group(1)
                elif 'ip access-group' in line.text:
                    match = re.match(r'\s*ip\s+access-group\s+(\S+)\s+(in|out)', line.text)
                    if match:
                        acl_name, direction = match.groups()
                        access_groups[direction] = acl_name
                elif 'switchport mode' in line.text:
                    match = re.match(r'\s*switchport\s+mode\s+(\S+)', line.text)
                    if match:
                        switchport_mode = match.group(1)
                elif 'switchport trunk allowed vlan' in line.text:
                    match = re.match(r'\s*switchport\s+trunk\s+allowed\s+vlan\s+(.+)$', line.text)
                    if match:
                        allowed_vlans = match.group(1)
                elif 'fex associate' in line.text:
                    match = re.match(r'\s*fex\s+associate\s+(\d+)', line.text)
                    if match:
                        fex_associate = int(match.group(1))

            interfaces[name] = Interface(
                name=name,
                description=description or '',
                ip_address=ip_address or '',
                subnet_mask=subnet_mask or '',
                enabled=enabled,
                speed=speed or '',
                duplex=duplex or '',
                vrf=vrf,
                access_groups=access_groups,
                switchport_mode=switchport_mode,
                allowed_vlans=allowed_vlans,
                fex_associate=fex_associate
            )
        return interfaces

    def _process_vrfs(self, parse: CiscoConfParse) -> Dict[str, VrfConfig]:
        """Process VRF information."""
        vrfs = {}
        for vrf in parse.find_objects(r'^vrf definition'):
            match = re.match(r'\s*vrf definition\s+(\S+)', vrf.text)
            if match:
                vrf_name = match.group(1)
                rd = None
                route_targets = {"import": [], "export": []}
                interfaces = []

                # Process VRF configuration
                for line in vrf.children:
                    if 'rd' in line.text:
                        rd_match = re.match(r'\s*rd\s+(\S+)', line.text)
                        if rd_match:
                            rd = rd_match.group(1)
                    elif 'route-target' in line.text:
                        rt_match = re.match(r'\s*route-target\s+(import|export)\s+(\S+)', line.text)
                        if rt_match:
                            rt_type, rt_value = rt_match.groups()
                            route_targets[rt_type].append(rt_value)

                # Find interfaces associated with this VRF
                for intf in parse.find_objects(r'^interface'):
                    for line in intf.children:
                        if 'vrf forwarding' in line.text and vrf_name in line.text:
                            interfaces.append(intf.text.split()[1])

                vrfs[vrf_name] = VrfConfig(
                    name=vrf_name,
                    rd=rd,
                    route_targets=route_targets,
                    interfaces=interfaces
                )
        return vrfs

    def _process_vlans(self, parse: CiscoConfParse) -> Dict[int, VlanConfig]:
        """Process VLAN information."""
        vlans = {}
        for vlan in parse.find_objects(r'^vlan\s+\d+'):
            vlan_id = int(vlan.text.split()[1])
            name = None
            state = 'active'

            for line in vlan.children:
                if 'name' in line.text:
                    match = re.match(r'\s*name\s+(\S+)', line.text)
                    if match:
                        name = match.group(1)
                elif 'state' in line.text:
                    match = re.match(r'\s*state\s+(\S+)', line.text)
                    if match:
                        state = match.group(1)

            vlans[vlan_id] = VlanConfig(
                vlan_id=vlan_id,
                name=name,
                state=state,
                interfaces=[]
            )
        return vlans

    def _process_acls(self, parse: CiscoConfParse) -> Dict[str, Acl]:
        """Process ACL information."""
        acls = {}
        
        for line in parse.find_objects(r'^ip access-list'):
            match = re.match(r'ip access-list (extended|standard) (\S+)', line.text)
            if match:
                acl_type, acl_name = match.groups()
                acl = Acl(type=acl_type)
                acls[acl_name] = acl
                
                for entry in line.children:
                    if entry.text.strip().startswith(('permit', 'deny')):
                        parts = entry.text.strip().split()
                        action = parts[0]
                        
                        # Handle sequence number if present
                        if len(parts) > 1 and parts[1].isdigit():
                            seq = int(parts[1])
                            parts = parts[2:]  # Remove sequence number
                        else:
                            seq = 0
                            parts = parts[1:]  # Remove action
                        
                        # Handle protocol
                        if acl_type == 'extended':
                            protocol = parts[0] if parts else 'ip'
                            parts = parts[1:]  # Remove protocol
                        else:
                            protocol = 'ip'
                        
                        # Handle source
                        source_ip = parts[0] if parts else 'any'
                        source_wildcard = None
                        parts = parts[1:]

                        if source_ip == 'host':
                            source_ip = parts[0]
                            parts = parts[1:]
                        elif source_ip != 'any' and parts and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                            source_wildcard = parts[0]
                            parts = parts[1:]
                            
                        # Handle destination
                        destination_ip = parts[0] if parts else 'any'
                        destination_wildcard = None
                        parts = parts[1:]

                        if destination_ip == 'host':
                            destination_ip = parts[0]
                            parts = parts[1:]
                        elif destination_ip != 'any' and parts and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                            destination_wildcard = parts[0]
                            parts = parts[1:]

                        # Handle destination port if present
                        destination_port = None
                        if len(parts) >= 2 and parts[0] == 'eq':
                            destination_port = parts[1]
                            parts = parts[2:]

                        # Handle protocol options (like icmp echo)
                        protocol_option = None
                        if protocol == 'icmp' and parts:
                            protocol_option = parts[0]
                            parts = parts[1:]

                        # Handle log option
                        log = False
                        if parts and parts[-1] == 'log':
                            log = True
                            parts = parts[:-1]
                        
                        acl_entry = AclEntry(
                            sequence=seq,
                            action=action,
                            protocol=protocol,
                            source_ip=source_ip,
                            source_wildcard=source_wildcard,
                            destination_ip=destination_ip,
                            destination_wildcard=destination_wildcard,
                            destination_port=destination_port,
                            protocol_option=protocol_option,
                            log=log
                        )
                        acl.entries.append(acl_entry)
        
        return acls

    def _process_prefix_lists(self, parse: CiscoConfParse) -> Dict[str, PrefixList]:
        """Process prefix list information."""
        prefix_lists = {}
        current_list = None
        current_entries = []
        
        for line in parse.find_objects(r'^ip prefix-list'):
            # Split regex for readability
            regex = (
                r'ip prefix-list\s+(\S+)'  # List name
                r'(?:\s+seq\s+(\d+))?'     # Optional sequence number
                r'\s+(permit|deny)'         # Action
                r'\s+(\S+)'                 # Prefix
                r'(?:\s+ge\s+(\d+))?'      # Optional ge value
                r'(?:\s+le\s+(\d+))?'      # Optional le value
            )
            match = re.match(regex, line.text)
            if match:
                name, seq, action, prefix, ge, le = match.groups()
                seq = int(seq) if seq else 0
                
                if current_list != name:
                    if current_list:
                        prefix_lists[current_list] = PrefixList(name=current_list, entries=current_entries)
                    current_list = name
                    current_entries = []
                
                current_entries.append(PrefixListEntry(
                    sequence=seq,
                    action=action,
                    prefix=prefix,
                    ge=int(ge) if ge else None,
                    le=int(le) if le else None
                ))
        
        if current_list:
            prefix_lists[current_list] = PrefixList(name=current_list, entries=current_entries)
        
        return prefix_lists

    def _process_route_maps(self, parse: CiscoConfParse) -> Dict[str, RouteMap]:
        """Process route-map information."""
        route_maps = {}
        current_map = None
        current_entry = None

        for line in parse.find_objects(r'^route-map'):
            match = re.match(r'route-map\s+(\S+)\s+(\S+)\s+(\d+)', line.text)
            if match:
                map_name, action, seq = match.groups()
                if map_name not in route_maps:
                    route_maps[map_name] = RouteMap()
                current_map = map_name
                current_entry = RouteMapEntry(
                    sequence=int(seq),
                    action=action
                )
                route_maps[current_map].entries.append(current_entry)

                for child in line.children:
                    child_text = child.text.strip()
                    if child_text.startswith('description'):
                        current_entry.description = child_text.split('description', 1)[1].strip().strip('"')
                    elif child_text.startswith('match'):
                        parts = child_text.split()
                        if len(parts) >= 3:
                            # Handle special cases for match statements
                            if parts[1] == 'ip' and parts[2] == 'address':
                                key = 'ip address'
                                values = parts[3:]
                            elif parts[1] == 'as-path':
                                key = 'as-path'
                                values = parts[2:]
                            elif parts[1] == 'community':
                                key = 'community'
                                values = parts[2:]
                            else:
                                key = parts[1]
                                if len(parts) >= 4 and parts[2] in ('ip', 'prefix-list'):
                                    key = f"{parts[1]} {parts[2]}"
                                    values = parts[3:]
                                else:
                                    values = parts[2:]
                            current_entry.match_statements[key] = values
                    elif child_text.startswith('set'):
                        parts = child_text.split()
                        if len(parts) >= 3:
                            key = parts[1]
                            # Handle special cases for set statements
                            if key == 'community':
                                # Handle community with additive and no-export options
                                values = []
                                for part in parts[2:]:
                                    values.append(part)
                                current_entry.set_statements[key] = values
                            elif key == 'as-path' and parts[2] == 'prepend':
                                # Handle AS path prepending
                                current_entry.set_statements[key] = ['prepend'] + parts[3:]
                            else:
                                current_entry.set_statements[key] = parts[2:]
        return route_maps

    def _parse_bgp_neighbor(self, line_text: str, neighbor_lines: Optional[List[str]] = None) -> Optional[BgpNeighbor]:
        """Parse BGP neighbor configuration."""
        match = re.match(r'\s*neighbor\s+(\S+)\s+remote-as\s+(\d+)', line_text)
        if match:
            neighbor_ip, remote_as = match.groups()
            neighbor_description = None
            route_maps = {}
            
            # If we have additional neighbor lines, process them
            if neighbor_lines:
                for line in neighbor_lines:
                    # Extract description if present
                    desc_match = re.search(r'description\s+(.+?)(?:\s+\w+\s+|$)', line)
                    if desc_match:
                        neighbor_description = desc_match.group(1)
                    
                    # Extract route maps
                    map_match = re.search(r'route-map\s+(\S+)\s+(in|out)', line)
                    if map_match:
                        map_name, direction = map_match.groups()
                        route_maps[direction] = map_name
            
            return BgpNeighbor(
                address=neighbor_ip,
                remote_as=int(remote_as),
                description=neighbor_description,
                route_maps=route_maps
            )
        return None

    def _process_bgp(self, parse: CiscoConfParse) -> Optional[BgpConfig]:
        """Process BGP configuration."""
        bgp_obj = parse.find_objects(r'^router bgp')
        if not bgp_obj:
            return None

        bgp_obj = bgp_obj[0]
        as_match = re.search(r'router bgp (\d+)', bgp_obj.text)
        if not as_match:
            return None

        as_number = int(as_match.group(1))
        router_id = None
        vrf_configs: Dict[str, BgpVrfConfig] = {}

        # Process BGP configuration
        for line in bgp_obj.children:
            line_text = line.text.strip()
            
            if 'router-id' in line_text:
                router_id = line_text.split()[-1]
            elif 'address-family ipv4 vrf' in line_text:
                vrf_name = line_text.split()[-1]
                vrf_config = BgpVrfConfig(name=vrf_name)
                neighbor_configs: Dict[str, BgpNeighbor] = {}

                # Process VRF configuration
                for vrf_line in line.children:
                    vrf_text = vrf_line.text.strip()
                    
                    if vrf_text.startswith('redistribute'):
                        protocol = vrf_text.split()[1]
                        if protocol not in vrf_config.redistribute:
                            vrf_config.redistribute.append(protocol)
                    elif vrf_text.startswith('neighbor'):
                        parts = vrf_text.split()
                        neighbor_ip = parts[1]
                        
                        if 'remote-as' in vrf_text:
                            # Collect all lines for this neighbor in this address-family
                            neighbor_lines = [vrf_text]
                            for sibling in line.children:
                                sibling_text = sibling.text.strip()
                                if sibling_text.startswith('neighbor') and sibling_text.split()[1] == neighbor_ip:
                                    neighbor_lines.append(sibling_text)
                            
                            # Parse neighbor with all its lines
                            neighbor = self._parse_bgp_neighbor(vrf_text, neighbor_lines)
                            if neighbor:
                                neighbor_configs[neighbor_ip] = neighbor
                    elif 'maximum-paths' in vrf_text:
                        max_paths = int(vrf_text.split()[1])
                        vrf_config.maximum_paths = max_paths

                vrf_config.neighbors = list(neighbor_configs.values())
                vrf_configs[vrf_name] = vrf_config

        return BgpConfig(
            asn=as_number,
            router_id=router_id,
            vrf_configs=vrf_configs
        )

    def _process_ospf(self, parse: CiscoConfParse) -> Dict[str, OspfConfig]:
        """Process OSPF information."""
        ospf_configs = {}
        for ospf in parse.find_objects(r'^router ospf'):
            process_id = int(ospf.text.split()[2])
            router_id = None
            reference_bandwidth = None
            networks = []
            passive_interfaces = set()
            area_auth = {}

            for line in ospf.children:
                if 'router-id' in line.text:
                    match = re.match(r'\s*router-id (\S+)', line.text)
                    if match:
                        router_id = match.group(1)
                elif 'auto-cost reference-bandwidth' in line.text:
                    match = re.match(r'\s*auto-cost\s+reference-bandwidth\s+(\d+)', line.text)
                    if match:
                        reference_bandwidth = int(match.group(1))
                elif 'network' in line.text:
                    match = re.match(r'\s*network\s+(\S+)\s+(\S+)\s+area\s+(\S+)', line.text)
                    if match:
                        network, wildcard, area = match.groups()
                        try:
                            area_val = int(area)
                        except ValueError:
                            area_val = area
                        networks.append(OspfNetwork(
                            network=network,
                            wildcard=wildcard,
                            area=area_val
                        ))
                elif 'passive-interface' in line.text:
                    if 'default' in line.text:
                        passive_interfaces.add('default')
                    else:
                        match = re.match(r'\s*passive-interface\s+(\S+)', line.text)
                        if match:
                            interface = match.group(1)
                            passive_interfaces.add(interface)
                elif 'area' in line.text and 'authentication' in line.text:
                    match = re.match(r'\s*area\s+(\S+)\s+authentication\s+(\S+)', line.text)
                    if match:
                        area, auth_type = match.groups()
                        area_auth[area] = auth_type

            ospf_configs[str(process_id)] = OspfConfig(
                process_id=process_id,
                router_id=router_id,
                reference_bandwidth=reference_bandwidth,
                networks=networks,
                passive_interfaces=passive_interfaces,
                area_auth=area_auth
            )
        return ospf_configs

    def _process_snmp(self, parse: CiscoConfParse) -> SnmpConfig:
        """Process SNMP information."""
        snmp_config = SnmpConfig(
            community={},
            location=None,
            contact=None,
            traps=[],
            host={}
        )

        for line in parse.find_objects(r'^snmp-server'):
            if 'community' in line.text:
                match = re.match(r'snmp-server community (\S+) (RO|RW)', line.text)
                if match:
                    community, access = match.groups()
                    snmp_config.community[community] = access
            elif 'location' in line.text:
                match = re.match(r'snmp-server location (.*)', line.text)
                if match:
                    snmp_config.location = match.group(1).strip().strip('"')
            elif 'contact' in line.text:
                match = re.match(r'snmp-server contact (.*)', line.text)
                if match:
                    snmp_config.contact = match.group(1).strip().strip('"')
            elif 'enable traps' in line.text:
                match = re.match(r'snmp-server enable traps (\S+)', line.text)
                if match:
                    snmp_config.traps.append(match.group(1))
            elif 'host' in line.text:
                match = re.match(r'snmp-server host (\S+)(?:\s+version\s+(\S+))?\s+(\S+)', line.text)
                if match:
                    host, version, community = match.groups()
                    snmp_config.host[host] = {
                        "version": version or "2c",
                        "community": community
                    }

        return snmp_config

    def _process_ntp(self, parse: CiscoConfParse) -> List[NtpServer]:
        """Process NTP information."""
        ntp_servers = []
        
        for line in parse.find_objects(r'^ntp server'):
            match = re.match(r'ntp server (\S+)(?:\s+prefer)?(?:\s+key\s+(\S+))?', line.text)
            if match:
                server, key = match.groups()
                prefer = 'prefer' in line.text
                ntp_servers.append(NtpServer(
                    server=server,
                    key=key,
                    prefer=prefer
                ))
        
        return ntp_servers

    def _process_logging(self, parse: CiscoConfParse) -> LoggingConfig:
        """Process logging information."""
        buffer_size = None
        console = None
        monitor = None
        hosts = []
        trap_level = None
        facility = None

        for line in parse.find_objects(r'^logging'):
            if 'buffered' in line.text:
                match = re.match(r'logging buffered (\d+)', line.text)
                if match:
                    buffer_size = int(match.group(1))
            elif 'console' in line.text:
                match = re.match(r'logging console (\w+)', line.text)
                if match:
                    console = match.group(1)
            elif 'monitor' in line.text:
                match = re.match(r'logging monitor (\w+)', line.text)
                if match:
                    monitor = match.group(1)
            elif 'host' in line.text:
                match = re.match(r'logging host (\S+)', line.text)
                if match:
                    hosts.append(match.group(1))
            elif 'trap' in line.text:
                match = re.match(r'logging trap (\w+)', line.text)
                if match:
                    trap_level = match.group(1)
            elif 'facility' in line.text:
                match = re.match(r'logging facility (\w+)', line.text)
                if match:
                    facility = match.group(1)

        return LoggingConfig(
            buffer_size=buffer_size,
            console=console,
            monitor=monitor,
            hosts=hosts,
            trap_level=trap_level,
            trap=trap_level,
            facility=facility
        )

    def _process_aaa(self, parse: CiscoConfParse) -> AaaConfig:
        """Process AAA information."""
        authentication = {"login": {}, "enable": {}}
        authorization = {"exec": {}}
        accounting = {"exec": {}}
        tacacs = {"hosts": {}, "timeout": 5}

        for line in parse.find_objects(r'^aaa'):
            if 'authentication' in line.text:
                match = re.match(r'\s*aaa authentication (\S+) (\S+) (.+)', line.text)
                if match:
                    auth_type, list_name, methods = match.groups()
                    if auth_type not in authentication:
                        authentication[auth_type] = {}
                    methods_list = []
                    current_group = None
                    for method in methods.strip().split():
                        if method == "group":
                            current_group = "group"
                        elif current_group == "group":
                            methods_list.append(f"group {method}")
                            current_group = None
                        else:
                            methods_list.append(method)
                    authentication[auth_type][list_name] = methods_list

            elif 'authorization' in line.text:
                match = re.match(r'\s*aaa authorization (\S+) (\S+) (.+)', line.text)
                if match:
                    auth_type, list_name, methods = match.groups()
                    if auth_type not in authorization:
                        authorization[auth_type] = {}
                    methods_list = []
                    current_group = None
                    for method in methods.strip().split():
                        if method == "group":
                            current_group = "group"
                        elif current_group == "group":
                            methods_list.append(f"group {method}")
                            current_group = None
                        else:
                            methods_list.append(method)
                    authorization[auth_type][list_name] = methods_list

            elif 'accounting' in line.text:
                match = re.match(r'\s*aaa accounting (\S+) (\S+) (start-stop|stop-only|none)\s*(.+)?', line.text)
                if match:
                    acct_type, list_name, record_type, methods = match.groups()
                    if acct_type not in accounting:
                        accounting[acct_type] = {}
                    methods_list = []
                    if methods:
                        current_group = None
                        for method in methods.strip().split():
                            if method == "group":
                                current_group = "group"
                            elif current_group == "group":
                                methods_list.append(f"group {method}")
                                current_group = None
                            else:
                                methods_list.append(method)
                    accounting[acct_type][list_name] = {
                        "record_type": record_type,
                        "methods": methods_list
                    }

        for line in parse.find_objects(r'^tacacs-server'):
            if 'host' in line.text:
                match = re.match(r'\s*tacacs-server host (\S+)(?:\s+key\s+(\S+))?', line.text)
                if match:
                    host, key = match.groups()
                    tacacs["hosts"][host] = {"key": key} if key else {}
            elif 'timeout' in line.text:
                match = re.match(r'\s*tacacs-server timeout (\d+)', line.text)
                if match:
                    tacacs["timeout"] = int(match.group(1))

        return AaaConfig(
            authentication=authentication,
            authorization=authorization,
            accounting=accounting,
            tacacs=tacacs
        )

    def _process_fex(self, parse: CiscoConfParse) -> Dict[str, FexConfig]:
        """Process FEX information."""
        fex_configs = {}
        
        for line in parse.find_objects(r'^fex\s+\d+'):
            match = re.match(r'fex\s+(\d+)', line.text)
            if match:
                fex_id = match.group(1)
                description = None
                fex_type = None
                serial = None
                max_links = 1
                
                for child in line.children:
                    if 'description' in child.text:
                        description = child.text.split('description', 1)[1].strip().strip('"')
                    elif 'type' in child.text:
                        fex_type = child.text.split('type', 1)[1].strip().strip('"')
                    elif 'serial' in child.text:
                        serial = child.text.split('serial', 1)[1].strip().strip('"')
                    elif 'pinning max-links' in child.text:
                        match = re.match(r'\s*pinning max-links (\d+)', child.text)
                        if match:
                            max_links = int(match.group(1))
                
                fex_configs[fex_id] = FexConfig(
                    description=description,
                    type=fex_type,
                    serial=serial,
                    max_links=max_links
                )
        
        return fex_configs

    def _process_community_lists(self, parse: CiscoConfParse) -> Dict[str, CommunityList]:
        """Process community lists."""
        community_lists: Dict[str, CommunityList] = {}
        
        # Find all community list lines
        for line in parse.find_objects(r'^ip community-list'):
            # Parse the line
            match = re.match(r'^ip community-list (standard|expanded)? ?(\S+) (\S+) (.+)$', line.text)
            if match:
                list_type, name, action, communities = match.groups()
                list_type = list_type if list_type else 'standard'  # Default to standard if not specified
                
                if name not in community_lists:
                    community_lists[name] = CommunityList(name=name, type=list_type)
                
                # Split communities and clean them
                community_values = [c.strip() for c in communities.split()]
                
                entry = CommunityListEntry(
                    action=action,
                    communities=community_values
                )
                community_lists[name].entries.append(entry)
        
        return community_lists

    def _process_as_path_lists(self, parse: CiscoConfParse) -> Dict[str, AsPathList]:
        """Process AS path access lists."""
        as_path_lists: Dict[str, AsPathList] = {}
        
        # Find all AS path access list lines
        for line in parse.find_objects(r'^ip as-path access-list'):
            # Parse the line
            match = re.match(r'^ip as-path access-list (\S+) (\S+)( \d+)? (.+)$', line.text)
            if match:
                name, action, sequence, regex = match.groups()
                
                if name not in as_path_lists:
                    as_path_lists[name] = AsPathList(name=name)
                
                entry = AsPathListEntry(
                    sequence=int(sequence.strip()) if sequence else None,
                    action=action,
                    regex=regex.strip()
                )
                as_path_lists[name].entries.append(entry)
        
        return as_path_lists

    @property
    def interfaces(self) -> List[Interface]:
        """Return a list of all interfaces configured on the router."""
        return list(self.config.interfaces.values())
    
    @property
    def vrfs(self) -> List[VrfConfig]:
        """Return a list of all VRFs configured on the router."""
        return list(self.config.vrfs.values())
    
    @property
    def vlans(self) -> List[VlanConfig]:
        """Return a list of all VLANs configured on the router."""
        return list(self.config.vlans.values())
    
    @property
    def prefix_lists(self) -> Dict[str, PrefixList]:
        """Return all prefix lists configured on the router."""
        return self.config.prefix_lists
    
    @property
    def route_maps(self) -> Dict[str, RouteMap]:
        """Return all route-maps configured on the router."""
        return self.config.route_maps
    
    @property
    def acls(self) -> Dict[str, Acl]:
        """Return all ACLs configured on the router."""
        return self.config.acls
    
    @property
    def fex_units(self) -> List[Any]:
        """Return a list of all FEX units configured on the router."""
        return list(self.config.fex.values())
    
    @property
    def bgp_config(self) -> BgpConfig:
        """Return BGP configuration."""
        return self.config.bgp
    
    @property
    def ospf_config(self) -> Dict[str, OspfConfig]:
        """Return all OSPF processes configured on the router."""
        return self.config.ospf
    
    def get_interface(self, name: str) -> Optional[Interface]:
        """Get interface configuration by name."""
        return self.config.interfaces.get(name)
    
    def get_vrf(self, name: str) -> Optional[VrfConfig]:
        """Get VRF configuration by name."""
        return self.config.vrfs.get(name)
    
    def get_vlan(self, vlan_id: int) -> Optional[VlanConfig]:
        """Get VLAN configuration by ID."""
        return self.config.vlans.get(vlan_id)
    
    def get_fex(self, fex_id: str) -> Optional[Any]:
        """Get FEX configuration by ID."""
        return self.config.fex.get(str(fex_id))
    
    def __str__(self) -> str:
        return f"CiscoRouter(hostname={self.config.hostname}, interfaces={len(self.config.interfaces)})"

    def __repr__(self) -> str:
        return f"CiscoRouter(hostname={self.config.hostname}, interfaces={len(self.config.interfaces)})"
