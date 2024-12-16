import re
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, Field, ConfigDict
from ciscoconfparse2 import CiscoConfParse

from src.models.base.device import Device
from src.models.base.router_config import RouterConfig
from src.models.base.interface import Interface
from src.models.base.vrf import VrfConfig
from src.models.base.vlan import VlanConfig
from src.models.base.acl import Acl, AclEntry
from src.models.base.prefix_list import PrefixList, PrefixListEntry
from src.models.base.route_map import RouteMap, RouteMapEntry
from src.models.base.bgp import BgpConfig, BgpVrfConfig, BgpNeighbor
from src.models.base.ospf import OspfConfig, OspfNetwork
from src.models.base.snmp import SnmpConfig
from src.models.base.ntp import NtpServer
from src.models.base.logging import LoggingConfig
from src.models.base.aaa import AaaConfig
from src.models.base.fex import FexConfig
from src.models.base.community_list import CommunityList, CommunityListEntry
from src.models.base.as_path import AsPathList, AsPathListEntry
from src.models.base.route import Route


class CiscoRouter(Device):
    """Model for Cisco router."""
    def __init__(self, config_text: str | None = None, hostname: str | None = None):
        """Initialize CiscoRouter."""
        super().__init__(hostname=hostname)
        self._routes: List[Route] = []
        self._interfaces: Dict[str, Interface] = {}
        self._vrfs: Dict[str, VrfConfig] = {}  # Add private VRFs storage
        self.config: RouterConfig | None = None
        if config_text:
            self.parse_config(config_text)

    def parse_config(self, config_text: str) -> None:
        """Parse configuration text."""
        parse = CiscoConfParse(config_text.splitlines())

        # Find hostname first
        hostname_obj = parse.find_objects(r'^hostname\s+\S+')
        if hostname_obj:
            self.hostname = hostname_obj[0].text.split(None, 1)[1]

        # Process each section
        self._interfaces = self._process_interfaces(parse)
        self._vrfs = self._process_vrfs(parse)  # Store in private variable
        
        # Create the router config object
        self.config = RouterConfig(
            hostname=self.hostname,
            interfaces=self._interfaces,
            vrfs=self._vrfs,  # Use private variable
            vlans=self._process_vlans(parse),
            fex=self._process_fex(parse),
            bgp=self._process_bgp(parse),
            ospf=self._process_ospf(parse),
            prefix_lists=self._process_prefix_lists(parse),
            route_maps=self._process_route_maps(parse),
            acls=self._process_acls(parse),
            snmp=self._process_snmp(parse),
            ntp_servers=self._process_ntp(parse),
            logging=self._process_logging(parse),
            aaa=self._process_aaa(parse),
            community_lists=self._process_community_lists(parse),
            as_path_lists=self._process_as_path_lists(parse)
        )

        # Update instance attributes
        self._routes = self.config.routes if hasattr(self.config, 'routes') else []

    @property
    def interface_list(self) -> List[Interface]:
        """Return a list of all interfaces configured on the device."""
        return list(self._interfaces.values())
    
    @property
    def vrf_list(self) -> List[VrfConfig]:
        """Return a list of all VRFs configured on the device."""
        return list(self._vrfs.values())

    @property
    def interfaces(self) -> Dict[str, Interface]:
        """Return all interfaces configured on the device."""
        return self._interfaces

    @property
    def vrfs(self) -> Dict[str, VrfConfig]:
        """Return all VRFs configured on the device."""
        return self._vrfs

    def get_routes(self) -> List[Route]:
        """Get all parsed routes."""
        return self._routes

    def get_routes_by_protocol(self, protocol: str) -> List[Route]:
        """Get routes filtered by protocol."""
        return [route for route in self._routes if route.protocol == protocol]

    def get_routes_by_network(self, network: str) -> List[Route]:
        """Get routes for a specific network."""
        return [route for route in self._routes if route.network == network]

    def get_best_routes(self) -> List[Route]:
        """Get only the best routes for each network."""
        return [route for route in self._routes if route.is_best]

    @property
    def vlans(self) -> Dict[int, VlanConfig]:
        """Return all VLANs configured on the router."""
        return self.config.vlans if self.config else {}

    @property
    def fex_units(self) -> Dict[str, FexConfig]:
        """Return all FEX units configured on the router."""
        return self.config.fex if self.config else {}

    @property
    def bgp_config(self) -> Optional[BgpConfig]:
        """Return BGP configuration."""
        return self.config.bgp if self.config else None

    @property
    def ospf_config(self) -> Dict[str, OspfConfig]:
        """Return all OSPF processes configured on the router."""
        return self.config.ospf if self.config else {}

    @property
    def prefix_lists(self) -> Dict[str, PrefixList]:
        """Return all prefix lists configured on the router."""
        return self.config.prefix_lists if self.config else {}

    @property
    def route_maps(self) -> Dict[str, RouteMap]:
        """Return all route-maps configured on the router."""
        return self.config.route_maps if self.config else {}

    @property
    def acls(self) -> Dict[str, Acl]:
        """Return all ACLs configured on the router."""
        return self.config.acls if self.config else {}

    def get_vrf(self, name: str) -> Optional[VrfConfig]:
        """Get VRF configuration by name."""
        return self._vrfs.get(name)

    def get_interface(self, name: str) -> Optional[Interface]:
        """Get interface configuration by name."""
        return self._interfaces.get(name)

    def get_vlan(self, vlan_id: int) -> Optional[VlanConfig]:
        """Get VLAN configuration by ID."""
        return self.vlans.get(vlan_id)

    def get_fex(self, fex_id: Union[str, int]) -> Optional[FexConfig]:
        """Get FEX configuration by ID."""
        if isinstance(fex_id, int):
            fex_id = str(fex_id)
        return self.fex_units.get(fex_id) if self.config and hasattr(self.config, 'fex') else None

    def _get_hostname(self, parse: CiscoConfParse) -> str | None:
        """Get hostname from configuration."""
        hostname_obj = parse.find_objects(r'^hostname\s+(.+)$')
        if hostname_obj:
            return hostname_obj[0].text.split(None, 1)[1]
        return self.hostname

    def _process_interfaces(self, parse: CiscoConfParse) -> Dict[str, Interface]:
        """Process interface configuration."""
        interfaces = {}
        interface_objs = parse.find_objects(r'^interface\s+\S+')

        for interface_obj in interface_objs:
            match = re.match(r'^interface\s+(\S+(?:\s+\S+)?)', interface_obj.text)  # Handle spaces in interface names
            if match:
                name = match.group(1)
                description = None
                ip_address = None
                subnet_mask = None
                vrf = None
                shutdown = False
                speed = None
                duplex = None
                access_groups = {}
                switchport_mode = None
                vlan = None
                allowed_vlans = None
                fex_associate = None

                for child in interface_obj.children:
                    child_text = child.text.strip()
                    if 'description' in child_text:
                        description = child_text.split('description', 1)[1].strip()
                    elif 'ip address' in child_text:
                        ip_match = re.match(r'\s*ip address\s+(\S+)\s+(\S+)', child_text)
                        if ip_match:
                            ip_address = ip_match.group(1)
                            subnet_mask = ip_match.group(2)
                    elif 'vrf forwarding' in child_text or 'vrf member' in child_text:
                        vrf = child_text.split()[-1].strip()
                    elif 'shutdown' in child_text:
                        shutdown = True
                    elif 'speed' in child_text:
                        speed_match = re.match(r'\s*speed\s+(\d+)', child_text)
                        if speed_match:
                            speed = speed_match.group(1)
                    elif 'duplex' in child_text:
                        duplex = child_text.split('duplex', 1)[1].strip()
                    elif 'ip access-group' in child_text:
                        access_match = re.match(r'\s*ip access-group\s+(\S+)\s+(in|out)', child_text)
                        if access_match:
                            acl_name, direction = access_match.groups()
                            access_groups[direction] = acl_name
                    elif 'switchport mode' in child_text:
                        mode_match = re.match(r'\s*switchport mode\s+(\S+)', child_text)
                        if mode_match:
                            switchport_mode = mode_match.group(1)
                    elif 'switchport access vlan' in child_text:
                        vlan_match = re.match(r'\s*switchport access vlan\s+(\d+)', child_text)
                        if vlan_match:
                            vlan = int(vlan_match.group(1))
                    elif 'switchport trunk allowed vlan' in child_text:
                        vlan_match = re.match(r'\s*switchport trunk allowed vlan\s+(.+)', child_text)
                        if vlan_match:
                            allowed_vlans = vlan_match.group(1).strip()
                    elif 'fex associate' in child_text:
                        fex_match = re.match(r'\s*fex associate\s+(\d+)', child_text)
                        if fex_match:
                            fex_associate = int(fex_match.group(1))

                interfaces[name] = Interface(
                    name=name,
                    description=description,
                    ip_address=ip_address,
                    subnet_mask=subnet_mask,
                    vrf=vrf,
                    enabled=not shutdown,
                    speed=speed,
                    duplex=duplex,
                    access_groups=access_groups,
                    switchport_mode=switchport_mode,
                    vlan=vlan,
                    allowed_vlans=allowed_vlans,
                    fex_associate=fex_associate
                )

        return interfaces

    def _process_vrfs(self, parse: CiscoConfParse) -> Dict[str, VrfConfig]:
        """Process VRF configuration."""
        vrfs = {}
        vrf_objs = parse.find_objects(r'^(?:vrf\s+definition|ip\s+vrf)\s+\S+')
        interface_objs = parse.find_objects(r'^interface\s+\S+')

        # First pass: collect VRF configurations
        for vrf_obj in vrf_objs:
            match = re.match(r'^(?:vrf\s+definition|ip\s+vrf)\s+(\S+)', vrf_obj.text)
            if match:
                name = match.group(1)
                description = None
                rd = None
                route_targets = {"import": [], "export": []}

                for child in vrf_obj.children:
                    child_text = child.text.strip()
                    if 'description' in child_text:
                        description = child_text.split('description', 1)[1].strip()
                    elif 'rd' in child_text:
                        rd = child_text.split('rd', 1)[1].strip()
                    elif 'route-target' in child_text:
                        rt_match = re.match(r'\s*route-target\s+(import|export)\s+(\S+)', child_text)
                        if rt_match:
                            direction, target = rt_match.groups()
                            route_targets[direction].append(target)

                vrfs[name] = VrfConfig(
                    name=name,
                    description=description,
                    rd=rd,
                    route_targets=route_targets,
                    interfaces=[]  # Initialize empty list for interfaces
                )

        # Second pass: associate interfaces with VRFs
        for interface_obj in interface_objs:
            for child in interface_obj.children:
                child_text = child.text.strip()
                if 'vrf forwarding' in child_text or 'vrf member' in child_text:
                    vrf_name = child_text.split()[-1].strip()
                    if vrf_name in vrfs:
                        match = re.match(r'^interface\s+(\S+(?:\s+\S+)?)', interface_obj.text)
                        if match:
                            interface_name = match.group(1)
                            vrfs[vrf_name].interfaces.append(interface_name)

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
                name=name or '',
                state=state
            )
        return vlans

    def _process_acls(self, parse: CiscoConfParse) -> Dict[str, Acl]:
        """Process ACL information."""
        acls = {}

        for line in parse.find_objects(r'^ip access-list'):
            match = re.match(r'ip access-list (extended|standard) (\S+)', line.text)
            if match:
                acl_type, acl_name = match.groups()
                acl = Acl(name=acl_name, type=acl_type)

                # Keep track of sequence number
                next_seq = 10

                # Process ACL entries
                for entry in line.children:
                    # Parse ACL entry with a single comprehensive regex
                    match = re.match(
                        r'\s*'
                        r'(?:(\d+)\s+)?'  # Optional sequence number
                        r'(permit|deny)\s+'  # Action
                        r'(\S+)\s+'  # Protocol
                        r'(host\s+\S+|any|\S+(?:\s+\S+)?)\s+'  # Source IP/Wildcard
                        r'(host\s+\S+|any|\S+(?:\s+\S+)?)'  # Destination IP/Wildcard
                        r'(?:\s+(?:eq\s+)?(\S+))?'  # Optional port/ICMP type
                        r'(.*)',  # Remaining options
                        entry.text
                    )
                    
                    if not match:
                        continue

                    sequence, action, protocol, source, destination, port_or_type, options = match.groups()
                    sequence = int(sequence) if sequence else next_seq
                    next_seq += 10 if not sequence else 0
                    
                    # Process source
                    source_wildcard = None
                    if source.startswith('host '):
                        source_ip = source.split()[1]
                        source = source_ip
                    elif source == 'any':
                        source_ip = source
                    else:
                        parts = source.split()
                        source_ip = parts[0]
                        source_wildcard = parts[1] if len(parts) > 1 else None
                        source = source_ip

                    # Process destination
                    destination_wildcard = None
                    if destination.startswith('host '):
                        destination_ip = destination.split()[1]
                        destination = destination_ip
                    elif destination == 'any':
                        destination_ip = destination
                    else:
                        parts = destination.split()
                        destination_ip = parts[0]
                        destination_wildcard = parts[1] if len(parts) > 1 else None
                        destination = destination_ip

                    # Handle protocol-specific options
                    protocol_option = None
                    destination_port = None
                    source_port = None
                    
                    if protocol == 'icmp' and port_or_type:
                        protocol_option = 'echo' if port_or_type == 'echo' else port_or_type
                    else:
                        destination_port = port_or_type

                    acl_entry = AclEntry(
                        sequence=sequence,
                        action=action,
                        protocol=protocol,
                        source=source,
                        destination=destination,
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        source_port=source_port,
                        destination_port=destination_port,
                        source_wildcard=source_wildcard,
                        destination_wildcard=destination_wildcard,
                        protocol_option=protocol_option,
                        log='log' in entry.text,
                        flags={}
                    )
                    acl.entries.append(acl_entry)
                acls[acl_name] = acl
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
                    route_maps[map_name] = RouteMap(name=map_name)

                current_map = route_maps[map_name]
                current_entry = RouteMapEntry(
                    sequence=int(seq),
                    action=action
                )
                current_map.entries.append(current_entry)

                # Process match and set statements
                for child in line.children:
                    text = child.text.strip()
                    if text.startswith('description'):
                        current_entry.description = text.split('description', 1)[1].strip().strip('"')
                    elif text.startswith('match '):
                        parts = text.split(maxsplit=2)  # Split into ['match', condition, value]
                        if len(parts) >= 3:
                            condition = parts[1]
                            value = parts[2]
                            # Special handling for 'ip address'
                            if condition == 'ip' and value.startswith('address'):
                                condition = 'ip address'
                                value = value[8:].strip()  # Remove 'address ' from value
                            
                            if condition not in current_entry.match_conditions:
                                current_entry.match_conditions[condition] = []
                            
                            # Split value into individual parts
                            value_parts = value.split()
                            current_entry.match_conditions[condition].extend(value_parts)
                            # For backward compatibility
                            current_entry.match_statements[condition] = current_entry.match_conditions[condition]
                    elif text.startswith('set '):
                        parts = text.split(maxsplit=2)  # Split into ['set', action, value]
                        if len(parts) >= 3:
                            action = parts[1]
                            value = parts[2]

                            if action not in current_entry.set_actions:
                                current_entry.set_actions[action] = []
                            
                            # Special handling for as-path and community
                            if action in ['as-path', 'community']:
                                value_parts = value.split()
                                current_entry.set_actions[action].extend(value_parts)
                            else:
                                current_entry.set_actions[action].append(value)
                            
                            # For backward compatibility
                            current_entry.set_statements[action] = current_entry.set_actions[action]

        return route_maps

    def _parse_bgp_neighbor(self, line_text: str, neighbor_lines: Optional[List[str]] = None) -> Optional[BgpNeighbor]:
        """Parse BGP neighbor configuration."""
        match = re.match(r'\s*neighbor\s+(\S+)\s+remote-as\s+(\d+)', line_text)
        if not match:
            return None

        address, remote_as = match.groups()
        route_maps = {'in': '', 'out': ''}

        if neighbor_lines:
            for line in neighbor_lines:
                if isinstance(line, str):
                    line_text = line
                else:
                    line_text = line.text
                if 'route-map' in line_text:
                    rm_match = re.match(r'\s*neighbor\s+\S+\s+route-map\s+(\S+)\s+(in|out)', line_text)
                    if rm_match:
                        map_name, direction = rm_match.groups()
                        route_maps[direction] = map_name

        return BgpNeighbor(
            address=address,
            remote_as=int(remote_as),
            route_maps=route_maps
        )

    def _process_bgp(self, parse: CiscoConfParse) -> Optional[BgpConfig]:
        """Process BGP configuration."""
        bgp_obj = parse.find_objects(r'^router bgp\s+\d+')
        if not bgp_obj:
            return None

        bgp_config = None
        router_id = None
        vrf_configs = {}

        # Get AS number from the router bgp line
        match = re.match(r'^router bgp\s+(\d+)', bgp_obj[0].text)
        if not match:  # If no ASN found, return None
            return None
            
        asn = int(match.group(1))
        bgp_config = BgpConfig(
            asn=asn,
            router_id=router_id,
            vrf_configs=vrf_configs
        )

        # Process BGP configuration
        for line in bgp_obj[0].children:
            line_text = line.text.strip()
            
            if 'router-id' in line_text:
                router_id = line_text.split()[-1]
                bgp_config.router_id = router_id
            elif 'address-family ipv4 vrf' in line_text:
                vrf_name = line_text.split()[-1]
                vrf_config = BgpVrfConfig()  # Create VRF config without name parameter
                neighbor_configs = {}

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

        bgp_config.vrf_configs = vrf_configs
        return bgp_config

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
        """Process NTP configuration."""
        ntp_servers = []
        ntp_objs = parse.find_objects(r'^ntp\s+server\s+\S+')

        for ntp_obj in ntp_objs:
            match = re.match(r'^ntp\s+server\s+(\S+)(?:\s+.*)?$', ntp_obj.text)
            if match:
                server = match.group(1)
                key = None
                prefer = False
                version = None

                # Check for additional parameters in the same line
                if 'key' in ntp_obj.text:
                    key_match = re.search(r'key\s+(\d+)', ntp_obj.text)
                    if key_match:
                        key = str(key_match.group(1))
                if 'prefer' in ntp_obj.text:
                    prefer = True
                if 'version' in ntp_obj.text:
                    version_match = re.search(r'version\s+(\d+)', ntp_obj.text)
                    if version_match:
                        version = int(version_match.group(1))

                ntp_servers.append(NtpServer(
                    server=server,
                    key=key,
                    prefer=prefer,
                    version=version
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
        """Process FEX configuration."""
        fex_configs = {}
        fex_objs = parse.find_objects(r'^fex\s+\d+')

        for fex_obj in fex_objs:
            match = re.match(r'^fex\s+(\d+)', fex_obj.text)
            if match:
                fex_id = str(match.group(1))  # Convert to string
                description = None
                fex_type = None
                serial = None
                max_links = 1

                for child in fex_obj.children:
                    child_text = child.text.strip()
                    if 'description' in child_text:
                        description = child_text.split('description', 1)[1].strip().strip('"')
                    elif 'type' in child_text:
                        fex_type = child_text.split('type', 1)[1].strip().strip('"')
                    elif 'serial' in child_text:
                        serial = child_text.split('serial', 1)[1].strip().strip('"')
                    elif 'pinning max-links' in child_text:
                        match = re.match(r'\s*pinning max-links (\d+)', child_text)
                        if match:
                            max_links = int(match.group(1))

                fex_configs[fex_id] = FexConfig(
                    id=int(fex_id),  # Keep ID as integer in the config
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

    def parse_routing_table(self, routing_table_text: str) -> None:
        """Parse routing table output from 'show ip route detail' and update routes."""
        routes = []
        current_route = None
        current_network = None
        current_protocol = None
        current_attributes = []
        
        # Split the input into lines and process each line
        for line in routing_table_text.splitlines():
            line = line.strip()
            
            # Skip empty lines and header lines
            if not line or 'Codes:' in line or 'Gateway of last resort' in line:
                continue
            
            # Skip VRF table headers
            if line.startswith('Routing Table:'):
                continue
            
            # Check for network line (starts with routing code)
            network_match = re.match(r'^([A-Z*>]+(?:\s+[A-Z*>]+)*)\s+(\d+\.\d+\.\d+\.\d+/\d+)(?:\s+\[(\d+)/(\d+)\])?(?:\s+via\s+(\d+\.\d+\.\d+\.\d+|\S+))?(?:,\s+([^,]+))?,?\s*([^,]+)?', line)
            if network_match:
                # If we were processing a route, add it to the list
                if current_route:
                    routes.append(current_route)

                protocol, network, ad, metric, next_hop, age, interface = network_match.groups()
                protocol = protocol.strip()  # Keep full protocol code for now
                current_network = network.strip()
                current_protocol = protocol
                current_attributes = []

                # Handle directly connected routes
                if protocol == 'C':
                    # For connected routes, set admin distance to 0 and metric to 0
                    ad = 0
                    metric = 0
                    # If next_hop exists and it's not an IP, it's actually the interface
                    if next_hop and not re.match(r'\d+\.\d+\.\d+\.\d+', next_hop):
                        interface = next_hop
                        next_hop = None

                # Clean up values
                if age:
                    age = age.strip(' ,')
                if interface:
                    interface = interface.strip(' ,')
                if next_hop:
                    next_hop = next_hop.strip(' ,')

                # Handle OSPF external routes
                if 'E2' in protocol or 'E1' in protocol:
                    base_protocol = 'O'  # Set protocol to OSPF
                else:
                    base_protocol = None
                    # Extract the base protocol (first character that's not * or >)
                    for char in protocol:
                        if char not in ['*', '>']:
                            base_protocol = char
                            break
                    if not base_protocol:
                        base_protocol = protocol[0]

                # Determine if this is a best route
                is_best = ('*' in protocol or '>' in protocol or 
                          protocol in ['C', 'S'] or  # Connected and static are always best
                          'best' in line.lower() or  # Explicit best marking
                          ('O' in protocol and ('*' in protocol or '>' in protocol)))  # OSPF routes with * or > are best

                # Create the route object
                current_route = Route(
                    protocol=base_protocol,
                    network=current_network,
                    next_hop=next_hop,
                    interface=interface,
                    admin_distance=int(ad) if ad else 0,
                    metric=int(metric) if metric else 0,
                    is_best=is_best,
                    source_protocol=None,
                    source_rid=None,
                    tag=None,
                    age=age,
                    attributes=current_attributes
                )

            # Handle descriptor block lines
            elif line.startswith('Routing Descriptor Blocks:'):
                continue
            elif line.startswith('* via'):
                # Parse descriptor block line
                via_match = re.match(r'^\*\s+via\s+(\d+\.\d+\.\d+\.\d+)(?:,\s+(\S+))?(?:,\s+(\S+))?', line)
                if via_match:
                    next_hop, interface, age = via_match.groups()
                    if current_route:
                        # Update the current route instead of creating a new one
                        current_route.next_hop = next_hop
                        if interface:
                            current_route.interface = interface.strip(' ,')
                        if age:
                            current_route.age = age.strip(' ,')
                        current_route.is_best = True  # Routes in descriptor blocks with * are best
            
            # Handle additional path lines (BGP alternate paths)
            elif line.startswith('[') and current_network:
                via_match = re.match(r'^\[(\d+)/(\d+)\]\s+via\s+(\d+\.\d+\.\d+\.\d+)(?:,\s+(\S+))?(?:,\s+(\S+))?', line)
                if via_match:
                    ad, metric, next_hop, interface, age = via_match.groups()
                    
                    # Create a new route for this path
                    alt_route = Route(
                        protocol=current_protocol[0] if current_protocol else 'B',
                        network=current_network,
                        next_hop=next_hop,
                        interface=interface.strip(' ,') if interface else None,
                        admin_distance=int(ad),
                        metric=int(metric),
                        is_best=False,  # Alternate paths are not best by default
                        source_protocol=current_route.source_protocol if current_route else None,
                        source_rid=current_route.source_rid if current_route else None,
                        tag=current_route.tag if current_route else None,
                        age=age.strip(' ,') if age else None,
                        attributes=current_route.attributes.copy() if current_route else []
                    )
                    routes.append(alt_route)

            # Handle source protocol information
            elif line.startswith('from') and current_route:
                from_match = re.match(r'\s*from\s+(\d+\.\d+\.\d+\.\d+)\s+\((\d+\.\d+\.\d+\.\d+)\)', line)
                if from_match:
                    source_rid, source_ip = from_match.groups()
                    current_route.source_rid = source_rid
            
            # Handle route type information for OSPF external routes
            elif 'Route type' in line and current_route:
                type_match = re.match(r'\s*Route type\s+(external\s+type\s+\d+)', line)
                if type_match:
                    route_type = type_match.group(1)
                    current_route.attributes.append(f"Route type is {route_type}")
            
            # Handle tag information
            elif 'tag' in line.lower() and current_route:
                tag_match = re.match(r'\s*Route tag\s+(\d+)', line)
                if tag_match:
                    current_route.tag = int(tag_match.group(1))

            # Handle source protocol information
            elif 'Known via' in line and current_route:
                source_match = re.match(r'\s*Known via "([^"]+)"', line)
                if source_match:
                    current_route.source_protocol = source_match.group(1)
                    if 'best' in line.lower():
                        current_route.is_best = True
            
            # Handle next hop in separate line
            elif line.startswith('via') and current_route:
                via_match = re.match(r'^\s*via\s+(\d+\.\d+\.\d+\.\d+)(?:,\s+(\S+))?(?:,\s+(\S+))?', line)
                if via_match:
                    next_hop, interface, age = via_match.groups()
                    if not current_route.next_hop:  # Only update if not already set
                        current_route.next_hop = next_hop
                    if interface:
                        current_route.interface = interface.strip(' ,')
                    if age:
                        current_route.age = age.strip(' ,')
            
            # Handle age information
            elif line.startswith('Age:') and current_route:
                age_match = re.match(r'Age:\s+(\S+)', line)
                if age_match:
                    current_route.age = age_match.group(1)
                    # Update age in any alternate paths for this network
                    for route in routes:
                        if route.network == current_route.network and not route.age:
                            route.age = age_match.group(1)
            
            # Add any other lines as attributes
            elif line and current_route:
                current_route.attributes.append(line)

        # Add the last route if there is one
        if current_route:
            routes.append(current_route)

        # Ensure BGP paths are properly marked
        bgp_routes = {}
        for route in routes:
            if route.protocol == 'B':
                key = route.network
                if key not in bgp_routes:
                    bgp_routes[key] = []
                bgp_routes[key].append(route)

        for routes_list in bgp_routes.values():
            if len(routes_list) > 1:  # Multiple paths for same network
                # First check for explicit best path markers
                best_route = next((r for r in routes_list if '*' in str(r) or '>' in str(r)), None)
                if not best_route:
                    # If no explicit markers, use the first path with lowest admin distance and metric
                    routes_list.sort(key=lambda r: (r.admin_distance, r.metric))
                    best_route = routes_list[0]
                best_route.is_best = True
                # Ensure other paths are not marked as best
                for route in routes_list:
                    if route != best_route:
                        route.is_best = False

        self._routes = routes

    def __str__(self) -> str:
        """Return string representation of router."""
        return f"CiscoRouter(hostname={self.hostname}, interfaces={len(self._interfaces)})"

    def __repr__(self) -> str:
        """Return string representation of router."""
        return f"CiscoRouter(hostname={self.hostname}, interfaces={len(self._interfaces)})"
