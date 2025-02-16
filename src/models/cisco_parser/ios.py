"""Router configuration parser."""
from functools import cached_property, lru_cache
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, AddressValueError
from typing import Any, Dict, List, Optional, Union
import re
from ciscoconfparse2 import CiscoConfParse

from models.base.core.device import Device
from models.base.interfaces import Interface, VlanConfig, FexConfig
from models.base.policy.acl import Ipv4Acl, Ipv6Acl
from models.base.routing_protocols import (
    BgpConfig, OspfConfig, OspfNetwork,
    BgpVrfConfig, BgpNeighbor, VrfConfig,
    Route
)
from models.base.policy import (
    AclEntry,
    RouteMap, RouteMapEntry,
    PrefixList, PrefixListEntry,
    CommunityList, CommunityListEntry,
    AsPathList, AsPathEntry,
)
from models.base.routing_protocols.vrf import VrfRouteTarget
from models.base.system import (
    AaaConfig,
    LoggingConfig,
    NtpServer,
    SnmpConfig,
)


class CiscoIOS(Device):
    """Model for Cisco router."""
    def __init__(self, config: Optional[str] = None, hostname: Optional[str] = None, rib: Optional[str] = None):
        """Initialize CiscoIOS."""
        self.rib: Optional[str] = rib
        self.routes: List[Route] = []
        self.interfaces: Dict[str, Interface] = {}
        self.vrfs: Dict[str, VrfConfig] = {}
        self.vlans: Dict[str, VlanConfig] = {}
        # if routing_table:
        #     self.parse_routing_table(routing_table)
        super().__init__(config, hostname)
    
    @cached_property
    def parse(self) -> Optional[CiscoConfParse]:
        if self.config:
            return CiscoConfParse(self.config.splitlines(), syntax='ios')
        return None

    def parse_config(self) -> None:
        """Parse configuration text."""
        # Process each section
        self._hostname = self._parse_hostname()
        self.interfaces = self._parse_interfaces()
        self.vrfs = self._parse_vrfs()
        self.vlans = self._parse_vlans()
        self.bgp = self._parse_bgp()
        self.ospf = self._parse_ospf()
        self.acls = self._parse_acls()
        self.route_maps = self._parse_route_maps()
        self.prefix_lists = self._parse_prefix_lists()
        self.community_lists = self._parse_community_lists()
        self.as_path_lists = self._parse_as_path_lists()

    @cached_property
    def interface_list(self) -> List[Interface]:
        """Return a list of all interfaces configured on the device."""
        return list(self.interfaces.values())
    
    @cached_property
    def vrf_list(self) -> List[VrfConfig]:
        """Return a list of all VRFs configured on the device."""
        return list(self.vrfs.values())

    # def get_routes(self) -> Dict[str, Route]:
    #     """Get all routes."""
    #     result = {}
    #     # Sort routes by network and is_best flag
    #     sorted_routes = sorted(self._routes, key=lambda r: (r.network, not r.is_best))
    #     for route in sorted_routes:
    #         # Only update if we don't have this network yet or if this is the best route
    #         if route.network not in result or route.is_best:
    #             result[route.network] = route
    #         # If this route has better metrics, mark it as best and update
    #         elif (route.admin_distance is not None and result[route.network].admin_distance is not None and
    #               (route.admin_distance < result[route.network].admin_distance or
    #                (route.admin_distance == result[route.network].admin_distance and
    #                 route.metric is not None and result[route.network].metric is not None and
    #                 route.metric < result[route.network].metric))):
    #             result[route.network] = route
    #             route.is_best = True
    #     return result

    # def get_best_routes(self) -> Dict[str, Route]:
    #     """Get best routes."""
    #     result = {}
    #     # First pass: collect all routes and mark best ones
    #     for route in self._routes:
    #         if route.network not in result:
    #             result[route.network] = route
    #             route.is_best = True
    #         elif route.is_best:
    #             result[route.network] = route
    #         elif (route.admin_distance is not None and result[route.network].admin_distance is not None and
    #               (route.admin_distance < result[route.network].admin_distance or
    #                (route.admin_distance == result[route.network].admin_distance and
    #                 route.metric is not None and result[route.network].metric is not None and
    #                 route.metric < result[route.network].metric))):
    #             result[route.network] = route
    #             route.is_best = True
                
    #     # Second pass: ensure we only return routes marked as best
    #     return {k: v for k, v in result.items() if v.is_best}

    # def get_routes_by_vrf(self, vrf: str) -> List[Route]:
    #     """Get all routes in a specific VRF."""
    #     return [route for route in self._routes if route.vrf == vrf]

    # def get_routes_by_protocol(self, protocol: str) -> List[Route]:
    #     """Get routes by protocol."""
    #     return [r for r in self._routes if r.protocol == protocol]

    # def get_routes_by_network(self, network: str) -> List[Route]:
    #     """Get routes by network."""
    #     return [r for r in self._routes if r.network == network]

    # def parse_routing_table(self, routing_table: str) -> None:
    #     """Parse routing table output."""
    #     if not routing_table:
    #         return

    #     current_vrf = 'default'
    #     current_route = None
    #     routes = []
    #     route_info_buffer = []

    #     for line in routing_table.splitlines():
    #         line = line.strip()
    #         if not line:
    #             continue

    #         # Check for VRF header
    #         vrf_match = re.match(r'Routing Table: VRF (\S+)', line)
    #         if vrf_match:
    #             current_vrf = vrf_match.group(1)
    #             continue

    #         # Skip header lines
    #         if any(x in line for x in ['Codes:', 'Gateway', '-']):
    #             continue

    #         # If line starts with a space, it's additional information for the current route
    #         if line.startswith(' '):
    #             route_info_buffer.append(line)
    #             continue

    #         # Process any buffered route information
    #         if current_route and route_info_buffer:
    #             for info_line in route_info_buffer:
    #                 if 'Known via' in info_line:
    #                     known_via_match = re.search(r'Known via "([^"]+)"', info_line)
    #                     if known_via_match:
    #                         current_route.source_protocol = known_via_match.group(1)
    #                     rid_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', info_line)
    #                     if rid_match:
    #                         current_route.source_rid = rid_match.group(1)
    #                 elif 'tag' in info_line:
    #                     tag_match = re.search(r'tag (\d+)', info_line)
    #                     if tag_match:
    #                         current_route.tag = int(tag_match.group(1))
    #                 elif any(x in info_line for x in ['external', 'candidate', 'mpls-vpn']):
    #                     if 'external' in info_line and 'external' not in current_route.attributes:
    #                         current_route.attributes.append('external')
    #                     if 'candidate' in info_line and 'candidate' not in current_route.attributes:
    #                         current_route.attributes.append('candidate')
    #                     if 'mpls-vpn' in info_line and 'mpls-vpn' not in current_route.attributes:
    #                         current_route.attributes.append('mpls-vpn')

    #         # Try to parse as a new route
    #         route = self._parse_route_line(line, current_vrf)
    #         if route:
    #             if current_route:
    #                 routes.append(current_route)
    #             current_route = route
    #             route_info_buffer = []
    #             continue

    #         # If line contains "via", it's an additional path for the current route
    #         if current_route and 'via' in line:
    #             next_hop_match = re.search(r'via\s+(\S+)', line)
    #             if next_hop_match:
    #                 new_route = current_route.copy()
    #                 new_route.next_hop = next_hop_match.group(1).rstrip(',')
    #                 new_route.is_best = '*' in line or '>' in line
    #                 if new_route.is_best:
    #                     new_route.attributes.append('best')
    #                 routes.append(new_route)

    #     # Add the last route and process its buffered information
    #     if current_route:
    #         if route_info_buffer:
    #             for info_line in route_info_buffer:
    #                 if 'Known via' in info_line:
    #                     known_via_match = re.search(r'Known via "([^"]+)"', info_line)
    #                     if known_via_match:
    #                         current_route.source_protocol = known_via_match.group(1)
    #                     rid_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', info_line)
    #                     if rid_match:
    #                         current_route.source_rid = rid_match.group(1)
    #                 elif 'tag' in info_line:
    #                     tag_match = re.search(r'tag (\d+)', info_line)
    #                     if tag_match:
    #                         current_route.tag = int(tag_match.group(1))
    #                 elif any(x in info_line for x in ['external', 'candidate', 'mpls-vpn']):
    #                     if 'external' in info_line and 'external' not in current_route.attributes:
    #                         current_route.attributes.append('external')
    #                     if 'candidate' in info_line and 'candidate' not in current_route.attributes:
    #                         current_route.attributes.append('candidate')
    #                     if 'mpls-vpn' in info_line and 'mpls-vpn' not in current_route.attributes:
    #                         current_route.attributes.append('mpls-vpn')
    #         routes.append(current_route)

    #     self._routes.extend(routes)

    @lru_cache
    def _parse_hostname(self) -> Optional[str]:
        """Get hostname from configuration."""
        hostname_obj = self.parse.find_objects(r'^hostname\s+(\S+)$')
        if hostname_obj:
            return hostname_obj[0].text.split(None, 1)[1]
        return self.hostname

    @lru_cache
    def _parse_interfaces(self) -> Dict[str, Interface]:
        """Process interface configuration."""
        interfaces = {}
        interface_objs = self.parse.find_objects(r'^interface\s+\S+')

        for interface_obj in interface_objs:
            match = re.match(r'^interface\s+(\S+(?:\s+\S+)?)', interface_obj.text)  # Handle spaces in interface names
            if match:
                name = match.group(1)
                description = None
                ip = None
                vrf = None
                shutdown = False
                speed = None
                duplex = None
                access_groups = {}
                switchport_mode = None
                vlan = None
                allowed_vlans = []
                fex_associate = None

                for child in interface_obj.children:
                    child_text = child.text.strip()
                    if 'description' in child_text:
                        description = child_text.split('description', 1)[1].strip()
                    elif 'ip address' in child_text:
                        ip_match = re.match(r'\s*ip address\s+(\S+)\s+(\S+)', child_text)
                        if ip_match:
                            try:
                                ip_address = IPv4Address(ip_match.group(1))
                                subnet_mask = ip_match.group(2)
                                ip_network = IPv4Network(f"{ip_match.group(1)}/{ip_match.group(2)}", strict=False)
                            except AddressValueError:
                                ip_address = IPv6Address(ip_match.group(1).split('/')[0])
                                subnet_mask = ip_match.group(1).split('/')[1]
                                ip_network = IPv6Network(f"{ip_match.group(1)}")
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
                            for v in vlan_match.group(1).strip().split(','):
                                if '-' in v:
                                    start, end = v.split('-')
                                    allowed_vlans.extend(list(map(str, range(int(start), int(end) + 1))))
                                else:
                                    allowed_vlans.append(v)
                    elif 'fex associate' in child_text:
                        fex_match = re.match(r'\s*fex associate\s+(\d+)', child_text)
                        if fex_match:
                            fex_associate = int(fex_match.group(1))

                interfaces[name] = Interface(
                    name=name,
                    description=description,
                    ip_network=ip_network,
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

    @lru_cache
    def _parse_vrfs(self) -> Dict[str, VrfConfig]:
        """Process VRF configuration."""
        interfaces = self._parse_interfaces()
        vrfs = {}
        vrf_objs = self.parse.find_objects(r'^(?:vrf\s+definition|ip\s+vrf)\s+\S+')

        # First pass: collect VRF configurations
        for vrf_obj in vrf_objs:
            match = re.match(r'^(?:vrf\s+definition|ip\s+vrf)\s+(\S+)', vrf_obj.text)
            if match:
                name = match.group(1)
                description = None
                rd = None
                route_targets = []

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
                            if direction == 'import':
                                route_targets.append(VrfRouteTarget(import_targets=[target]))
                            elif direction == 'export':
                                route_targets.append(VrfRouteTarget(export_targets=[target]))

                vrfs[name] = VrfConfig(
                    name=name,
                    description=description,
                    rd=rd,
                    route_targets=route_targets,
                    interfaces=[]  # Initialize empty list for interfaces
                )

        # Second pass: associate interfaces with VRFs
        for interface in interfaces.values():
            if interface.vrf and interface.vrf in vrfs:
                vrfs[interface.vrf].interfaces.append(interface.name)

        return vrfs

    @lru_cache
    def _parse_vlans(self) -> Dict[str, VlanConfig]:
        """Process VLAN information."""
        interfaces = self._parse_interfaces()
        vlans = {}
        for vlan in self.parse.find_objects(r'^vlan\s+\d+'):
            vlan_id = vlan.text.split()[1]
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
                vlan_id=int(vlan_id),
                name=name,
                state=state
            )

        for interface in interfaces.values():
            for vlan in vlans:
                if interface.vlan == vlan:
                    vlans[vlan].interfaces.append(interface.name)
                elif vlan in interface.allowed_vlans:
                    vlans[vlan].interfaces.append(interface.name)

        return vlans

    @lru_cache
    def _parse_acls(self) -> Dict[str, Union[Ipv4Acl, Ipv6Acl]]:
        """Process ACLs from configuration."""
        acls = {}
        current_acl = None

        for line in self.parse.find_objects(r'^ip access-list'):
            parts = line.text.split()
            acl_type = parts[2]  # standard or extended
            name = parts[3]

            current_acl = Ipv4Acl(name=name, type=acl_type)
            acls[name] = current_acl

            # Process ACL entries
            for entry in line.children:
                entry_text = entry.text.strip()
                if not entry_text:
                    continue

                parts = entry_text.split()
                sequence = int(parts[0]) if parts[0].isdigit() else len(current_acl.entries) * 10 + 10
                action = parts[1] if parts[0].isdigit() else parts[0]
                protocol = parts[2] if parts[0].isdigit() else parts[1]

                # Parse source and destination
                idx = 3 if parts[0].isdigit() else 2
                source = parts[idx]
                source_wildcard = parts[idx + 1] if len(parts) > idx + 1 and not parts[idx + 1].startswith('eq') else None
                
                # Handle destination
                dest_idx = idx + (2 if source_wildcard else 1)
                destination = parts[dest_idx] if len(parts) > dest_idx else 'any'
                dest_wildcard = parts[dest_idx + 1] if len(parts) > dest_idx + 1 and not parts[dest_idx + 1].startswith('eq') else None

                # Handle ports
                source_port = None
                destination_port = None
                remaining_parts = parts[dest_idx + (2 if dest_wildcard else 1):]
                
                for i, part in enumerate(remaining_parts):
                    if part == 'eq' and i + 1 < len(remaining_parts):
                        if source_port is None:
                            source_port = remaining_parts[i + 1]
                        else:
                            destination_port = remaining_parts[i + 1]

                # Create ACL entry
                entry = AclEntry(
                    sequence=sequence,
                    action=action,
                    protocol=protocol,
                    source=source,
                    source_wildcard=source_wildcard,
                    destination=destination,
                    destination_wildcard=dest_wildcard,
                    source_port=source_port,
                    destination_port=destination_port,
                    log='log' in entry_text
                )
                current_acl.entries[str(sequence)] = entry

        return acls

    @lru_cache
    def _parse_prefix_lists(self) -> Dict[str, PrefixList]:
        """Process prefix lists from configuration."""
        prefix_lists = {}

        for line in self.parse.find_objects(r'^ip prefix-list'):
            # Extract name and create prefix list if it doesn't exist
            parts = line.text.split()
            name = parts[2]
            if name not in prefix_lists:
                prefix_lists[name] = PrefixList(name=name)

            # Parse the rest of the line
            if 'seq' in line.text:
                # Format: ip prefix-list NAME seq NUM permit/deny PREFIX [ge/le NUM]
                seq_idx = parts.index('seq')
                sequence = int(parts[seq_idx + 1])
                action = parts[seq_idx + 2]
                prefix = parts[seq_idx + 3]
                remaining = parts[seq_idx + 4:]
            else:
                # Format: ip prefix-list NAME permit/deny PREFIX [ge/le NUM]
                sequence = len(prefix_lists[name].entries) * 5 + 5
                action = parts[3]
                prefix = parts[4]
                remaining = parts[5:]

            # Parse ge/le values if present
            ge = le = None
            if remaining:
                for i in range(0, len(remaining), 2):
                    if i + 1 < len(remaining):
                        if remaining[i] == 'ge':
                            ge = int(remaining[i + 1])
                        elif remaining[i] == 'le':
                            le = int(remaining[i + 1])

            # Create and add the entry
            entry = PrefixListEntry(
                sequence=sequence,
                action=action,
                prefix=prefix,
                ge=ge,
                le=le
            )
            prefix_lists[name].entries[sequence] = entry

        return prefix_lists

    @lru_cache
    def _parse_route_maps(self) -> Dict[str, RouteMap]:
        """Process route maps from configuration."""
        route_maps = {}

        for line in self.parse.find_objects(r'^route-map'):
            parts = line.text.split()
            name = parts[1]
            action = parts[2]
            sequence = int(parts[3]) if len(parts) > 3 else 10

            if name not in route_maps:
                route_maps[name] = RouteMap(name=name)

            # Create route map entry
            entry = RouteMapEntry(
                sequence=sequence,
                action=action
            )
            route_maps[name].entries[str(sequence)] = entry

            # Process set and match statements
            for child in line.children:
                child_text = child.text.strip()
                if child_text.startswith('match'):
                    parts = child_text.split()
                    match_type = parts[1]
                    match_value = ' '.join(parts[2:])
                    entry.match[match_type] = match_value
                elif child_text.startswith('set'):
                    parts = child_text.split()
                    set_type = parts[1]
                    set_value = ' '.join(parts[2:])
                    entry.set[set_type] = set_value

        return route_maps

    @cached_property
    def bgp_neighbors(self) -> Optional[List[BgpNeighbor]]:
        """Parse BGP neighbor configuration."""
        bgp_neighbors = [neighbor for vrf in self.bgp.vrf_configs.values() for neighbor in vrf.neighbors.values()]
        bgp_neighbors.extend(self.bgp.neighbors.values())

        return bgp_neighbors

    @lru_cache
    def _parse_bgp(self) -> BgpConfig | None:
        """Process BGP configuration."""
        router_id = None
        vrf_configs = {}
        neighbors = {}
        networks = {}
        redistribute = []

        bgp_obj = self.parse.find_objects(r'^router bgp')
        if not bgp_obj:
            return None

        # Get AS number from the router bgp line
        match = re.match(r'^router bgp\s+(\d+)', bgp_obj[0].text)

        asn = int(match.group(1))
        bgp_config = BgpConfig(
            asn=asn,
            router_id=router_id,
            vrf_configs=vrf_configs,
            neighbors=neighbors,  # Added
            networks=networks,    # Added
            redistribute=redistribute  # Added
        )

        current_vrf = None
        current_vrf_config = None

        # Process BGP configuration
        for line in bgp_obj[0].children:
            line_text = line.text.strip()
            
            if 'router-id' in line_text:
                router_id = line_text.split()[-1]
                bgp_config.router_id = router_id
            elif 'address-family ipv4 vrf' in line_text:
                current_vrf = line_text.split()[-1]
                current_vrf_config = BgpVrfConfig(
                    vrf=current_vrf,
                    neighbors={},
                    redistribute=[],
                    networks={}
                )
                for sub_line in line.children:
                    sub_line_text = sub_line.text.strip()
                    if 'redistribute' in sub_line_text:
                        protocol = sub_line_text.split()[1]
                        if protocol not in current_vrf_config.redistribute:
                            current_vrf_config.redistribute.append(protocol)
                    elif 'network' in sub_line_text:
                        network = sub_line_text.split()[1]
                        mask = sub_line_text.split()[-1]
                        current_vrf_config.networks[network] = IPv4Network(f'{network}/{mask}')
                    elif 'neighbor' in sub_line_text:
                        neighbor_match = re.match(r'\s*neighbor\s+(\S+)\s+remote-as\s+(\d+)', sub_line_text)
                        if neighbor_match:
                            neighbor_ip = neighbor_match.group(1)
                            remote_as = int(neighbor_match.group(2))
                            if neighbor_ip not in current_vrf_config.neighbors:
                                current_vrf_config.neighbors[neighbor_ip] = BgpNeighbor(
                                    peer=neighbor_ip,
                                    remote_as=remote_as,
                                    description=None,
                                    route_maps={},
                                    vrf=current_vrf
                                )
                        if 'route-map' in sub_line_text:
                            route_map_match = re.match(r'\s*neighbor\s+\S+\s+route-map\s+(\S+)\s+(in|out)', sub_line_text)
                            if route_map_match:
                                route_map_name = route_map_match.group(1)
                                direction = route_map_match.group(2)
                                if route_map_name not in current_vrf_config.neighbors[neighbor_ip].route_maps:
                                    current_vrf_config.neighbors[neighbor_ip].route_maps[direction] = route_map_name
                    elif 'maximum-paths' in sub_line_text:
                        max_paths = int(sub_line_text.split()[-1])
                        current_vrf_config.maximum_paths = max_paths
                vrf_configs[current_vrf] = current_vrf_config
            elif 'neighbor' in line_text:
                neighbor_match = re.match(r'\s*neighbor\s+(\S+)\s+remote-as\s+(\d+)', line_text)
                if neighbor_match:
                    neighbor_ip = neighbor_match.group(1)
                    remote_as = int(neighbor_match.group(2))
                    if neighbor_ip not in neighbors:
                        neighbors[neighbor_ip] = BgpNeighbor(
                            peer=neighbor_ip,
                            remote_as=remote_as,
                            description=None,
                            route_maps={}
                        )
                elif 'route-map' in line_text:
                    route_map_match = re.match(r'\s*neighbor\s+\S+\s+route-map\s+(\S+)\s+(in|out)', line_text)
                    if route_map_match:
                        route_map_name = route_map_match.group(1)
                        direction = route_map_match.group(2)
                        if route_map_name in route_maps:
                            neighbors[neighbor_ip]['route_maps'][direction] = route_maps[route_map_name]
            elif line_text.startswith('network'):
                network = line_text.split()[1]
                if current_vrf_config:
                    current_vrf_config.networks[network] = network
                else:
                    networks[network] = network
            elif line_text.startswith('redistribute'):
                protocol = line_text.split()[1]
                if current_vrf_config and protocol not in current_vrf_config.redistribute:
                    current_vrf_config.redistribute.append(protocol)
                elif protocol not in redistribute:
                    redistribute.append(protocol)

        bgp_config.vrf_configs = vrf_configs
        return bgp_config

    @lru_cache
    def _parse_ospf(self) -> Dict[str, OspfConfig]:
        """Process OSPF information."""
        ospf_configs = {}
        for ospf in self.parse.find_objects(r'^router ospf'):
            process_id = int(ospf.text.split()[-1])
            router_id = None
            reference_bandwidth = None
            networks = []
            passive_interfaces = set()
            area_auth = {}

            for line in ospf.children:
                line_text = line.text.strip()
                if 'router-id' in line_text:
                    match = re.match(r'\s*router-id (\S+)', line_text)
                    if match:
                        router_id = match.group(1)
                elif 'auto-cost reference-bandwidth' in line_text:
                    match = re.match(r'\s*auto-cost\s+reference-bandwidth\s+(\d+)', line_text)
                    if match:
                        reference_bandwidth = int(match.group(1))
                elif 'network' in line_text:
                    match = re.match(r'\s*network\s+(\S+)\s+(\S+)\s+area\s+(\S+)', line_text)
                    if match:
                        network, wildcard, area = match.groups()
                        try:
                            area_val = int(area)  # Keep as integer for networks
                        except ValueError:
                            area_val = area
                        networks.append(OspfNetwork(
                            network=network,
                            wildcard=wildcard,
                            area=area_val
                        ))
                elif 'passive-interface' in line_text:
                    if 'default' in line_text:
                        passive_interfaces.add('default')
                    else:
                        match = re.match(r'\s*passive-interface\s+(\S+)', line_text)
                        if match:
                            interface = match.group(1)
                            passive_interfaces.add(interface)
                elif 'area' in line_text and 'authentication' in line_text:
                    match = re.match(r'\s*area\s+(\S+)\s+authentication(\s+message-digest)?', line_text)
                    if match:
                        area = match.group(1)
                        auth_type = "message-digest" if match.group(2) else "enabled"
                        area_auth[area] = auth_type
                elif 'default-information' in line_text:
                    match = re.match(r'\s*default-information\s+originate\s+always\s+metric\s+(\d+)', line_text)
                    if match:
                        metric = int(match.group(1))
                        for network in networks:
                            network.metric = metric

            ospf_configs[str(process_id)] = OspfConfig(
                instance_tag=process_id,
                router_id=router_id,
                reference_bandwidth=reference_bandwidth,
                networks=networks,
                passive_interfaces=list(passive_interfaces),
                area_auth=area_auth
            )

        return ospf_configs

    @lru_cache
    def _parse_community_lists(self) -> Dict[str, CommunityList]:
        """Process community lists."""
        community_lists: Dict[str, CommunityList] = {}

        # Find all community list lines
        for line in self.parse.find_objects(r'^ip community-list'):
            # Parse the line
            match = re.match(r'^ip community-list\s+(?:(standard|expanded))?\s*(\S+)\s+(permit|deny)\s+(.+)$', line.text)
            if match:
                list_type, name, action, communities = match.groups()
                list_type = list_type or 'standard'  # Default to standard if not specified

                # Create community list if it doesn't exist
                if name not in community_lists:
                    community_lists[name] = CommunityList(name=name, type=list_type, entries={})

                # Create entry
                sequence = (len(community_lists[name].entries) + 1) * 10
                entry = CommunityListEntry(
                    sequence=sequence,
                    action=action,
                    communities=communities.strip()
                )

                # Add entry to community list
                community_lists[name].entries[sequence] = entry

        return community_lists

    @lru_cache
    def _parse_as_path_lists(self) -> Dict[str, AsPathList]:
        """Process AS path access lists."""
        as_path_lists: Dict[str, AsPathList] = {}

        # Find all AS path access list lines
        for line in self.parse.find_objects(r'^ip as-path access-list'):
            # Parse the line
            match = re.match(r'^ip as-path access-list\s+(\S+)\s+(permit|deny)\s+(.+)$', line.text)
            if match:
                name, action, pattern = match.groups()

                # Create AS path list if it doesn't exist
                if name not in as_path_lists:
                    as_path_lists[name] = AsPathList(name=name, entries={})

                # Create entry
                sequence = (len(as_path_lists[name].entries) + 1) * 10
                entry = AsPathEntry(
                    sequence=sequence,
                    action=action,
                    pattern=pattern.strip()
                )

                # Add entry to AS path list
                as_path_lists[name].entries[sequence] = entry

        return as_path_lists

    def get_vrf(self, name: str) -> Optional[VrfConfig]:
        """Get VRF configuration by name."""
        return self.vrfs.get(name)

    def get_interface(self, name: str) -> Optional[Interface]:
        """Get interface configuration by name."""
        return self.interfaces.get(name)

    def get_vlan(self, vlan_id: int) -> Optional[VlanConfig]:
        """Get VLAN configuration by ID."""
        return self.vlans.get(vlan_id)

    # def get_fex(self, fex_id: Union[str, int]) -> Optional[FexConfig]:
    #     """Get FEX configuration by ID."""
    #     if isinstance(fex_id, int):
    #         fex_id = str(fex_id)
    #     # return self.fex_units.get(fex_id) if self.config and hasattr(self.config, 'fex') else None

    # def _parse_route_line(self, line: str, vrf: str = 'default') -> Optional[Route]:
    #     """Parse a single route line."""
    #     # Skip empty lines and header lines
    #     if not line or any(x in line for x in ['Codes:', 'Gateway', '-']):
    #         return None

    #     # Handle directly connected routes
    #     if 'is directly connected' in line:
    #         match = re.match(r'^([A-Z])\s+(\S+)', line)
    #         if match:
    #             protocol, network = match.groups()
    #             interface_match = re.search(r'connected,\s+(\S+)', line)
    #             interface = interface_match.group(1) if interface_match else None
    #             return Route(
    #                 protocol=protocol,
    #                 network=network,
    #                 next_hop=interface,
    #                 interface=interface,
    #                 admin_distance=0,
    #                 metric=0,
    #                 is_best=True,
    #                 source_protocol=None,
    #                 source_rid=None,
    #                 tag=None,
    #                 age=None,
    #                 attributes=['best'],
    #                 vrf=vrf
    #             )

    #     # Extract protocol and network
    #     match = re.match(r'^(?P<best>[*>])?(?P<protocol>[A-Za-z]+)?\s+(?P<network>\S+)(?:\s+\[(?P<ad>\d+)/(?P<metric>\d+)\])?(?:\s+via\s+(?P<next_hop>\S+))?(?:,\s+(?P<age>\d+:\d+:\d+|\d+\w+))?(?:,\s+(?P<interface>\S+))?', line)
    #     if not match:
    #         return None

    #     groups = match.groupdict()
    #     protocol = groups.get('protocol', '').strip()
    #     network = groups.get('network', '').strip()
    #     next_hop = groups.get('next_hop', '').rstrip(',') if groups.get('next_hop') else None
    #     interface = groups.get('interface') if groups.get('interface') and not groups.get('interface').startswith('[') else None
    #     age = groups.get('age')

    #     # Skip if we don't have a valid network
    #     if not network or network == 'via' or '-' in network:
    #         return None

    #     # Extract admin distance and metric
    #     admin_distance = int(groups['ad']) if groups.get('ad') else 0
    #     metric = int(groups['metric']) if groups.get('metric') else 0

    #     # Extract source protocol and router ID from the next line if available
    #     source_protocol = None
    #     source_rid = None
    #     if 'Known via' in line:
    #         known_via_match = re.search(r'Known via "([^"]+)"', line)
    #         if known_via_match:
    #             source_protocol = known_via_match.group(1)

    #         rid_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
    #         if rid_match:
    #             source_rid = rid_match.group(1)

    #     # Extract tag if present
    #     tag_match = re.search(r'tag (\d+)', line)
    #     tag = int(tag_match.group(1)) if tag_match else None

    #     # Build attributes list
    #     attributes = []
    #     if groups.get('best') or '*' in line or '>' in line:
    #         attributes.append('best')
    #     if 'candidate' in line:
    #         attributes.append('candidate')
    #     if 'external' in line:
    #         attributes.append('external')
    #     if 'mpls-vpn' in line:
    #         attributes.append('mpls-vpn')

    #     return Route(
    #         protocol=protocol,
    #         network=network,
    #         next_hop=next_hop,
    #         interface=interface,
    #         admin_distance=admin_distance,
    #         metric=metric,
    #         is_best=bool(groups.get('best') or '*' in line or '>' in line),
    #         source_protocol=source_protocol,
    #         source_rid=source_rid,
    #         tag=tag,
    #         age=age,
    #         attributes=attributes,
    #         vrf=vrf
    #     )

    # def parse_routing_table(self, routing_table: str) -> None:
    #     """Parse the routing table output."""
    #     if not routing_table:
    #         return

    #     current_vrf = 'default'
    #     current_route = None
    #     routes = []
    #     route_info_buffer = []

    #     for line in routing_table.splitlines():
    #         line = line.strip()
            
    #         # Check for VRF header
    #         vrf_match = re.match(r'Routing Table: VRF (\S+)', line)
    #         if vrf_match:
    #             current_vrf = vrf_match.group(1)
    #             continue

    #         # Skip header lines
    #         if any(x in line for x in ['Codes:', 'Gateway', '-']):
    #             continue

    #         # If line starts with a space, it's additional information for the current route
    #         if line.startswith(' '):
    #             route_info_buffer.append(line)
    #             continue

    #         # Process any buffered route information
    #         if current_route and route_info_buffer:
    #             for info_line in route_info_buffer:
    #                 if 'Known via' in info_line:
    #                     known_via_match = re.search(r'Known via "([^"]+)"', info_line)
    #                     if known_via_match:
    #                         current_route.source_protocol = known_via_match.group(1)
    #                     rid_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', info_line)
    #                     if rid_match:
    #                         current_route.source_rid = rid_match.group(1)
    #                 elif 'tag' in info_line:
    #                     tag_match = re.search(r'tag (\d+)', info_line)
    #                     if tag_match:
    #                         current_route.tag = int(tag_match.group(1))
    #                 elif any(x in info_line for x in ['external', 'candidate', 'mpls-vpn']):
    #                     if 'external' in info_line and 'external' not in current_route.attributes:
    #                         current_route.attributes.append('external')
    #                     if 'candidate' in info_line and 'candidate' not in current_route.attributes:
    #                         current_route.attributes.append('candidate')
    #                     if 'mpls-vpn' in info_line and 'mpls-vpn' not in current_route.attributes:
    #                         current_route.attributes.append('mpls-vpn')

    #         # Try to parse as a new route
    #         route = self._parse_route_line(line, current_vrf)
    #         if route:
    #             if current_route:
    #                 routes.append(current_route)
    #             current_route = route
    #             route_info_buffer = []
    #             continue

    #         # If line contains "via", it's an additional path for the current route
    #         if current_route and 'via' in line:
    #             next_hop_match = re.search(r'via\s+(\S+)', line)
    #             if next_hop_match:
    #                 new_route = current_route.copy()
    #                 new_route.next_hop = next_hop_match.group(1).rstrip(',')
    #                 new_route.is_best = '*' in line or '>' in line
    #                 if new_route.is_best:
    #                     new_route.attributes.append('best')
    #                 routes.append(new_route)

    #     # Add the last route and process its buffered information
    #     if current_route:
    #         if route_info_buffer:
    #             for info_line in route_info_buffer:
    #                 if 'Known via' in info_line:
    #                     known_via_match = re.search(r'Known via "([^"]+)"', info_line)
    #                     if known_via_match:
    #                         current_route.source_protocol = known_via_match.group(1)
    #                     rid_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', info_line)
    #                     if rid_match:
    #                         current_route.source_rid = rid_match.group(1)
    #                 elif 'tag' in info_line:
    #                     tag_match = re.search(r'tag (\d+)', info_line)
    #                     if tag_match:
    #                         current_route.tag = int(tag_match.group(1))
    #                 elif any(x in info_line for x in ['external', 'candidate', 'mpls-vpn']):
    #                     if 'external' in info_line and 'external' not in current_route.attributes:
    #                         current_route.attributes.append('external')
    #                     if 'candidate' in info_line and 'candidate' not in current_route.attributes:
    #                         current_route.attributes.append('candidate')
    #                     if 'mpls-vpn' in info_line and 'mpls-vpn' not in current_route.attributes:
    #                         current_route.attributes.append('mpls-vpn')
    #         routes.append(current_route)

    #     self._routes.extend(routes)
