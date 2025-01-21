"""Cisco Nexus parser."""
from functools import cached_property, lru_cache
from ipaddress import AddressValueError, IPv4Address, IPv4Network, IPv6Address, IPv6Network, NetmaskValueError
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import re
import logging
from ciscoconfparse2 import CiscoConfParse

from models.base.core.device import Device
from models.base.interfaces import Interface, VlanConfig, FexConfig
from models.base.policy.acl import Ipv4Acl, Ipv6Acl
from models.base.routing_protocols import (
    BgpConfig, OspfConfig, OspfNetwork,
    BgpVrfConfig, BgpNeighbor, VrfConfig,
    Route, RoutingTable
)
from models.base.policy import (
    AclEntry,
    RouteMap, RouteMapEntry,
    PrefixList, PrefixListEntry,
    CommunityList, CommunityListEntry,
    AsPathList, AsPathEntry,
)
from models.base.policy.acl import acl_entry_regex
from models.base.policy.prefix_list import prefix_list_entry_regex
from models.base.routing_protocols.bgp import BgpAddressFamily, BgpAddressFamilyRedistribute, BgpAdminDistance, BgpMaximumPaths, BgpNextHopTriggerDelay, BgpTemplatePeer, BgpTemplatePeerLocalAs, BgpTimers
from models.base.routing_protocols.ospf import OspfDefaultInformation, OspfDiscardRoute, OspfLsaThrottlingTimers, OspfSpfThrottlingTimers, OspfTimers, OspfVrfConfig
from models.base.routing_protocols.route import route_nh_regex, protocol_map
from models.base.routing_protocols.vrf import VrfAddressFamily, VrfRouteTarget
from models.base.system import (
    AaaConfig,
    LoggingConfig,
    NtpServer,
    SnmpConfig,
)

class CiscoNXOS(Device):
    """Cisco Nexus device."""

    def __init__(self, config: Optional[str] = None, hostname: Optional[str] = None, routing_table: Optional[str] = None):
        """Initialize the device."""
        self.routing_table: Optional[str] = routing_table
        self.routes: List[Route] = []
        self.interfaces: Dict[str, Interface] = {}
        self.vrfs: Dict[str, VrfConfig] = {}
        self.vlans: Dict[str, VlanConfig] = {}
        super().__init__(config, hostname)
    
    @cached_property
    def parse(self) -> Optional[CiscoConfParse]:
        if self.config:
            return CiscoConfParse(self.config.splitlines(), syntax='nxos')
        return None

    @cached_property
    def parse_routing(self) -> Optional[CiscoConfParse]:
        if self.routing_table:
            return CiscoConfParse(self.routing_table.splitlines(), syntax='nxos')
        return None

    def parse_config(self) -> None:
        """Parse device configuration."""
        # Process each section
        self._hostname = self._parse_hostname()
        self.interfaces = self._parse_interfaces()
        self.vrfs = self._parse_vrfs()
        self.vlans = self._parse_vlans()
        self.bgp = self._parse_bgp()
        self.ospf = self._parse_ospf()
        self.acls = self._parse_acls()
        self.prefix_lists = self._parse_prefix_lists()
        self.route_maps = self._parse_route_maps()

    @lru_cache
    def _parse_interfaces(self) -> Dict[str, Interface]:
        """Get interface configuration."""
        interfaces = {}
        for intf in self.parse.find_objects(r'^interface'):
            name = intf.text.split()[1]
            interface = Interface(
                name=name,
                description=None,
                enabled=True,
                allowed_vlans=[],
            )

            for line in intf.children:
                if 'description' in line.text:
                    interface.description = line.text.split('description')[1].strip()
                elif 'shutdown' in line.text:
                    interface.enabled = 'no shutdown' in line.text
                elif 'switchport mode' in line.text:
                    interface.switchport_mode = line.text.split()[-1]
                elif 'bandwidth' in line.text and 'no' not in line.text:
                    interface.bandwidth = int(line.text.split()[-1])
                elif 'ip address' in line.text:
                    ip_match = re.match(r'\s*ip address\s+(\S+)', line.text)
                    if ip_match:
                        try:
                            if '/' in ip_match.group(1):
                                ip_address, subnet_mask = ip_match.group(1).split('/')
                            ip_network_string = f"{ip_match.group(1)}" if '/' in line.text else f"{ip_match.group(1)}/{ip_match.group(2)}"
                            interface.ip_network = IPv4Network(ip_network_string, strict=False)
                            interface.ip_address = IPv4Address(ip_address)
                            interface.subnet_mask = subnet_mask
                        except AddressValueError:
                            interface.ip_network = IPv6Network(f"{ip_match.group(1)}")
                            interface.ip_address = IPv6Address(ip_match.group(1).split('/')[0])
                            interface.subnet_mask = ip_match.group(1).split('/')[1]
                elif 'speed' in line.text:
                    interface.speed = line.text.split()[-1]
                elif 'duplex' in line.text:
                    interface.duplex = line.text.split()[-1]
                elif 'mtu' in line.text:
                    interface.mtu = int(line.text.split()[-1])
                elif 'vrf member' in line.text:
                    interface.vrf = line.text.split()[-1]
                elif 'channel-group' in line.text:
                    parts = line.text.strip().split()
                    interface.channel_group = int(parts[1])
                    if len(parts) > 2:
                        interface.channel_mode = parts[-1]
                elif 'switchport access vlan' in line.text:
                    interface.vlan = line.text.split()[-1]
                elif 'allowed vlan' in line.text:
                    for v in line.text.split()[-1].split(','):
                        if '-' in v:
                            start, end = v.split('-')
                            interface.allowed_vlans.extend(list(map(str, range(int(start), int(end) + 1))))
                        else:
                            interface.allowed_vlans.append(v)
                elif 'vpc' in line.text:
                    interface.vpc = line.text.split()[-1]
                elif 'storm-control broadcast level' in line.text:
                    interface.storm_control_broadcast = int(float(line.text.split()[-1]) * 100)
                elif 'storm-control multicast level' in line.text:
                    interface.storm_control_multicast = int(float(line.text.split()[-1]) * 100)
                elif 'spanning-tree port type' in line.text:
                    interface.stp_port_type = line.text.split()[-1]
                elif 'ip router ospf' in line.text:
                    ospf_match = re.match(r'\s*ip router ospf\s+(\S+)\s+area\s+(\S+)', line.text)
                    if ospf_match:
                        interface.ospf_process_id = ospf_match.group(1)
                        interface.ospf_area = ospf_match.group(2)

            interfaces[name] = interface
        return interfaces

    @lru_cache
    def _parse_vlans(self) -> Dict[str, VlanConfig]:
        """Get VLAN configuration."""
        vlans = {}
        for vlan in self.parse.find_objects(r'^vlan \d+'):
            vlan_ids = vlan.text.split()[1]
            if ',' in vlan_ids:
                vlan_ids = vlan_ids.split(',')
                for vlan_id in vlan_ids:
                    if '-' in vlan_id:
                        start, end = vlan_id.split('-')
                        for id in range(int(start), int(end) + 1):
                            vlan_config = VlanConfig(
                                vlan_id=int(id),
                                name=None,
                                state='active',
                                interfaces=[],
                                private_vlan_type={},
                                shutdown=False
                            )
                            vlans[str(id)] = vlan_config
                    else:
                        vlan_config = VlanConfig(
                            vlan_id=int(vlan_id),
                            name=None,
                            state='active',
                            interfaces=[],
                            private_vlan_type={},
                            shutdown=False
                        )
                        vlans[vlan_id] = vlan_config
            else:
                vlans[vlan_ids] = VlanConfig(
                    vlan_id=int(vlan_ids),
                    name=None,
                    state='active',
                    interfaces=[],
                    private_vlan_type={},
                    shutdown=False
                )

            for line in vlan.children:
                vlan_id = vlan.text.split()[1]
                if 'name' in line.text:
                    vlans[vlan_id].name = line.text.split('name')[1].strip()
                elif 'mode' in line.text:
                    vlans[vlan_id].mode = line.text.split('mode')[1].strip()
                elif 'private-vlan' in line.text:
                    parts = line.text.strip().split()
                    vlans[vlan_id].private_vlan_type.update({parts[1]: True})
                    if len(parts) > 2:
                        if parts[1] == 'association':
                            vlans[vlan_id].private_vlan_type[parts[1]] = [x for x in parts[2:]]
                elif 'shutdown' in line.text:
                    vlans[vlan_id].shutdown = True
                elif 'state' in line.text:
                    vlans[vlan_id].state = line.text.split('state')[1].strip()
                elif 'vn-segment' in line.text:
                    vlans[vlan_id].vn_segment = line.text.split('vn-segment')[1].strip()
                elif 'xconnect' in line.text:
                    vlans[vlan_id].xconnect = True

        return vlans

    @lru_cache
    def _parse_vrfs(self) -> Dict[str, VrfConfig]:
        """Get VRF configuration."""
        vrfs = {}
        for vrf in self.parse.find_objects(r'^vrf context'):
            name = vrf.text.split()[2]
            vrf_config = VrfConfig(
                name=name,
                description=None,
                rd=None,
                routes=[],
                route_targets=[],
                address_families={},
                vrf=name,
                interfaces=[interface.name for interface in self.interfaces.values() if interface.vrf == name],
            )

            for line in vrf.children:
                if 'description' in line.text:
                    vrf_config.description = line.text.split('description')[1].strip()
                elif 'vni' in line.text:
                    vrf_config.vni = int(line.text.split('vni')[1].strip())
                elif 'ip route' in line.text:
                    route_match = re.match(r'\s*ip route\s+(\S+)\s*(\S+)?\s*name\s*(\S+)?\s*(\d+)?', line.text)
                    if route_match:
                        ip_network = route_match.group(1)
                        next_hop = route_match.group(2)
                        route_name = None
                        admin_distance = 0
                        if len(route_match.groups()) > 2:
                            route_name = route_match.group(3)
                            admin_distance = int(route_match.group(4)) if route_match.group(4) else 0
                        vrf_config.routes.append(Route(
                            protocol='S',
                            name=route_name,
                            network=IPv4Network(ip_network, strict=False),
                            admin_distance=admin_distance,
                            next_hop=IPv4Address(next_hop),
                        ))
                elif 'rd' in line.text:
                    vrf_config.rd = line.text.split('rd')[1].strip()
                elif 'route-target' in line.text:
                    parts = line.text.strip().split()
                    if len(parts) > 2:
                        if parts[1] == 'import':
                            import_vrf_route_target = VrfRouteTarget(import_targets=[parts[2]])
                            if 'evpn' in parts:
                                import_vrf_route_target.import_evpn_routes = True
                            vrf_config.route_targets.append(import_vrf_route_target)
                        elif parts[1] == 'export':
                            export_vrf_route_target = VrfRouteTarget(export_targets=[parts[2]])
                            if 'evpn' in parts:
                                export_vrf_route_target.export_evpn_routes = True
                            vrf_config.route_targets.append(export_vrf_route_target)
                        elif parts[1] == 'both':
                            import_export_vrf_route_target = VrfRouteTarget(import_targets=parts[2], export_targets=parts[2])
                            if 'evpn' in parts:
                                import_export_vrf_route_target.import_evpn_routes = True
                                import_export_vrf_route_target.export_evpn_routes = True
                            vrf_config.route_targets.append(import_export_vrf_route_target)
                elif 'address-family' in line.text:
                    address_family_key = line.text.split('address-family')[1].strip()
                    vrf_config.address_families[address_family_key] = VrfAddressFamily(
                        family=address_family_key,
                        route_targets=[],
                    )
                    for sub_line in line.children:
                        if 'route-target' in sub_line.text:
                            parts = sub_line.text.strip().split()
                            if len(parts) > 2:
                                if parts[1] == 'import':
                                    import_vrf_route_target = VrfRouteTarget(import_targets=[parts[2]])
                                    if 'evpn' in parts:
                                        import_vrf_route_target.import_evpn_routes = True
                                    vrf_config.address_families[address_family_key].route_targets.append(import_vrf_route_target)
                                elif parts[1] == 'export':
                                    export_vrf_route_target = VrfRouteTarget(export_targets=[parts[2]])
                                    if 'evpn' in parts:
                                        export_vrf_route_target.export_evpn_routes = True
                                    vrf_config.address_families[address_family_key].route_targets.append(export_vrf_route_target)
                                elif parts[1] == 'both':
                                    import_export_vrf_route_target = VrfRouteTarget(import_targets=parts[2], export_targets=parts[2])
                                    if 'evpn' in parts:
                                        import_export_vrf_route_target.import_evpn_routes = True
                                        import_export_vrf_route_target.export_evpn_routes = True
                                    vrf_config.address_families[address_family_key].route_targets.append(import_export_vrf_route_target)

            vrfs[name] = vrf_config
        return vrfs

    @lru_cache
    def _parse_bgp(self) -> Optional[BgpConfig]:
        """Get BGP configuration."""
        bgp_block = self.parse.find_objects(r'^router bgp')
        if not bgp_block:
            return None

        asn = bgp_block[0].text.split()[2]
        address_families = {}
        neighbors = {}
        template_peers = {}
        router_id = None
        rd = None
        keepalive_timer = None
        holdtime_timer = None
        best_path_limit = None
        prefix_peer_wait = None
        prefix_peer_timeout = None
        networks = {}
        vrf_configs = {}

        for line in bgp_block[0].children:
            if 'router-id' in line.text:
                router_id = line.text.split('router-id')[1].strip()
            elif 'network' in line.text:
                parts = line.text.strip().split()
                networks[parts[1]] = {'mask': parts[2] if len(parts) > 2 else None}
            elif 'timers' in line.text:
                bgp_timers_match =  re.match(r'\s*timers\s+bgp\s+(\d+)\s+(\d+)', line.text)
                best_path_match = re.match(r'\s*timers\s+bestpath-limit\s+(\d+)', line.text)
                prefix_peer_wait_match = re.match(r'\s*timers\s+prefix-peer-wait\s+(\d+)', line.text)
                prefix_peer_timeout_match = re.match(r'\s*timers\s+prefix-peer-timeout\s+(\d+)', line.text)
                if bgp_timers_match:
                    keepalive_timer = int(bgp_timers_match.group(1))
                    holdtime_timer = int(bgp_timers_match.group(2))
                elif best_path_match:
                    best_path_limit = int(best_path_match.group(1))
                elif prefix_peer_wait_match:
                    prefix_peer_wait = int(prefix_peer_wait_match.group(1))
                elif prefix_peer_timeout_match:
                    prefix_peer_timeout = int(prefix_peer_timeout_match.group(1))
            elif line.text.strip().split()[0] == 'rd':
                rd = line.text.split('rd')[1].strip()
            elif 'address-family' in line.text:
                family_name = line.text.split('address-family')[1].strip()
                address_families[family_name] = BgpAddressFamily(
                    family=family_name,
                    max_paths=BgpMaximumPaths(),
                    next_hop_trigger_delay=BgpNextHopTriggerDelay(),
                    admin_distance=BgpAdminDistance(),
                )
                for sub_line in line.children:
                    if 'maximum-paths' in sub_line.text:
                        ebgp_max_paths_match = re.match(r'\s*maximum-paths\s+(\d+)', sub_line.text)
                        ibgp_max_paths_match = re.match(r'\s*maximum-paths\s+ibgp\s+(\d+)', sub_line.text)
                        eibgp_max_paths_match = re.match(r'\s*maximum-paths\s+eibgp\s+(\d+)', sub_line.text)
                        local_max_paths_match = re.match(r'\s*maximum-paths\s+local\s+(\d+)', sub_line.text)
                        mixed_max_paths_match = re.match(r'\s*maximum-paths\s+mixed\s+(\d+)', sub_line.text)
                        if ebgp_max_paths_match:
                            address_families[family_name].max_paths.ebgp = int(ebgp_max_paths_match.group(1))
                        elif ibgp_max_paths_match:
                            address_families[family_name].max_paths.ibgp = int(ibgp_max_paths_match.group(1))
                        elif eibgp_max_paths_match:
                            address_families[family_name].max_paths.eibgp = int(eibgp_max_paths_match.group(1))
                        elif local_max_paths_match:
                            address_families[family_name].max_paths.local = int(local_max_paths_match.group(1))
                        elif mixed_max_paths_match:
                            address_families[family_name].max_paths.mixed = int(mixed_max_paths_match.group(1))
                    elif 'nexthop trigger-delay' in sub_line.text:
                        critical_next_hop_trigger_delay_match = re.match(r'\s*nexthop trigger-delay\s+critical\s+(\d+)\s+non-critical\s+(\d+)', sub_line.text)
                        if critical_next_hop_trigger_delay_match:
                            address_families[family_name].next_hop_trigger_delay.critical = int(critical_next_hop_trigger_delay_match.group(1))
                            address_families[family_name].next_hop_trigger_delay.non_critical = int(critical_next_hop_trigger_delay_match.group(2))
                    elif 'client-to-client reflection' in sub_line.text:
                        address_families[family_name].client_to_client_reflection = True
                    elif 'distance' in sub_line.text:
                        bgp_distance_match = re.match(r'\s*distance\s+(\d+)\s+(\d+)\s+(\d+)', sub_line.text)
                        if bgp_distance_match:
                            address_families[family_name].admin_distance.ebgp = int(bgp_distance_match.group(1))
                            address_families[family_name].admin_distance.ibgp = int(bgp_distance_match.group(2))
                            address_families[family_name].admin_distance.locally_originated = int(bgp_distance_match.group(3))
                    elif 'dampen-igp-metric' in sub_line.text:
                        address_families[family_name].dampen_igp_metric = int(sub_line.text.split('dampen-igp-metric')[1].strip())
            elif 'template peer' in line.text:
                template_peer_name = line.text.split('template peer')[1].strip()
                template_peers[template_peer_name] = BgpTemplatePeer(
                    name=template_peer_name,
                    local_as=BgpTemplatePeerLocalAs(),
                )
                for sub_line in line.children:
                    if 'remote-as' in sub_line.text:
                        template_peers[template_peer_name].remote_as = int(sub_line.text.split('remote-as')[1].strip())
                    elif 'local-as' in sub_line.text:
                        local_as_match = re.match(r'\s*local-as\s+(\d+)(?:\s+(no-prepend)\s+(replace-as))?', sub_line.text)
                        if local_as_match:
                            template_peers[template_peer_name].local_as.local_as = int(local_as_match.group(1))
                            if local_as_match.group(2):
                                template_peers[template_peer_name].local_as.no_prepend = True
                            if local_as_match.group(3):
                                template_peers[template_peer_name].local_as.replace_as = True
                    elif 'dynamic-capability' in sub_line.text:
                        template_peers[template_peer_name].dynamic_capability = True
                    elif 'update-source' in sub_line.text:
                        template_peers[template_peer_name].update_source = sub_line.text.split('update-source')[1].strip()
                    elif 'timers' in sub_line.text:
                        timers_match = re.match(r'\s*timers\s+(\d+)\s+(\d+)', sub_line.text)
                        if timers_match:
                            template_peers[template_peer_name].keepalive_timer = int(timers_match.group(1))
                            template_peers[template_peer_name].holdtime_timer = int(timers_match.group(2))
                    elif 'dscp' in sub_line.text:
                        template_peers[template_peer_name].dscp = int(sub_line.text.split('dscp')[1].strip())
                    elif 'address-family' in sub_line.text:
                        template_address_family_name = sub_line.text.split('address-family')[1].strip()
                        template_peers[template_peer_name].address_families[template_address_family_name] = BgpAddressFamily(
                            family=template_address_family_name,
                        )
                        for sub_sub_line in sub_line.children:
                            if 'send-community' in sub_sub_line.text:
                                template_peers[template_peer_name].address_families[template_address_family_name].send_community = True
                                if 'extended' in sub_sub_line.text:
                                    template_peers[template_peer_name].address_families[template_address_family_name].send_community_extended = True
                            elif 'next-hop-third-party' in sub_sub_line.text:
                                template_peers[template_peer_name].address_families[template_address_family_name].next_hop_third_party = True
                            elif 'advertise local-labeled-route' in sub_sub_line.text:
                                template_peers[template_peer_name].address_families[template_address_family_name].advertise_local_labeled_route = True
                                if 'safi-unicast' in sub_sub_line.text:
                                    template_peers[template_peer_name].address_families[template_address_family_name].advertise_local_labeled_route_safi_unicast = True
                            elif 'soft-reconfiguration' in sub_sub_line.text:
                                sub_sub_parts = sub_sub_line.text.strip().split()
                                if len(sub_sub_parts) > 2:
                                    template_peers[template_peer_name].address_families[template_address_family_name].soft_reconfiguration_inbound = sub_sub_parts[2]
                                else:
                                    template_peers[template_peer_name].address_families[template_address_family_name].soft_reconfiguration_inbound = True
                    elif 'description' in sub_line.text:
                        template_peers[template_peer_name].description = sub_line.text.split('description')[1].strip()
                    elif 'route-map' in sub_line.text:
                        direction = sub_line.text.split('route-map')[1].split()[0]
                        route_map = sub_line.text.split('route-map')[1].split()[1]
            elif re.match(r'\s*neighbor\s+\S+', line.text):
                neighbor_address = line.text.strip().split()[1]
                neighbors[neighbor_address] = BgpNeighbor(
                    peer=neighbor_address,
                )
                for sub_line in line.children:
                    if 'inherit peer' in sub_line.text:
                        inherit_peer_name = sub_line.text.split('inherit peer')[1].strip()
                        inherit_template_peer = template_peers.get(inherit_peer_name)
                        neighbors[neighbor_address].inherit_peer = inherit_template_peer or inherit_peer_name
                        neighbors[neighbor_address].remote_as = inherit_template_peer.remote_as if inherit_template_peer else None  
                    elif 'dynamic-capability' in sub_line.text:
                        neighbors[neighbor_address].dynamic_capability = True
                    elif 'timers' in sub_line.text:
                        timers_match = re.match(r'\s*timers\s+(\d+)\s+(\d+)', sub_line.text)
                        if timers_match:
                            neighbors[neighbor_address].keepalive_timer = int(timers_match.group(1))
                            neighbors[neighbor_address].holdtime_timer = int(timers_match.group(2))
                    elif 'dscp' in sub_line.text:
                        neighbors[neighbor_address].dscp = int(sub_line.text.split('dscp')[1].strip())
            elif 'vrf' in line.text:
                vrf_name = line.text.split()[1]
                vrf_config = BgpVrfConfig(
                    vrf=vrf_name,
                    rd=None,
                    neighbors={},
                    networks={},
                    address_families={},
                    redistribute=[]
                )

                for vrf_line in line.children:
                    if 'address-family' in vrf_line.text:
                        family_name = vrf_line.text.split('address-family')[1].strip()
                        vrf_address_family = BgpAddressFamily(
                            family=family_name,
                            max_paths=BgpMaximumPaths(),
                            next_hop_trigger_delay=BgpNextHopTriggerDelay(),
                            admin_distance=BgpAdminDistance(),
                        )
                        for sub_vrf_line in vrf_line.children:
                            if 'advertise' in sub_vrf_line.text:
                                vrf_address_family.advertise = sub_vrf_line.text.split('advertise')[1].strip()
                            elif 'redistribute' in sub_vrf_line.text:
                                parts = sub_vrf_line.text.strip().split()
                                if 'direct' in parts:
                                    vrf_address_family.redistribute.append(BgpAddressFamilyRedistribute(protocol='direct', route_map=parts[-1]))
                                elif 'static' in parts:
                                    vrf_address_family.redistribute.append(BgpAddressFamilyRedistribute(protocol='static', route_map=parts[-1]))
                                elif 'ospf' in parts:
                                    vrf_address_family.redistribute.append(BgpAddressFamilyRedistribute(protocol='ospf', instance_tag=parts[2], route_map=parts[-1]))
                            elif 'maximum-paths' in sub_vrf_line.text:
                                ebgp_max_paths_match = re.match(r'\s*maximum-paths\s+(\d+)', sub_vrf_line.text)
                                ibgp_max_paths_match = re.match(r'\s*maximum-paths\s+ibgp\s+(\d+)', sub_vrf_line.text)
                                eibgp_max_paths_match = re.match(r'\s*maximum-paths\s+eibgp\s+(\d+)', sub_vrf_line.text)
                                local_max_paths_match = re.match(r'\s*maximum-paths\s+local\s+(\d+)', sub_vrf_line.text)
                                mixed_max_paths_match = re.match(r'\s*maximum-paths\s+mixed\s+(\d+)', sub_vrf_line.text)
                                if ebgp_max_paths_match:
                                    vrf_address_family.max_paths.ebgp = int(ebgp_max_paths_match.group(1))
                                elif ibgp_max_paths_match:
                                    vrf_address_family.max_paths.ibgp = int(ibgp_max_paths_match.group(1))
                                elif eibgp_max_paths_match:
                                    vrf_address_family.max_paths.eibgp = int(eibgp_max_paths_match.group(1))
                                elif local_max_paths_match:
                                    vrf_address_family.max_paths.local = int(local_max_paths_match.group(1))
                                elif mixed_max_paths_match:
                                    vrf_address_family.max_paths.mixed = int(mixed_max_paths_match.group(1))
                            elif 'nexthop trigger-delay' in sub_vrf_line.text:
                                critical_next_hop_trigger_delay_match = re.match(r'\s*nexthop trigger-delay\s+critical\s+(\d+)\s+non-critical\s+(\d+)', sub_vrf_line.text)
                                if critical_next_hop_trigger_delay_match:
                                    vrf_address_family.next_hop_trigger_delay.critical = int(critical_next_hop_trigger_delay_match.group(1))
                                    vrf_address_family.next_hop_trigger_delay.non_critical = int(critical_next_hop_trigger_delay_match.group(2))
                            elif 'client-to-client reflection' in sub_vrf_line.text:
                                vrf_address_family.client_to_client_reflection = True
                            elif 'distance' in sub_vrf_line.text:
                                bgp_distance_match = re.match(r'\s*distance\s+(\d+)\s+(\d+)\s+(\d+)', sub_vrf_line.text)
                                if bgp_distance_match:
                                    vrf_address_family.admin_distance.ebgp = int(bgp_distance_match.group(1))
                                    vrf_address_family.admin_distance.ibgp = int(bgp_distance_match.group(2))
                                    vrf_address_family.admin_distance.locally_originated = int(bgp_distance_match.group(3))
                            elif 'dampen-igp-metric' in sub_vrf_line.text:
                                vrf_address_family.dampen_igp_metric = int(sub_vrf_line.text.split('dampen-igp-metric')[1].strip())
                        vrf_config.address_families[family_name] = vrf_address_family
                    elif re.match(r'\s*neighbor\s+\S+', vrf_line.text):
                        parts = vrf_line.text.strip().split()
                        neighbor = parts[1]
                        if neighbor not in vrf_config.neighbors:
                            vrf_config.neighbors[neighbor] = BgpNeighbor(
                                peer=neighbor,
                                remote_as=0,
                                description=None,
                                route_maps={'in': None, 'out': None}
                            )
                        if 'remote-as' in vrf_line.text:
                            vrf_config.neighbors[neighbor].remote_as = parts[3]
                        elif 'description' in vrf_line.text:
                            vrf_config.neighbors[neighbor].description = ' '.join(parts[2:])
                        elif 'route-map' in vrf_line.text:
                            direction = parts[-1]
                            route_map = parts[-2]
                            vrf_config.neighbors[neighbor].route_maps[direction] = self.route_maps[route_map]
                        elif (sub_vrf_af_line := next((sub_vrf_line for sub_vrf_line in vrf_line.children if 'address-family' in sub_vrf_line.text), None)):
                            for sub_vrf_sub_af_line in sub_vrf_af_line.children:
                                if 'route-map' in sub_vrf_sub_af_line.text:
                                    direction = sub_vrf_sub_af_line.text.strip().split()[-1]
                                    route_map = sub_vrf_sub_af_line.text.strip().split()[-2]
                                    vrf_config.neighbors[neighbor].route_maps[direction] = self.route_maps[route_map]

                    elif 'network' in vrf_line.text:
                        parts = vrf_line.text.strip().split()
                        vrf_config.networks[parts[1]] = {'mask': parts[2] if len(parts) > 2 else None}
                    elif 'redistribute' in vrf_line.text:
                        vrf_config.redistribute.append(vrf_line.text.strip())

                vrf_configs[vrf_name] = vrf_config

        return BgpConfig(
            asn=asn,
            router_id=router_id,
            route_distinguisher=rd,
            address_families=address_families,
            neighbors=neighbors,
            template_peers=template_peers,
            networks=networks,
            vrf_configs=vrf_configs,
            timers=BgpTimers(
                keepalive_timer=keepalive_timer,
                holdtime_timer=holdtime_timer,
                best_path_limit=best_path_limit,
                prefix_peer_wait=prefix_peer_wait,
                prefix_peer_timeout=prefix_peer_timeout
            )
        )

    @lru_cache
    def _parse_ospf(self) -> Dict[str, OspfConfig]:
        """Get OSPF configuration."""
        ospf_configs = {}

        interfaces = self.interfaces.values()
        vrf_ospf_interfaces = [interface for interface in interfaces if interface.vrf and interface.ospf_process_id]
        no_vrf_ospf_interfaces = [interface for interface in interfaces if not interface.vrf and interface.ospf_process_id]

        for ospf in self.parse.find_objects(r'^router ospf'):
            instance_tag = ospf.text.split()[2]
            ospf_config = OspfConfig(
                instance_tag=instance_tag,
                timers=OspfTimers(),
                discard_route=OspfDiscardRoute(),
            )

            for line in ospf.children:
                if 'router-id' in line.text:
                    ospf_config.router_id = line.text.split('router-id')[1].strip()
                elif 'graceful-restart' in line.text:
                    if 'grace-period' in line.text:
                        ospf_config.graceful_restart_grace_period = int(line.text.split('grace-period')[1].strip())
                    else:
                        ospf_config.graceful_restart = True
                elif 'max-metric router-lsa on-startup' in line.text:
                    parts = line.text.strip().split()
                    ospf_config.max_metric_lsa_on_startup = int(parts[3])
                elif 'timers' in line.text:
                    spf_throttling_timers_match = re.match(r'\s*timers\s+throttle\s+spf\s+(\d+)\s+(\d+)\s+(\d+)', line.text)
                    lsa_group_pacing_timers_match = re.match(r'\s*timers\s+lsa-group-pacing\s+(\d+)', line.text)
                    lsa_arrival_timers_match = re.match(r'\s*timers\s+lsa-arrival\s+(\d+)', line.text)
                    lsa_throttling_timers_match = re.match(r'\s*timers\s+throttle\s+lsa\s+(\d+)\s+(\d+)\s+(\d+)', line.text)
                    if spf_throttling_timers_match:
                        ospf_config.timers.spf_throttling_timers = OspfSpfThrottlingTimers(
                            initial_delay=int(spf_throttling_timers_match.group(1)),
                            wait_time=int(spf_throttling_timers_match.group(2)),
                            max_wait_time=int(spf_throttling_timers_match.group(3))
                        )
                    elif lsa_group_pacing_timers_match:
                        ospf_config.timers.lsa_group_pacing = lsa_group_pacing_timers_match.group(1)
                    elif lsa_arrival_timers_match:
                        ospf_config.timers.lsa_arrival = lsa_arrival_timers_match.group(1)
                    elif lsa_throttling_timers_match:
                        ospf_config.timers.lsa_throttling_timers = OspfLsaThrottlingTimers(
                            initial_delay=int(lsa_throttling_timers_match.group(1)),
                            wait_time=int(lsa_throttling_timers_match.group(2)),
                            max_wait_time=int(lsa_throttling_timers_match.group(3))
                        )
                elif 'distance' in line.text:
                    ospf_config.admin_distance = int(line.text.split('distance')[1].strip())
                elif 'maximum-paths' in line.text:
                    ospf_config.max_paths = int(line.text.split('maximum-paths')[1].strip())
                elif 'auto-cost reference-bandwidth' in line.text:
                    parts = line.text.strip().split()
                    reference_bandwidth = int(parts[2])
                    if len(parts) > 3:
                        if parts[3].lower() == 'gbps':
                            ospf_config.reference_bandwidth = reference_bandwidth * 1000
                    else:
                        ospf_config.reference_bandwidth = reference_bandwidth
                elif 'discard-route' in line.text:
                    if 'external' in line.text:
                        ospf_config.discard_route.external = True
                    elif 'internal' in line.text:
                        ospf_config.discard_route.internal = True
                elif 'vrf' in line.text:
                    vrf_name = line.text.split('vrf')[1].strip()
                    current_vrf_ospf_interfaces = [interface for interface in vrf_ospf_interfaces if interface.vrf == vrf_name]
                    current_vrf_ospf_networks = [
                        OspfNetwork(
                            network=interface.ip_network,
                            area=interface.ospf_area,
                            wildcard=str(interface.ip_network.hostmask)
                        ) for interface in current_vrf_ospf_interfaces
                    ]
                    ospf_config.vrf_configs[vrf_name] = OspfVrfConfig(
                        vrf=vrf_name,
                        timers=OspfTimers(),
                        discard_route=OspfDiscardRoute(),
                        interfaces=current_vrf_ospf_interfaces,
                        areas=set([interface.ospf_area for interface in current_vrf_ospf_interfaces]),
                        networks=current_vrf_ospf_networks,
                    )
                    for sub_line in line.children:
                        if 'bfd' in sub_line.text:
                            ospf_config.vrf_configs[vrf_name].bidirectional_forwarding_detection = True
                        elif 'router-id' in sub_line.text:
                            ospf_config.vrf_configs[vrf_name].router_id = sub_line.text.split('router-id')[1].strip()
                        elif 'default-information' in sub_line.text:
                            if 'originate' in sub_line.text:
                                ospf_config.vrf_configs[vrf_name].default_information = OspfDefaultInformation(originate=True)
                            if 'always' in sub_line.text:
                                ospf_config.vrf_configs[vrf_name].default_information.always = True
                        elif 'graceful-restart' in sub_line.text:
                            ospf_config.vrf_configs[vrf_name].graceful_restart = True
                            if 'grace-period' in sub_line.text:
                                ospf_config.vrf_configs[vrf_name].graceful_restart_grace_period = int(sub_line.text.split('grace-period')[1].strip())
                        elif 'max-metric router-lsa on-startup' in sub_line.text:
                            parts = sub_line.text.strip().split()
                            ospf_config.vrf_configs[vrf_name].max_metric_lsa_on_startup = int(parts[3])
                        elif 'timers' in sub_line.text:
                            vrf_spf_throttling_timers_match = re.match(r'\s*timers\s+throttle\s+spf\s+(\d+)\s+(\d+)\s+(\d+)', sub_line.text)
                            vrf_lsa_group_pacing_timers_match = re.match(r'\s*timers\s+lsa-group-pacing\s+(\d+)', sub_line.text)
                            vrf_lsa_arrival_timers_match = re.match(r'\s*timers\s+lsa-arrival\s+(\d+)', sub_line.text)
                            vrf_lsa_throttling_timers_match = re.match(r'\s*timers\s+throttle\s+lsa\s+(\d+)\s+(\d+)\s+(\d+)', sub_line.text)
                            if vrf_spf_throttling_timers_match:
                                ospf_config.vrf_configs[vrf_name].timers.spf_throttling_timers = OspfSpfThrottlingTimers(
                                    initial_delay=int(vrf_spf_throttling_timers_match.group(1)),
                                    wait_time=int(vrf_spf_throttling_timers_match.group(2)),
                                    max_wait_time=int(vrf_spf_throttling_timers_match.group(3))
                                )
                            elif vrf_lsa_group_pacing_timers_match:
                                ospf_config.vrf_configs[vrf_name].timers.lsa_group_pacing = vrf_lsa_group_pacing_timers_match.group(1)
                            elif vrf_lsa_arrival_timers_match:
                                ospf_config.vrf_configs[vrf_name].timers.lsa_arrival = vrf_lsa_arrival_timers_match.group(1)
                            elif vrf_lsa_throttling_timers_match:
                                ospf_config.vrf_configs[vrf_name].timers.lsa_throttling_timers = OspfLsaThrottlingTimers(
                                    initial_delay=int(vrf_lsa_throttling_timers_match.group(1)),
                                    wait_time=int(vrf_lsa_throttling_timers_match.group(2)),
                                    max_wait_time=int(vrf_lsa_throttling_timers_match.group(3))
                                )
                        elif 'distance' in sub_line.text:
                            ospf_config.vrf_configs[vrf_name].admin_distance = int(sub_line.text.split('distance')[1].strip())
                        elif 'table-map' in sub_line.text and 'filter' in sub_line.text:
                            ospf_config.vrf_configs[vrf_name].table_map_filter = sub_line.text.strip().split()[1]
                        elif 'maximum-paths' in sub_line.text:
                            ospf_config.vrf_configs[vrf_name].max_paths = int(sub_line.text.split('maximum-paths')[1].strip())
                        elif 'auto-cost reference-bandwidth' in sub_line.text:
                            parts = sub_line.text.strip().split()
                            reference_bandwidth = int(parts[2])
                            if len(parts) > 3:
                                if parts[3].lower() == 'gbps':
                                    ospf_config.vrf_configs[vrf_name].reference_bandwidth = reference_bandwidth * 1000
                            else:
                                ospf_config.vrf_configs[vrf_name].reference_bandwidth = reference_bandwidth
                        elif 'discard-route' in sub_line.text:
                            if 'external' in sub_line.text:
                                ospf_config.vrf_configs[vrf_name].discard_route.external = True
                            elif 'internal' in sub_line.text:
                                ospf_config.vrf_configs[vrf_name].discard_route.internal = True

            ospf_configs[instance_tag] = ospf_config
            ospf_configs[instance_tag].interfaces = no_vrf_ospf_interfaces
            ospf_configs[instance_tag].areas = set([interface.ospf_area for interface in no_vrf_ospf_interfaces])
            ospf_configs[instance_tag].networks = [
                OspfNetwork(
                    network=interface.ip_network,
                    area=interface.ospf_area,
                    wildcard=str(interface.ip_network.hostmask)
                ) for interface in no_vrf_ospf_interfaces
            ]

        return ospf_configs

    @lru_cache
    def _parse_acls(self) -> Dict[str, Union[Ipv4Acl, Ipv6Acl]]:
        """Get ACL configuration."""
        acls = {}
        for line in self.parse.find_objects(r'^ip access-list'):
            parts = line.text.split()
            name = parts[2]
            acl_type = "standard" if name.isdigit() and int(name) in range(1, 99) else "extended"

            if name not in acls:
                acls[name] = Ipv4Acl(name=name, type=acl_type, entries={})

            for child in line.children:
                seq = None
                action = None
                protocol = None
                source = None
                destination = None
                acl_entry_match = acl_entry_regex.match(child.text)
                if acl_entry_match:
                    if acl_entry_match.group(2) not in ['permit', 'deny']:
                        continue
                    seq = int(acl_entry_match.group('seq')) if acl_entry_match.group('seq') else None
                    action = acl_entry_match.group('action')
                    protocol = acl_entry_match.group('protocol')
                    source = acl_entry_match.group('src_host') if acl_entry_match.group('src_host') else acl_entry_match.group('src')
                    source_port = acl_entry_match.group('src_port')
                    not_source_port = acl_entry_match.group('not_src_port')
                    lt_source_port = acl_entry_match.group('lt_src_port')
                    gt_source_port = acl_entry_match.group('gt_src_port')
                    source_port_lower_range = acl_entry_match.group('src_port_lower_range')
                    source_port_upper_range = acl_entry_match.group('src_port_upper_range')
                    source_message_type = acl_entry_match.group('src_msg_type')
                    destination = acl_entry_match.group('dst_host') if acl_entry_match.group('dst_host') else acl_entry_match.group('dst')
                    destination_port = acl_entry_match.group('dst_port')
                    not_destination_port = acl_entry_match.group('not_dst_port')
                    lt_destination_port = acl_entry_match.group('lt_dst_port')
                    gt_destination_port = acl_entry_match.group('gt_dst_port')
                    destination_port_lower_range = acl_entry_match.group('dst_port_lower_range')
                    destination_port_upper_range = acl_entry_match.group('dst_port_upper_range')
                    destination_message_type = acl_entry_match.group('dst_msg_type')
                    entry = AclEntry(
                        sequence=seq,
                        action=action,
                        protocol=protocol,
                        source=source,
                        source_port=source_port,
                        not_equal_source_port=not_source_port,
                        less_than_source_port=lt_source_port,
                        greater_than_source_port=gt_source_port,
                        source_port_lower_range=source_port_lower_range,
                        source_port_upper_range=source_port_upper_range,
                        source_message_type=source_message_type,
                        destination=destination,
                        destination_port=destination_port,
                        not_equal_destination_port=not_destination_port,
                        less_than_destination_port=lt_destination_port,
                        greater_than_destination_port=gt_destination_port,
                        destination_port_lower_range=destination_port_lower_range,
                        destination_port_upper_range=destination_port_upper_range,
                        destination_message_type=destination_message_type
                    )
                    if len(source.split()) > 1:
                        source_subnet, source_wildcard_mask = source.split()
                        source_mask = '.'.join(str(255 - int(x)) for x in source_wildcard_mask.split('.'))
                        try:
                            entry.source = IPv4Network(f'{source_subnet}/{source_mask}')
                        except NetmaskValueError:
                            entry.source = source
                        entry.source_wildcard = source_wildcard_mask
                    elif len(source.split()) == 1:
                        if '/' in source:
                            entry.source = IPv4Network(source)
                        elif re.match(r'(\d+\.){3}\d+', source):
                            entry.source = IPv4Address(source)
                    if len(destination.split()) > 1:
                        destination_subnet, destination_wildcard_mask = destination.split()
                        destination_mask = '.'.join(str(255 - int(x)) for x in destination_wildcard_mask.split('.'))
                        try:
                            entry.destination = IPv4Network(f'{destination_subnet}/{destination_mask}')
                        except NetmaskValueError:
                            entry.destination = destination
                        entry.destination_wildcard = destination_wildcard_mask
                    elif len(destination.split()) == 1:
                        if '/' in destination:
                            entry.destination = IPv4Network(destination)
                        elif re.match(r'(\d+\.){3}\d+', destination):
                            entry.destination = IPv4Address(destination)

                    if seq:
                        acls[name].entries[seq] = entry
                    else:
                        # Auto-generate sequence number if not present
                        max_seq = max(acls[name].entries.keys()) if acls[name].entries else 0
                        acls[name].entries[max_seq + 10] = entry
        
        for line in self.parse.find_objects(r'^ipv6 access-list'):
            parts = line.text.split()
            name = parts[2]

            if name not in acls:
                acls[name] = Ipv6Acl(name=name, entries={})

            for child in line.children:
                seq = None
                action = None
                protocol = None
                source = None
                destination = None
                acl_entry_match = acl_entry_regex.match(child.text)
                if acl_entry_match:
                    if acl_entry_match.group(2) not in ['permit', 'deny']:
                        continue
                    seq = int(acl_entry_match.group('seq')) if acl_entry_match.group('seq') else None
                    action = acl_entry_match.group('action')
                    protocol = acl_entry_match.group('protocol')
                    source = acl_entry_match.group('src_host') if acl_entry_match.group('src_host') else acl_entry_match.group('src')
                    source_port = acl_entry_match.group('src_port')
                    not_source_port = acl_entry_match.group('not_src_port')
                    lt_source_port = acl_entry_match.group('lt_src_port')
                    gt_source_port = acl_entry_match.group('gt_src_port')
                    source_port_lower_range = acl_entry_match.group('src_port_lower_range')
                    source_port_upper_range = acl_entry_match.group('src_port_upper_range')
                    source_message_type = acl_entry_match.group('src_msg_type')
                    destination = acl_entry_match.group('dst_host') if acl_entry_match.group('dst_host') else acl_entry_match.group('dst')
                    destination_port = acl_entry_match.group('dst_port')
                    not_destination_port = acl_entry_match.group('not_dst_port')
                    lt_destination_port = acl_entry_match.group('lt_dst_port')
                    gt_destination_port = acl_entry_match.group('gt_dst_port')
                    destination_port_lower_range = acl_entry_match.group('dst_port_lower_range')
                    destination_port_upper_range = acl_entry_match.group('dst_port_upper_range')
                    destination_message_type = acl_entry_match.group('dst_msg_type')
                    entry = AclEntry(
                        sequence=seq,
                        action=action,
                        protocol=protocol,
                        source=source,
                        source_port=source_port,
                        not_equal_source_port=not_source_port,
                        less_than_source_port=lt_source_port,
                        greater_than_source_port=gt_source_port,
                        source_port_lower_range=source_port_lower_range,
                        source_port_upper_range=source_port_upper_range,
                        source_message_type=source_message_type,
                        destination=destination,
                        destination_port=destination_port,
                        not_equal_destination_port=not_destination_port,
                        less_than_destination_port=lt_destination_port,
                        greater_than_destination_port=gt_destination_port,
                        destination_port_lower_range=destination_port_lower_range,
                        destination_port_upper_range=destination_port_upper_range,
                        destination_message_type=destination_message_type
                    )
                    if len(source.split()) > 1:
                        source_subnet, source_wildcard_mask = source.split()
                        source_mask = '.'.join(str(255 - int(x)) for x in source_wildcard_mask.split('.'))
                        try:
                            entry.source = IPv6Network(f'{source_subnet}/{source_mask}')
                        except NetmaskValueError:
                            entry.source = source
                        entry.source_wildcard = source_wildcard_mask
                    elif len(source.split()) == 1:
                        if '/' in source:
                            entry.source = IPv6Network(source)
                        elif re.match(r'(\d+\.){3}\d+', source):
                            entry.source = IPv6Address(source)
                    if len(destination.split()) > 1:
                        destination_subnet, destination_wildcard_mask = destination.split()
                        destination_mask = '.'.join(str(255 - int(x)) for x in destination_wildcard_mask.split('.'))
                        try:
                            entry.destination = IPv6Network(f'{destination_subnet}/{destination_mask}')
                        except NetmaskValueError:
                            entry.destination = destination
                        entry.destination_wildcard = destination_wildcard_mask
                    elif len(destination.split()) == 1:
                        if '/' in destination:
                            entry.destination = IPv6Network(destination)
                        elif re.match(r'(\d+\.){3}\d+', destination):
                            entry.destination = IPv6Address(destination)

                    if seq:
                        acls[name].entries[seq] = entry
                    else:
                        # Auto-generate sequence number if not present
                        max_seq = max(acls[name].entries.keys()) if acls[name].entries else 0
                        acls[name].entries[max_seq + 10] = entry

        return acls

    @lru_cache
    def _parse_prefix_lists(self) -> Dict[str, PrefixList]:
        """Process prefix lists from configuration."""
        prefix_lists = {}

        for line in self.parse.find_objects(r'^ip prefix-list'):
            prefix_list_match = prefix_list_entry_regex.match(line.text)
            if prefix_list_match:
                name = prefix_list_match.group('name')
                seq = int(prefix_list_match.group('seq')) if prefix_list_match.group('seq') else None
                action = prefix_list_match.group('action')
                prefix = prefix_list_match.group('prefix')
                ge = int(prefix_list_match.group('ge')) if prefix_list_match.group('ge') else None
                le = int(prefix_list_match.group('le')) if prefix_list_match.group('le') else None

                if name not in prefix_lists:
                    prefix_lists[name] = PrefixList(name=name)

                # Create prefix list entry
                entry = PrefixListEntry(
                    sequence=seq,
                    action=action,
                    prefix=IPv4Network(prefix),
                    ge=ge,
                    le=le
                )
                prefix_lists[name].entries[str(seq)] = entry

        return prefix_lists

    @lru_cache
    def _parse_route_maps(self) -> Dict[str, RouteMap]:
        """Process route maps from configuration."""
        route_maps = {}

        for line in self.parse.find_objects(r'^route-map'):
            parts = line.text.split()
            name = parts[1]
            action = parts[2]
            seq = parts[3] if len(parts) > 3 else '10'

            if name not in route_maps:
                route_maps[name] = RouteMap(name=name)

            # Create route map entry
            entry = RouteMapEntry(
                sequence=seq,
                action=action
            )
            route_maps[name].entries[seq] = entry

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

    @lru_cache
    def _parse_routing_table(self) -> Dict[str, RoutingTable]:
        """Process routing table."""
        table_name = None
        routing_tables = {}

        for line in self.parse_routing.find_objects(r'^(?:IP Route Table|(?:\d+\.){3}\d+)'):
            if (vrf_name := line.re_match(r'^IP Route Table for VRF "(\S+)"')):
                table_name = vrf_name
                routing_tables[table_name] = RoutingTable(vrf=table_name)
            elif (subnet := line.re_match(r'^((?:\d+\.){3}\d+\/\d+)')):
                for child in line.children:
                    route = Route(
                        network=IPv4Network(subnet),
                    )
                    route_match = route_nh_regex.match(child.text)
                    if route_match:
                        try:
                            route.next_hop = IPv4Address(route_match.group('next_hop')) if route_match.group('next_hop') else None
                        except AddressValueError:
                            route.next_hop = route_match.group('next_hop')
                        route.egress_interface = route_match.group('interface')
                        route.admin_distance = int(route_match.group('admin_distance'))
                        route.metric = int(route_match.group('metric'))
                        route.tag = int(route_match.group('tag')) if route_match.group('tag') else None
                        protocol = route_match.group('protocol')
                        if '-' in protocol:
                            routing_protocol, inst_tag_or_asn = protocol.split('-')
                            route.protocol = protocol_map.get(routing_protocol)
                            if routing_protocol.lower() == 'ospf':
                                route.ospf_instance_tag = inst_tag_or_asn
                            elif routing_protocol.lower() == 'bgp':
                                route.bgp_asn = inst_tag_or_asn
                        else:
                            route.protocol = protocol_map.get(protocol)
                        
                        if subnet not in routing_tables[table_name].routes:
                            routing_tables[table_name].routes[subnet] = [route]
                        else:
                            routing_tables[table_name].routes[subnet].append(route)

        # for line in self.parse_routing.find_objects(r'^IP Route Table'):
        #     parts = line.text.split()
        #     name = parts[2]
        #     # route_table = RouteTable(name=name)
        #     route_tables[name] = route_table

        return routing_tables

    # def _parse_route_line(self, line: str, vrf: str = 'default') -> Optional[Route]:
    #     """Parse a single route line using CiscoConfParse."""
    #     # Skip empty lines and header lines
    #     if not line or any(x in line for x in ['Codes:', 'Gateway', '-', '*via']):
    #         return None

    #     # Create a CiscoConfParse object with the line
    #     parse = CiscoConfParse([line], syntax='nxos')
    #     route_obj = parse.find_objects(r'^[A-Z*>].*')[0] if parse.find_objects(r'^[A-Z*>].*') else None
    #     if not route_obj:
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
    #     line_text = route_obj.text
    #     match = re.match(r'^(?P<best>[*>])?(?P<protocol>[A-Za-z]+)?\s+(?P<network>\S+)', line_text)
    #     if not match:
    #         return None

    #     groups = match.groupdict()
    #     protocol = groups.get('protocol', '').strip()
    #     network = groups.get('network', '').strip()

    #     # Skip if we don't have a valid network
    #     if not network or network == 'via' or '-' in network:
    #         return None

    #     # Extract admin distance and metric
    #     ad_metric_match = re.search(r'\[(?P<ad>\d+)/(?P<metric>\d+)\]', line_text)
    #     admin_distance = int(ad_metric_match.group('ad')) if ad_metric_match else 0
    #     metric = int(ad_metric_match.group('metric')) if ad_metric_match else 0

    #     # Extract next hop and interface using CiscoConfParse children
    #     next_hop = None
    #     interface = None
    #     if route_obj.children:
    #         child_text = route_obj.children[0].text
    #         next_hop_match = re.search(r'via\s+(\S+)', child_text)
    #         next_hop = next_hop_match.group(1).rstrip(',') if next_hop_match else None
            
    #         interface_match = re.search(r'(?:,\s+)?(\S+)$', child_text)
    #         interface = interface_match.group(1) if interface_match and not interface_match.group(1).startswith('[') else None

    #     # Extract source protocol and router ID
    #     source_protocol = None
    #     source_rid = None
    #     if route_obj.children:
    #         child_text = route_obj.children[0].text
    #         if 'Known via' in child_text:
    #             known_via_match = re.search(r'Known via "([^"]+)"', child_text)
    #             if known_via_match:
    #                 source_protocol = known_via_match.group(1)

    #             rid_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', child_text)
    #             if rid_match:
    #                 source_rid = rid_match.group(1)
    #         else:
    #             # Extract protocol from route information
    #             protocol_match = re.search(r'(?:ospf|bgp|eigrp)-(\d+)', child_text)
    #             if protocol_match:
    #                 source_protocol = protocol_match.group(0).split('-')[0]
    #                 source_rid = protocol_match.group(1)

    #     # Extract age if present
    #     age_match = re.search(r',\s+(\d+:\d+:\d+|\d+\w+)', line_text)
    #     age = age_match.group(1) if age_match else None

    #     # Extract tag if present
    #     tag_match = re.search(r'tag (\d+)', line_text)
    #     tag = int(tag_match.group(1)) if tag_match else None

    #     # Build attributes list using CiscoConfParse children
    #     attributes = []
    #     if groups.get('best') or '*' in line_text or '>' in line_text:
    #         attributes.append('best')
    #     if route_obj.children:
    #         child_text = route_obj.children[0].text
    #         if 'candidate' in child_text:
    #             attributes.append('candidate')
    #         if 'external' in child_text:
    #             attributes.append('external')
    #         if 'mpls-vpn' in child_text:
    #             attributes.append('mpls-vpn')
    #         if 'intra' in child_text:
    #             attributes.append('intra')

    #     return Route(
    #         protocol=protocol,
    #         network=network,
    #         next_hop=next_hop,
    #         interface=interface,
    #         admin_distance=admin_distance,
    #         metric=metric,
    #         is_best=bool(groups.get('best') or '*' in line_text or '>' in line_text),
    #         source_protocol=source_protocol,
    #         source_rid=source_rid,
    #         tag=tag,
    #         age=age,
    #         attributes=attributes,
    #         vrf=vrf
    #     )

    # def parse_routing_table(self, routing_table: str) -> None:
    #     """Parse routing table output using CiscoConfParse."""
    #     if not routing_table:
    #         return

    #     # Create CiscoConfParse object with the routing table
    #     parse = CiscoConfParse(routing_table.splitlines(), syntax='nxos')
        
    #     current_vrf = 'default'
    #     routes = []

    #     # Find all VRF sections and route entries
    #     for obj in parse.find_objects(r'^(?:IP Route Table for VRF|[A-Z*>])'):
    #         if 'IP Route Table for VRF' in obj.text:
    #             vrf_match = re.match(r'IP Route Table for VRF "(\S+)"', obj.text)
    #             if vrf_match:
    #                 current_vrf = vrf_match.group(1)
    #             continue

    #         # Process route entries
    #         route = self._parse_route_line(obj.text, current_vrf)
    #         if route and route.is_best:
    #             routes.append(route)

    #     self._routes.extend(routes)

    def get_routes(self) -> List[Route]:
        """Get all routes."""
        return self._routes if hasattr(self, '_routes') else []

    def get_routes_by_vrf(self, vrf: str) -> List[Route]:
        """Get routes for a specific VRF."""
        return [r for r in self.get_routes() if r.vrf == vrf]

    def get_routes_by_protocol(self, protocol: str) -> List[Route]:
        """Get routes for a specific protocol."""
        return [r for r in self.get_routes() if r.protocol == protocol]

    def get_best_routes(self) -> List[Route]:
        """Get only the best routes."""
        return [r for r in self.get_routes() if r.is_best]

    def get_routes_by_network(self, network: str) -> List[Route]:
        """Get routes by network."""
        return [r for r in self.get_routes() if r.network == network]

    def get_interface(self, name: str) -> Optional[Interface]:
        """Get interface by name."""
        return self.interfaces.get(name)

    def get_vrf(self, name: str) -> Optional[VrfConfig]:
        """Get VRF by name."""
        return self.vrfs.get(name)

    def interface_list(self) -> List[str]:
        """Get list of interface names."""
        return list(self.interfaces.keys())

    def vrf_list(self) -> List[str]:
        """Get list of VRF names."""
        return list(self.vrfs.keys())

    @lru_cache
    def _parse_hostname(self) -> Optional[str]:
        """Get device hostname."""
        hostname_obj = self.parse.find_objects(r'^hostname\s+(\S+)$')
        if hostname_obj:
            return hostname_obj[0].text.split()[1]
        return self.hostname

    @cached_property
    def interfaces(self) -> Dict[str, Interface]:
        """Get interfaces."""
        return self._interfaces

    @cached_property
    def vrfs(self) -> Dict[str, VrfConfig]:
        """Get VRFs."""
        return self._vrfs

    @cached_property
    def route_maps(self) -> Dict[str, RouteMap]:
        """Get route-map configuration."""
        if not hasattr(self, '_route_maps'):
            self._route_maps = self.get_route_maps()
        return self._route_maps

# logging.basicConfig(level=logging.DEBUG)
