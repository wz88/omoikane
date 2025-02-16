import logging
from ipaddress import IPv4Address, ip_address
from typing import Dict, List, Optional, Tuple

from models.base.core.device import Device
from models.base.interfaces.interface import Interface
from models.base.routing_protocols.route import Route
from models.cisco_parser.nexus import CiscoNXOS
from models.cisco_parser.ios import CiscoIOS
from omoikane.errors import NoRouteFound

logging.basicConfig(level=logging.INFO)


class Omoikane:
    """Omoikane main class."""

    def __init__(self, device_list: List[Dict[str, str]]):
        self.devices: List[Device] = []
        self.device_list = device_list
        self.instantiate_devices()

    def instantiate_devices(self):
        """Instantiate the devices from the given list."""
        for device in self.device_list:
            hostname = device["hostname"]
            type = device["type"]
            rib = device["rib"]
            if type == "nxos":
                with open(device["config"], "r") as f:
                    config = f.read()
                with open(device["rib"], "r") as f:
                    rib = f.read()
                self.devices.append(CiscoNXOS(config, hostname, rib))
            elif type == "ios":
                with open(device["config"], "r") as f:
                    config = f.read()
                with open(device["rib"], "r") as f:
                    rib = f.read()
                self.devices.append(CiscoIOS(config, hostname, rib))

    @staticmethod
    def _get_best_route(ip: IPv4Address, device: Device) -> Optional[Route]:
        """Get the best route for the given IP address and device."""
        targeted_routes = []
        for route in device.routes:
            if ip in route.network:
                targeted_routes.append(route)
        if len(targeted_routes) > 0:
            return max(targeted_routes, key=lambda x: x.network.prefixlen)

    def _routing_lookup(self, ip: IPv4Address, device: Device) -> Optional[Device]:
        nh_route = None
        for route in device.routes:
            if ip in route.network:
                if type(route.next_hop) == IPv4Address:
                    if route.next_hop in route.network:
                        return route
                    nh_route = self._routing_lookup(route.next_hop, device)
                elif type(route.next_hop) == str:
                    return route
                nh_route = self._routing_lookup(route.next_hop, device)
        return nh_route

    def _search_in_interfaces(self, ip: IPv4Address) -> Optional[Device]:
        for device in self.devices:
            for interface in device.interfaces.values():
                if ip == interface.ip_address:
                    return device

    def get_owning_device(self, ip: str) -> Optional[Device]:
        ip_address: IPv4Address = IPv4Address(ip)
        owning_device: Optional[Device] = self._search_in_interfaces(ip_address)
        if owning_device is not None:
            return owning_device
        for device in self.devices:
            best_route = self._get_best_route(ip_address, device)
            if best_route is None:
                logging.info(NoRouteFound(f"No route found for {ip} in {device.hostname}'s routing table"))
                continue
            nh_route = self._routing_lookup(ip_address, device)
            if best_route == nh_route:
                return device

    def _get_neighboring_device(self, local_device: Device, local_interface: Interface, nh_ip: Optional[IPv4Address] = None) -> Optional[Tuple[Device, Interface]]:
        for device in [dev for dev in self.devices if dev != local_device]:
            for remote_interface in device.interfaces.values():
                if local_interface.ip_network == remote_interface.ip_network:
                    if nh_ip:
                        for dev_remote_interface in device.interfaces.values():
                            if dev_remote_interface.ip_address == nh_ip:
                                return device, remote_interface
                    else:
                        return device, remote_interface
        return (None, None)
        # while owning_device is None:
        #     for device in self.devices:
        #         if owning_device is not None:
        #             break
        #         while True:
        #             nh_route = self._routing_lookup(ip_address, device)
        #             if nh_route is None:
        #                 break
        #             if nh_route.next_hop == "Null0" or nh_route.egress_interface is None or nh_route.protocol in ["D", "L"]:
        #                 owning_device = device
        #                 break
        #             if nh_route.egress_interface is not None:
        #                 break
        #             if device == self.devices[-1]:
        #                 break
        #     break
        # return owning_device

    def discover_path(self, src_ip: str, dst_ip: str):
        reached_dst_device: bool = False
        dst_ip_address: IPv4Address = IPv4Address(dst_ip)
        src_device = self.get_owning_device(src_ip)
        dst_device = self.get_owning_device(dst_ip)
        import networkx as nx
        G = nx.MultiDiGraph()
        G.add_node(src_device.hostname, device=src_device)
        G.add_node(dst_device.hostname, device=dst_device)
        starting_device = src_device
        while not reached_dst_device:
            dst_best_route = self._get_best_route(dst_ip_address, starting_device)
            dst_nh_route = self._get_best_route(dst_best_route.next_hop, starting_device)
            dst_egress_interface_route = self._routing_lookup(dst_ip_address, starting_device)
            local_interface = starting_device.get_interface(dst_egress_interface_route.egress_interface)
            if dst_nh_route.egress_interface is not None:
                import pdb; pdb.set_trace()
                nh_device, nh_interface = self._get_neighboring_device(starting_device, local_interface, dst_nh_route.next_hop)
            print(f"{starting_device.hostname} ({local_interface.name}) -> ({nh_interface.name}) {nh_device.hostname}")
            starting_device = nh_device
            if nh_device == dst_device:
                reached_dst_device = True
        # for device in inner_devices:
        #     G.add_node(device.hostname, device=device)
