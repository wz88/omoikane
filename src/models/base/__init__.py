"""Base models for network devices."""
from models.base.policy.acl import Ipv4Acl, Ipv6Acl
from models.base.policy.route_map import RouteMap
from models.base.policy.prefix_list import PrefixList
from models.base.policy.community_list import CommunityList
from models.base.policy.as_path import AsPathList
from models.base.interfaces.interface import Interface
from models.base.interfaces.vlan import VlanConfig
from models.base.interfaces.fex import FexConfig
from models.base.routing_protocols.bgp import BgpConfig
from models.base.routing_protocols.ospf import OspfConfig
from models.base.routing_protocols.route import Route
from models.base.system.aaa import AaaConfig
from models.base.system.logging import LoggingConfig
from models.base.system.snmp import SnmpConfig
from models.base.system.ntp import NtpConfig

__all__ = [
    'Ipv4Acl',
    'Ipv6Acl',
    'Route',
    'RouteMap',
    'PrefixList',
    'CommunityList',
    'AsPathList',
    'Interface',
    'VlanConfig',
    'FexConfig',
    'BgpConfig',
    'OspfConfig',
    'AaaConfig',
    'LoggingConfig',
    'SnmpConfig',
    'NtpConfig',
]