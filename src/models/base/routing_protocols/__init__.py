"""Routing protocol models for network devices."""
from .bgp import BgpConfig, BgpVrfConfig, BgpNeighbor
from .route import Route, RoutingTable
from .ospf import OspfConfig, OspfNetwork
from .vrf import VrfConfig

__all__ = [
    'BgpConfig',
    'BgpVrfConfig',
    'BgpNeighbor',
    'Route',
    'RoutingTable',
    'OspfConfig',
    'OspfNetwork',
    'VrfConfig',
]
