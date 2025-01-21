"""Interface models for network devices."""
from .interface import Interface
from .vlan import VlanConfig
from .fex import FexConfig

__all__ = [
    'Interface',
    'VlanConfig',
    'FexConfig',
]