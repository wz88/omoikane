"""Models for network device configurations."""

from .cisco_parser.router import CiscoRouter, Interface, RouterConfig, VlanConfig

__all__ = ['CiscoRouter', 'RouterConfig', 'Interface', 'VlanConfig']
