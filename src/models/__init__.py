"""Models for network device configurations."""
from models.cisco_parser.ios import CiscoIOS
from models.cisco_parser.nexus import CiscoNXOS

__all__ = ['CiscoIOS', 'CiscoNXOS']
