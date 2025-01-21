from functools import cached_property
from typing import Any, Dict, Optional
from abc import ABC, abstractmethod

from ciscoconfparse2 import CiscoConfParse

from models.base.interfaces.interface import Interface


class Device(ABC):
    """Base class for network devices."""

    def __init__(self, config: Optional[str] = None, hostname: Optional[str] = None):
        """Initialize device."""
        self.config = config
        self._hostname = hostname
        self.interfaces: Dict[str, Interface] = {}
        if config:
            self.parse_config()

    @cached_property
    def parse(self) -> Optional[CiscoConfParse]:
        ...

    @abstractmethod
    def parse_config(self, config: str) -> None:
        """Parse configuration text."""
        raise NotImplementedError

    @cached_property
    @abstractmethod
    def interfaces(self) -> Dict[str, Any]:
        """Return all interfaces configured on the device."""
        ...

    @property
    def hostname(self) -> Optional[str]:
        return self._hostname

    @hostname.setter
    def hostname(self, value: Optional[str]):
        self._hostname = value

    def __str__(self) -> str:
        """Return string representation."""
        return f"{self.__class__.__name__}(hostname={self.hostname}, interfaces={len(self.interfaces)})"

    def __repr__(self) -> str:
        """Return string representation."""
        return self.__str__()