from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field


class Interface(BaseModel):
    """Base model for interface configuration."""
    name: str
    description: Optional[str] = None
    ip_network: Optional[Union[IPv4Network, IPv6Network]] = None
    ip_address: Optional[Union[IPv4Address, IPv6Address]] = None
    subnet_mask: Optional[str] = None
    enabled: bool = True
    speed: Optional[str] = None
    duplex: Optional[str] = None
    vrf: Optional[str] = None
    access_groups: Dict[str, str] = Field(default_factory=dict)
    switchport_mode: Optional[str] = None  # access, trunk, general, fex-fabric
    vlan: Optional[str] = None
    allowed_vlans: Optional[List[str]] = None
    fex_associate: Optional[int] = None
    
    # Nexus-specific fields
    channel_group: Optional[str] = None
    channel_mode: Optional[str] = None  # on, active, passive
    vpc: Optional[str] = None
    storm_control_broadcast: Optional[str] = None
    storm_control_multicast: Optional[str] = None
    stp_port_type: Optional[str] = None
    mtu: Optional[int] = None
    bandwidth: Optional[int] = None
    delay: Optional[int] = None
    storm_control: Dict[str, int] = Field(default_factory=dict)  # {"broadcast": 80, "multicast": 80, "unicast": 80}
    bpduguard: Optional[bool] = None
    portfast: Optional[bool] = None
    port_type: Optional[str] = None  # fabric, edge, network
    lacp_suspend_individual: Optional[bool] = None
    ospf_process_id: Optional[str] = None
    ospf_area: Optional[str] = None

    @property
    def mode(self) -> str | None:
        """Get interface mode."""
        return self.switchport_mode

    @mode.setter
    def mode(self, value: Optional[str]) -> None:
        """Set interface mode."""
        self.switchport_mode = value

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        if key in ['mode', 'switchport_mode']:
            return self.mode
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)
