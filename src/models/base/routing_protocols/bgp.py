from functools import cached_property
from ipaddress import IPv4Network
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, Field

from models.base.policy import RouteMap


class BgpNeighbor(BaseModel):
    """Base model for BGP neighbor configuration."""
    peer: str
    remote_as: Optional[int] = None
    inherit_peer: Optional[str] = None
    description: Optional[str] = None
    dynamic_capability: bool = False
    shutdown: bool = False
    route_maps: Dict[str, RouteMap|None] = Field(default_factory=dict)
    password: Optional[str] = None
    keepalive_timer: Optional[int] = None
    holdtime_timer: Optional[int] = None
    dscp: Optional[int] = None
    maximum_prefix: Optional[int] = None
    vrf: Optional[str] = None

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)


class BgpTimers(BaseModel):
    """Base model for BGP timers configuration."""
    keepalive_timer: Optional[int] = None
    holdtime_timer: Optional[int] = None
    best_path_limit: Optional[int] = None
    prefix_peer_wait: Optional[int] = None
    prefix_peer_timeout: Optional[int] = None


class BgpMaximumPaths(BaseModel):
    """Base model for BGP maximum paths configuration."""
    ebgp: Optional[int] = None
    ibgp: Optional[int] = None
    eibgp: Optional[int] = None
    local: Optional[int] = None
    mixed: Optional[int] = None


class BgpAdminDistance(BaseModel):
    """Base model for BGP admin distance configuration."""
    ebgp: Optional[int] = None
    ibgp: Optional[int] = None
    locally_originated: Optional[int] = None


class BgpNextHopTriggerDelay(BaseModel):
    """Base model for BGP next hop trigger delay configuration."""
    critical: Optional[int] = None
    non_critical: Optional[int] = None


class BgpAddressFamilyRedistribute(BaseModel):
    """Base model for BGP address family redistribute configuration."""
    protocol: Literal["direct", "static", "ospf"]
    instance_tag: Optional[str] = None
    route_map: Optional[str] = None


class BgpAddressFamily(BaseModel):
    """Base model for BGP address family configuration."""
    family: Literal["ipv4 unicast", "ipv6 unicast", "l2vpn evpn"]
    advertise: Optional[str] = None
    redistribute: List[BgpAddressFamilyRedistribute] = Field(default_factory=list)
    client_to_client_reflection: bool = False
    dampen_igp_metric: Optional[int] = None
    max_paths: Optional[BgpMaximumPaths] = None
    admin_distance: Optional[BgpAdminDistance] = None
    next_hop_trigger_delay: Optional[BgpNextHopTriggerDelay] = None
    next_hop_third_party: bool = False
    send_community: bool = False
    send_community_extended: bool = False
    route_maps: Dict[str, RouteMap|None] = Field(default_factory=dict)
    advertise_local_labeled_route: Optional[bool] = None
    advertise_local_labeled_route_safi_unicast: Optional[bool] = None
    soft_reconfiguration_inbound: Optional[Union[Literal["always"], bool]] = None

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)


class BgpTemplatePeerLocalAs(BaseModel):
    """Base model for BGP template peer local AS configuration."""
    local_as: Optional[int] = None
    no_prepend: bool = False
    replace_as: bool = False


class BgpTemplatePeer(BaseModel):
    """Base model for BGP template peer configuration."""
    name: str
    remote_as: Optional[int] = None
    local_as: Optional[BgpTemplatePeerLocalAs] = None
    dynamic_capability: bool = False
    update_source: Optional[str] = None
    keepalive_timer: Optional[int] = None
    holdtime_timer: Optional[int] = None
    dscp: Optional[int] = None
    address_families: Dict[str, BgpAddressFamily] = Field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)


class BgpVrfConfig(BaseModel):
    """Base model for BGP VRF configuration."""
    vrf: Optional[str] = None
    router_id: Optional[str] = None
    timers: Optional[BgpTimers] = None
    neighbors: Dict[str, BgpNeighbor] = Field(default_factory=dict)
    redistribute: List[str] = Field(default_factory=list)
    maximum_paths: Optional[int] = None
    address_families: Dict[str, BgpAddressFamily] = Field(default_factory=dict)
    networks: Dict[str, IPv4Network] = Field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)


class BgpConfig(BaseModel):
    """BGP configuration."""
    asn: Union[int, str]
    router_id: Optional[str] = None
    timers: Optional[BgpTimers] = None
    route_distinguisher: Optional[str] = None
    vrf_configs: Dict[str, BgpVrfConfig] = Field(default_factory=dict)
    networks: Dict[str, str] = Field(default_factory=dict)
    neighbors: Dict[str, BgpNeighbor] = Field(default_factory=dict)
    redistribute: List[str] = Field(default_factory=list)
    address_families: Dict[str, BgpAddressFamily] = Field(default_factory=dict)
    template_peers: Dict[str, BgpTemplatePeer] = Field(default_factory=dict)

    @cached_property
    def as_number(self) -> Union[int, str]:
        """Alias for asn for backward compatibility."""
        return self.asn

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)
