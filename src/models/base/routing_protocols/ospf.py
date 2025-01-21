from ipaddress import IPv4Network
from typing import Dict, List, Optional, Set, Union, Any
from pydantic import BaseModel, Field

from models.base.interfaces.interface import Interface


class OspfNetwork(BaseModel):
    """Base model for OSPF network."""
    network: Optional[IPv4Network] = None
    area: Optional[Union[int, str]] = None
    wildcard: Optional[str] = None
    metric: Optional[int] = None

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)


class OspfDefaultInformation(BaseModel):
    originate: bool = False
    always: bool = False


class OspfSpfThrottlingTimers(BaseModel):
    initial_delay: Optional[int] = None
    wait_time: Optional[int] = None
    max_wait_time: Optional[int] = None


class OspfLsaThrottlingTimers(BaseModel):
    initial_delay: Optional[int] = None
    wait_time: Optional[int] = None
    max_wait_time: Optional[int] = None


class OspfTimers(BaseModel):
    spf_throttling_timers: Optional[OspfSpfThrottlingTimers] = None
    lsa_group_pacing: Optional[int] = None
    lsa_arrival: Optional[int] = None
    lsa_throttling_timers: Optional[OspfLsaThrottlingTimers] = None


class OspfDiscardRoute(BaseModel):
    internal: Optional[bool] = None
    external: Optional[bool] = None


class OspfVrfConfig(BaseModel):
    vrf: Optional[str] = None
    bidirectional_forwarding_detection: bool = False
    router_id: Optional[str] = None
    default_information: OspfDefaultInformation = Field(default_factory=OspfDefaultInformation)
    graceful_restart: bool = False
    graceful_restart_grace_period: Optional[int] = None
    max_metric_lsa_on_startup: Optional[int] = None
    timers: Optional[OspfTimers] = None
    admin_distance: Optional[int] = None
    max_paths: Optional[int] = None
    reference_bandwidth: Optional[int] = None
    table_map_filter: Optional[str] = None
    discard_route: Optional[OspfDiscardRoute] = None
    networks: List[OspfNetwork] = Field(default_factory=list)
    areas: Set[str] = Field(default_factory=set)
    interfaces: List[Interface] = Field(default_factory=list)

class OspfConfig(BaseModel):
    """Base model for OSPF configuration."""
    instance_tag: Union[int, str]
    router_id: Optional[str] = None
    graceful_restart: bool = False
    graceful_restart_grace_period: Optional[int] = None
    max_metric_lsa_on_startup: Optional[int] = None
    timers: Optional[OspfTimers] = None
    admin_distance: Optional[int] = None
    max_paths: Optional[int] = None
    reference_bandwidth: Optional[int] = None
    discard_route: Optional[OspfDiscardRoute] = None
    networks: List[OspfNetwork] = Field(default_factory=list)
    passive_interfaces: Set[str] = Field(default_factory=set)
    area_auth: Dict[str, str] = Field(default_factory=dict)
    areas: Set[str] = Field(default_factory=set)
    default_information: Dict[str, bool] = Field(default_factory=lambda: {"originate": False, "always": False})
    timers: Optional[OspfTimers] = None
    vrf_configs: Dict[str, OspfVrfConfig] = Field(default_factory=dict)
    interfaces: List[Interface] = Field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        """Make the model behave like a dictionary."""
        return getattr(self, key)
