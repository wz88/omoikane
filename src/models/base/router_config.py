from typing import Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict

from .interface import Interface
from .vrf import VrfConfig
from .vlan import VlanConfig
from .acl import Acl
from .prefix_list import PrefixList
from .route_map import RouteMap
from .bgp import BgpConfig
from .ospf import OspfConfig
from .snmp import SnmpConfig
from .ntp import NtpServer
from .logging import LoggingConfig
from .aaa import AaaConfig
from .fex import FexConfig
from .community_list import CommunityList
from .as_path import AsPathList
from .route import Route


class RouterConfig(BaseModel):
    """Base model for router configuration."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    hostname: Optional[str] = None
    interfaces: Dict[str, Interface] = Field(default_factory=dict)
    vrfs: Dict[str, VrfConfig] = Field(default_factory=dict)
    vlans: Dict[int, VlanConfig] = Field(default_factory=dict)
    acls: Dict[str, Acl] = Field(default_factory=dict)
    prefix_lists: Dict[str, PrefixList] = Field(default_factory=dict)
    route_maps: Dict[str, RouteMap] = Field(default_factory=dict)
    bgp: Optional[BgpConfig] = None
    ospf: Dict[str, OspfConfig] = Field(default_factory=dict)
    snmp: SnmpConfig = Field(default_factory=SnmpConfig)
    ntp_servers: List[NtpServer] = Field(default_factory=list)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    aaa: AaaConfig = Field(default_factory=AaaConfig)
    fex: Dict[str, FexConfig] = Field(default_factory=dict)
    community_lists: Dict[str, CommunityList] = Field(default_factory=dict)
    as_path_lists: Dict[str, AsPathList] = Field(default_factory=dict)
    routes: List[Route] = Field(default_factory=list)
