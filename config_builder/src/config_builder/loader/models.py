from typing import Optional, Annotated, Any
from ipaddress import IPv4Address, IPv4Interface, IPv6Interface, IPv6Address
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, AfterValidator, model_validator
from .validators import TagType, constrained_ip_interface


#
# Base Models
#
class ConfigBaseModel(BaseModel):
    model_config = ConfigDict(extra='forbid', use_enum_values=True)


InterfaceName = Annotated[str, StringConstraints(pattern=r'^[a-zA-Z]+\d(?:/\d+)+$')]

StringNoSpaces = Annotated[str, StringConstraints(pattern=r'^\S+$')]

RouteDistinguisher = Annotated[str, StringConstraints(pattern=r'^(?:\d+\.\d+\.\d+\.\d+|\d+):\d+$')]


#
# Interfaces block
#
class InterfaceModel(ConfigBaseModel):
    description: Optional[str] = None
    ipv4_address: IPv4Interface
    ipv6_address: IPv6Interface
    router_isis: bool = False
    router_ospf: bool = False
    asbr_ipv4_route: bool = False
    vrf: Optional[str] = None


class SubInterfaceModel(InterfaceModel):
    ipv4_address: Annotated[Optional[IPv4Interface], AfterValidator(constrained_ip_interface(min_length=30))] = None
    ipv6_address: Annotated[Optional[IPv6Interface], AfterValidator(constrained_ip_interface(min_length=126))] = None
    sub_interface_id: Annotated[int, Field(ge=0)]

    @model_validator(mode='after')
    def validate_asbr_ipv4_route(self) -> 'SubInterfaceModel':
        if self.asbr_ipv4_route and self.ipv4_address is None:
            raise ValueError('"ipv4_address" is required when "asbr_ipv4_route" is true')

        return self


class BundleInterfacesModel(InterfaceModel):
    ipv4_address: Annotated[Optional[IPv4Interface], AfterValidator(constrained_ip_interface(length=31))] = None
    ipv6_address: Annotated[Optional[IPv6Interface], AfterValidator(constrained_ip_interface(length=127))] = None
    bundle_id: Annotated[int, Field(ge=0)]
    member_interfaces: list[InterfaceName]
    sub_interfaces: Annotated[list[SubInterfaceModel], Field(default_factory=list)]

    @model_validator(mode='after')
    def validate_address_mandatory(self) -> 'BundleInterfacesModel':
        if not self.sub_interfaces and not (self.ipv4_address and self.ipv6_address):
            raise ValueError('"ipv4_address" and "ipv6_address" must be defined when sub_interfaces are not used')
        if self.asbr_ipv4_route and self.ipv4_address is None:
            raise ValueError('"ipv4_address" is required when "asbr_ipv4_route" is true')

        return self


#
# Routing IGP block
#
class Loopback0Model(ConfigBaseModel):
    ipv4_address: Annotated[IPv4Interface, AfterValidator(constrained_ip_interface(length=32))]
    ipv6_address: Annotated[Optional[IPv6Interface], AfterValidator(constrained_ip_interface(length=128))] = None
    prefix_sid: Annotated[int, Field(ge=0, le=1048575)]


class ISISModel(ConfigBaseModel):
    process_id: StringNoSpaces
    net: Annotated[str, Field(pattern=r'^[a-fA-F0-9]{2}(\.[a-fA-F0-9]{4}){3,9}\.[a-fA-F0-9]{2}$')]


class OSPFModel(ConfigBaseModel):
    process_id: StringNoSpaces


class RoutingIGPModel(ConfigBaseModel):
    loopback_0: Optional[Loopback0Model] = None
    isis: Optional[ISISModel] = None
    ospf: Optional[OSPFModel] = None


#
# Routing BGP block
#
class EbgpPeer(ConfigBaseModel):
    description: str
    remote_as: Annotated[int, Field(ge=0)]
    route_policy_in: StringNoSpaces
    route_policy_out: StringNoSpaces
    default_originate: bool = False
    allowas_in: bool = False
    neighbor_group: Optional[StringNoSpaces] = None
    address_family_vpnv4: bool = False


class Ipv4EbgpPeer(EbgpPeer):
    ipv4_address: IPv4Address


class Ipv6EbgpPeer(EbgpPeer):
    ipv6_address: IPv6Address


class Ipv4IbgpPeer(ConfigBaseModel):
    description: str
    ipv4_address: IPv4Address
    neighbor_group: Optional[StringNoSpaces] = None


class BgpVrf(ConfigBaseModel):
    name: StringNoSpaces
    rd: RouteDistinguisher
    bgp_pic: bool = False
    ipv4_ebgp_peers: Optional[list[Ipv4EbgpPeer]] = None
    ipv6_ebgp_peers: Optional[list[Ipv6EbgpPeer]] = None


class RoutingBGPModel(ConfigBaseModel):
    local_as: Annotated[int, Field(ge=0)]
    ipv4_ibgp_peers: Optional[list[Ipv4IbgpPeer]] = None
    ipv4_ebgp_peers: Optional[list[Ipv4EbgpPeer]] = None
    ipv6_ebgp_peers: Optional[list[Ipv6EbgpPeer]] = None
    vrfs: Optional[list[BgpVrf]] = None


#
# Breakouts block
#
OpticsInterfaceName = Annotated[str, StringConstraints(pattern=r'^Optics\d(?:/\d+)+$')]
ControllerPortName = Annotated[str, StringConstraints(pattern=r'^0/\d+/CPU0$')]


class BreakoutModel(ConfigBaseModel):
    location: OpticsInterfaceName | ControllerPortName
    port: Optional[Annotated[int, Field(ge=0, le=99)]] = None

    @model_validator(mode='after')
    def validate_port_mandatory(self) -> 'BreakoutModel':
        is_optics = self.location.startswith('Optics')
        if is_optics and self.port is not None:
            raise ValueError('"port" cannot be defined for Optics location names')
        if not is_optics and self.port is None:
            raise ValueError('"port" is required for line-card based location')

        return self


class BreakoutsModel(ConfigBaseModel):
    breakout_4x100: Annotated[list[BreakoutModel], Field(default_factory=list)]
    breakout_1x100: Annotated[list[BreakoutModel], Field(default_factory=list)]
    breakout_4x10: Annotated[list[BreakoutModel], Field(default_factory=list)]

    @model_validator(mode='after')
    def validate_unique_ports(self) -> 'BreakoutsModel':
        breakout_set = set()
        for breakout in self.breakout_4x100 + self.breakout_1x100 + self.breakout_4x10:
            if (breakout.location, breakout.port) in breakout_set:
                port = f' port {breakout.port}' if breakout.port else ''
                raise ValueError(f'{breakout.location}{port} is already being used on this device')
            breakout_set.add((breakout.location, breakout.port))

        return self


#
# OOB Management block
#
ManagementInterfaceName = Annotated[str, StringConstraints(pattern=r'^MgmtEth0/(?:RP|RSP)[0-9]/CPU0/[0-9]$')]


class ManagementInterfaceModel(ConfigBaseModel):
    name: ManagementInterfaceName
    ipv4_address: IPv4Interface


class ManagementOOBModel(ConfigBaseModel):
    vip_ipv4_address: IPv4Interface
    default_gateway_ipv4_address: IPv4Address
    interfaces: list[ManagementInterfaceModel]

    @model_validator(mode='after')
    def validate_same_subnet(self) -> 'ManagementOOBModel':
        if not all(interface.ipv4_address.network == self.vip_ipv4_address.network for interface in self.interfaces):
            raise ValueError('Management VIP must be on the same subnet as all MgmtEth interfaces')

        return self


#
# BFD block
#
LineCardName = Annotated[str, StringConstraints(pattern=r'^\d(?:/\d+)+/CPU0$')]


class BFDModel(ConfigBaseModel):
    multipath_lcs: list[LineCardName]


#
# NTP block
#
class NTPModel(ConfigBaseModel):
    vrf_ipv4_servers: list[IPv4Address]


#
# SNMP block
#
class TrapHostModel(ConfigBaseModel):
    address: IPv4Address
    community: StringNoSpaces


class SNMPv3UserModel(ConfigBaseModel):
    username: StringNoSpaces
    authentication_md5: StringNoSpaces
    encryption_aes128: StringNoSpaces


class SNMPModel(ConfigBaseModel):
    trap_hosts: list[TrapHostModel]
    snmp_v3_users: list[SNMPv3UserModel]


#
# Local accounts block
#
class UserAccountModel(ConfigBaseModel):
    username: StringNoSpaces
    secret: Annotated[str, Field(pattern=r'^\$6\$')]


class LocalUsersModel(ConfigBaseModel):
    admins: list[UserAccountModel]
    operators: Optional[list[UserAccountModel]] = None
    observers: Optional[list[UserAccountModel]] = None


class HTTPProxyModel(ConfigBaseModel):
    proxy: StringNoSpaces
    port: Annotated[int, Field(ge=1, le=65535)] = 80


#
# groups block
#
class VarsModel(ConfigBaseModel):
    nso_ned_id: Optional[StringNoSpaces] = None
    syslog_ipv4_servers: Optional[list[IPv4Address]] = None
    dns_ipv4_servers: Optional[list[IPv4Address]] = None
    dns_vrf_ipv4_servers: Optional[list[IPv4Address]] = None
    local_users: Optional[LocalUsersModel] = None
    snmp: Optional[SNMPModel] = None
    ntp: Optional[NTPModel] = None
    http_proxy: Optional[HTTPProxyModel] = None
    bfd: Optional[BFDModel] = None
    management_oob: Optional[ManagementOOBModel] = None
    breakouts: Optional[BreakoutsModel] = None
    routing_igp: Optional[RoutingIGPModel] = None
    routing_bgp: Optional[RoutingBGPModel] = None
    bundle_interfaces: Annotated[list[BundleInterfacesModel], Field(default_factory=list)]


class DeviceModel(ConfigBaseModel):
    name: StringNoSpaces
    vars: Optional[VarsModel] = None


class GroupModel(ConfigBaseModel):
    # Restriction of minimum of 3 characters comes from BPA REFd
    name: Annotated[str, StringConstraints(pattern=r'^\S+$', min_length=3)]
    vars: Optional[VarsModel] = None
    devices: list[DeviceModel]


#
# targets_config block
#
class JinjaTargetModel(ConfigBaseModel):
    tag: TagType
    description: str
    template: str
    filename: str
    is_global: bool = False


class JinjaRendererModel(ConfigBaseModel):
    templates_dir: str
    targets: list[JinjaTargetModel]


class TargetsConfigModel(ConfigBaseModel):
    jinja_renderer: JinjaRendererModel


#
# metadata config block
#
class MetadataModel(ConfigBaseModel):
    environment: Annotated[str, Field(pattern=r'^[^_\s]+$')]


#
# Top-level ConfigModel
#
class RenderingVarsModel(ConfigBaseModel):
    global_vars: Optional[VarsModel] = None
    groups: list[GroupModel]
    
    @model_validator(mode='after')
    def propagate_global_name(self) -> 'RenderingVarsModel':
        """
        Propagate global name to VarsModel for IP uniqueness validation.
        """
        from .validators import _ipv4_addresses, _ipv6_addresses
        _ipv4_addresses.clear()
        _ipv6_addresses.clear()
        
        if self.global_vars:
            setattr(self.global_vars, '_device_name', 'global')
            
        return self
        
        def collect_ip_addresses(device_name: str, vars_model: VarsModel):
            """
            Collect and validate IP addresses from a VarsModel instance.
            
            Args:
                device_name: Name of the device or scope (e.g., 'global', 'group-X')
                vars_model: The VarsModel instance to collect IP addresses from
            
            Raises:
                ValueError: If a duplicate IP address is found
            """
            if vars_model is None:
                return
                
            # Bundle interfaces
            for bundle in vars_model.bundle_interfaces:
                if bundle.ipv4_address:
                    ip_str = str(bundle.ipv4_address.ip)
                    if ip_str in ipv4_addresses:
                        existing = ipv4_addresses[ip_str]
                        raise ValueError(f'IPv4 address {ip_str} is assigned to multiple interfaces: '
                                       f'{existing[0]} {existing[1]}{existing[2]} and '
                                       f'{device_name} Bundle-Ether{bundle.bundle_id}')
                    ipv4_addresses[ip_str] = (device_name, 'Bundle-Ether', bundle.bundle_id)
                
                if bundle.ipv6_address:
                    ip_str = str(bundle.ipv6_address.ip)
                    if ip_str in ipv6_addresses:
                        existing = ipv6_addresses[ip_str]
                        raise ValueError(f'IPv6 address {ip_str} is assigned to multiple interfaces: '
                                       f'{existing[0]} {existing[1]}{existing[2]} and '
                                       f'{device_name} Bundle-Ether{bundle.bundle_id}')
                    ipv6_addresses[ip_str] = (device_name, 'Bundle-Ether', bundle.bundle_id)
                
                # Sub-interfaces
                for sub in bundle.sub_interfaces:
                    if sub.ipv4_address:
                        ip_str = str(sub.ipv4_address.ip)
                        if ip_str in ipv4_addresses:
                            existing = ipv4_addresses[ip_str]
                            raise ValueError(f'IPv4 address {ip_str} is assigned to multiple interfaces: '
                                           f'{existing[0]} {existing[1]}{existing[2]} and '
                                           f'{device_name} Bundle-Ether{bundle.bundle_id}.{sub.sub_interface_id}')
                        ipv4_addresses[ip_str] = (device_name, 'Bundle-Ether', f'{bundle.bundle_id}.{sub.sub_interface_id}')
                    
                    if sub.ipv6_address:
                        ip_str = str(sub.ipv6_address.ip)
                        if ip_str in ipv6_addresses:
                            existing = ipv6_addresses[ip_str]
                            raise ValueError(f'IPv6 address {ip_str} is assigned to multiple interfaces: '
                                           f'{existing[0]} {existing[1]}{existing[2]} and '
                                           f'{device_name} Bundle-Ether{bundle.bundle_id}.{sub.sub_interface_id}')
                        ipv6_addresses[ip_str] = (device_name, 'Bundle-Ether', f'{bundle.bundle_id}.{sub.sub_interface_id}')
            
            # Loopback interfaces
            if vars_model.routing_igp and vars_model.routing_igp.loopback_0:
                loopback = vars_model.routing_igp.loopback_0
                if loopback.ipv4_address:
                    ip_str = str(loopback.ipv4_address.ip)
                    if ip_str in ipv4_addresses:
                        existing = ipv4_addresses[ip_str]
                        raise ValueError(f'IPv4 address {ip_str} is assigned to multiple interfaces: '
                                       f'{existing[0]} {existing[1]}{existing[2]} and '
                                       f'{device_name} Loopback0')
                    ipv4_addresses[ip_str] = (device_name, 'Loopback', 0)
                
                if loopback.ipv6_address:
                    ip_str = str(loopback.ipv6_address.ip)
                    if ip_str in ipv6_addresses:
                        existing = ipv6_addresses[ip_str]
                        raise ValueError(f'IPv6 address {ip_str} is assigned to multiple interfaces: '
                                       f'{existing[0]} {existing[1]}{existing[2]} and '
                                       f'{device_name} Loopback0')
                    ipv6_addresses[ip_str] = (device_name, 'Loopback', 0)
            
            # Management interfaces
            if vars_model.management_oob:
                mgmt = vars_model.management_oob
                if mgmt.vip_ipv4_address:
                    vip_ip = str(mgmt.vip_ipv4_address.ip)
                    if vip_ip in ipv4_addresses:
                        existing = ipv4_addresses[vip_ip]
                        raise ValueError(f'IPv4 address {vip_ip} is assigned to multiple interfaces: '
                                       f'{existing[0]} {existing[1]}{existing[2]} and '
                                       f'{device_name} Management-VIP')
                    ipv4_addresses[vip_ip] = (device_name, 'Management-VIP', '')
                
                # Individual management interfaces
                for mgmt_int in mgmt.interfaces:
                    if mgmt_int.ipv4_address:
                        ip_str = str(mgmt_int.ipv4_address.ip)
                        if ip_str in ipv4_addresses:
                            existing = ipv4_addresses[ip_str]
                            raise ValueError(f'IPv4 address {ip_str} is assigned to multiple interfaces: '
                                           f'{existing[0]} {existing[1]}{existing[2]} and '
                                           f'{device_name} {mgmt_int.name}')
                        ipv4_addresses[ip_str] = (device_name, mgmt_int.name, '')
        
        if self.global_vars:
            collect_ip_addresses('global', self.global_vars)
        
        for group in self.groups:
            if group.vars:
                collect_ip_addresses(f'group-{group.name}', group.vars)
            
            for device in group.devices:
                if device.vars:
                    collect_ip_addresses(device.name, device.vars)
        
        return self


class ConfigModel(RenderingVarsModel):
    metadata: MetadataModel
    targets_config: TargetsConfigModel
    


#
# Auxiliary functions that work on the models
#
def merged_rendering_vars(global_vars: dict[str, Any], groups: list[GroupModel]) -> RenderingVarsModel:
    def merged_device_vars(group: GroupModel, device: DeviceModel) -> DeviceModel:
        group_vars = group.vars.model_dump(by_alias=True, exclude_none=True) if group.vars is not None else {}
        device_vars = device.vars.model_dump(by_alias=True, exclude_none=True) if device.vars is not None else {}
        return DeviceModel(name=device.name, vars=VarsModel(**dict(global_vars | group_vars | device_vars)))

    return RenderingVarsModel(
        global_vars=VarsModel(**global_vars),
        groups=[
            GroupModel(name=group.name, devices=[merged_device_vars(group, device) for device in group.devices])
            for group in groups
        ]
    )
