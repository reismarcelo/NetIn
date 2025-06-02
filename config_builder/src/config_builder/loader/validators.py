import re
from collections.abc import Callable, Iterator
from typing import Optional, Annotated, TypeVar
from ipaddress import IPv4Address, IPv4Network, IPv4Interface, IPv6Interface
from pathlib import Path
from pydantic import ValidationInfo, AfterValidator


#
# Reusable validators
#
_used_tags: set[str] = set()


def validate_tag(tag: str) -> str:
    if tag in _used_tags:
        raise ValueError(f'tag "{tag}" is already in use, tags must be unique.')
    if not re.match(r"[a-zA-Z0-9_-]+$", tag):
        raise ValueError(f'invalid tag "{tag}", tags can only have alphanumeric characters, "-" or "_".')

    _used_tags.add(tag)
    return tag


TagType = Annotated[str, AfterValidator(validate_tag)]


def validate_regex(regex: str) -> str:
    if regex is not None:
        try:
            re.compile(regex)
        except (re.error, TypeError):
            raise ValueError(f'"{regex}" is not a valid regular expression.') from None

    return regex


def validate_existing_file(filename: str) -> str:
    """ Validate whether filename exists
    """
    if not Path(filename).exists():
        raise ValueError(f'File "{filename}" not found.')

    return filename


def formatted_string(v: str, info: ValidationInfo) -> str:
    """
    Process v as a python formatted string
    :param v: Value to be validated
    :param info: A ValidationInfo instance with previously validated model fields
    :return: Expanded formatted string
    """
    try:
        return v.format(**info.data) if v is not None else v
    except KeyError as ex:
        raise ValueError(f"Variable not found: {ex}") from None


def constrained_ipv4_cidr(
    *,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    length: Optional[int] = None
) -> Callable[[IPv4Network], IPv4Network]:
    """
    Impose restrictions on an IPv4 address
    :param min_length: Prefix length must be greater than or equal to this value
    :param max_length: Prefix length must be less than or equal to this value
    :param length: Prefix length must be exactly equal to this value
    :return:
    """
    def validator(ipv4_network: IPv4Network) -> IPv4Network:
        if length is not None and ipv4_network.prefixlen != length:
            raise ValueError(f'IPv4 prefix length needs to be /{length}')
        if max_length is not None and ipv4_network.prefixlen > max_length:
            raise ValueError(f'IPv4 prefix length needs to be <= /{max_length}')
        if min_length is not None and ipv4_network.prefixlen < min_length:
            raise ValueError(f'IPv4 prefix length needs to be >= /{min_length}')

        return ipv4_network

    return validator


IPInterface = TypeVar('IPInterface', IPv4Interface, IPv6Interface)


def constrained_ip_interface(
    *,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    length: Optional[int] = None
) -> Callable[[IPInterface], IPInterface]:
    """
    Impose restrictions on an IP interface address (IPv4 or IPv6)
    :param min_length: Prefix length must be greater than or equal to this value
    :param max_length: Prefix length must be less than or equal to this value
    :param length: Prefix length must be exactly equal to this value
    :return:
    """
    def validator(ip_interface: IPInterface | None) -> IPInterface | None:
        if ip_interface is not None:
            prefix_length = int(ip_interface.with_prefixlen.split('/')[-1])
            if length is not None and prefix_length != length:
                raise ValueError(f'IPv{ip_interface.version} prefix length needs to be /{length}')
            if max_length is not None and prefix_length > max_length:
                raise ValueError(f'IPv{ip_interface.version} prefix length needs to be <= /{max_length}')
            if min_length is not None and prefix_length < min_length:
                raise ValueError(f'IPv{ip_interface.version} prefix length needs to be >= /{min_length}')

        return ip_interface

    return validator


def cidr_subnet(
        *,
        cidr_field: str,
        prefix_len: int = 24
) -> Callable[[IPv4Network, ValidationInfo], IPv4Network]:

    subnet_gen_map: dict[IPv4Network, Iterator[IPv4Network]] = {}

    def validator(subnet: IPv4Network, info: ValidationInfo) -> IPv4Network:
        if subnet is None:
            cidr = info.data.get(cidr_field, ...)
            if cidr is ...:
                raise ValueError(f"no cidr_field name {cidr_field}")
            if cidr is None:
                raise ValueError(f"{cidr_field} needs to be provided when subnet is not specified")
            try:
                subnet = next(subnet_gen_map.setdefault(cidr, cidr.subnets(new_prefix=prefix_len)))
            except StopIteration:
                raise ValueError(f"no more /{prefix_len} subnets available in CIDR {cidr}") from None

        return subnet

    return validator


def subnet_interface(
        *,
        subnet_field: str,
        host_index: int
) -> Callable[[IPv4Interface, ValidationInfo], IPv4Interface]:
    def validator(ipv4_interface: IPv4Interface, info: ValidationInfo) -> IPv4Interface:
        if ipv4_interface is None:
            subnet = info.data.get(subnet_field, ...)
            if subnet is ...:
                raise ValueError(f"no subnet_field name {subnet_field}")
            if subnet is None:
                raise ValueError(f"{subnet_field} was not set")
            try:
                ipv4_interface = IPv4Interface((list(subnet.hosts())[host_index], subnet.prefixlen))
            except IndexError:
                raise ValueError(f"host_index {host_index} is out of bounds for /{subnet.prefixlen}") from None

        return ipv4_interface

    return validator


def subnet_address(
        *,
        subnet_field: str,
        host_index: int
) -> Callable[[IPv4Address, ValidationInfo], IPv4Address]:
    def validator(ipv4_address: IPv4Address, info: ValidationInfo) -> IPv4Address:
        if ipv4_address is None:
            subnet = info.data.get(subnet_field, ...)
            if subnet is ...:
                raise ValueError(f"no subnet_field name {subnet_field}")
            if subnet is None:
                raise ValueError(f"{subnet_field} was not set")
            try:
                ipv4_address = list(subnet.hosts())[host_index]
            except IndexError:
                raise ValueError(f"host_index {host_index} is out of bounds for /{subnet.prefixlen}") from None

        return ipv4_address

    return validator


