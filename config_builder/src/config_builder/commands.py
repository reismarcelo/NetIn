import argparse
import logging
import json
import re
import yaml
from pathlib import Path
from ipaddress import IPv4Interface, IPv4Network, IPv4Address
from typing import Any
from collections.abc import Iterable
from .loader import load_yaml, LoaderException, ConfigModel, merged_rendering_vars
from jinja2 import (Environment, FileSystemLoader, select_autoescape, TemplateNotFound, StrictUndefined,
                    UndefinedError, TemplateSyntaxError)


#
# Custom Jinja2 filters
#
class FilterError(ValueError):
    """ Filter processing exception """
    pass


def read_file_filter(left_value: str) -> str:
    with open(left_value) as f:
        return f.read()


def ipv4_address_filter(left_value: IPv4Interface | str, attribute: str = 'ip') -> str:
    try:
        interface = left_value if isinstance(left_value, IPv4Interface) else IPv4Interface(left_value)
        return str(getattr(interface, attribute))

    except (ValueError, AttributeError) as ex:
        raise FilterError(ex) from None


def ipv4_netmask_filter(left_value: IPv4Interface | str) -> str:
    return ipv4_address_filter(left_value, attribute='with_netmask').split('/')[1]


def ipv4_subnet_filter(left_value: IPv4Network | str, prefix_len: int, subnet_index: int) -> IPv4Network:
    try:
        network = left_value if isinstance(left_value, IPv4Network) else IPv4Network(left_value)
        return list(network.subnets(new_prefix=prefix_len))[subnet_index]

    except IndexError:
        raise FilterError(
            f"subnet_index {subnet_index} is out of bounds for /{prefix_len} subnets in {left_value}") from None
    except ValueError as ex:
        raise FilterError(ex) from None


def ipv4_subnet_host_filter(left_value: IPv4Network | str, host_index: int) -> IPv4Interface:
    try:
        subnet = left_value if isinstance(left_value, IPv4Network) else IPv4Network(left_value)
    except ValueError as ex:
        raise FilterError(ex) from None

    try:
        return IPv4Interface((list(subnet.hosts())[host_index], subnet.prefixlen))
    except IndexError:
        raise FilterError(
            f"host_index {host_index} is out of bounds for /{subnet.prefixlen}") from None


def to_yaml_filter(left_value: dict[str, Any]) -> str:
    try:
        return yaml.safe_dump(json.loads(json.dumps(left_value, default=str)))
    except yaml.YAMLError as ex:
        raise FilterError(f"invalid YAML '{ex}'") from None


def interface_field_filter(left_value: str, selector: str = 'id') -> str:
    try:
        # Interface format: HundredGigE0/0/0/8/2
        match = re.match(r'(?P<type>[a-zA-Z]+)\s?(?P<id>\d/\S+)', left_value)
        if match:
            return match.group(selector)
        # Interface format: 0/0/0/8/2
        match = re.match(r'(?P<id>\d/\S+)', left_value)
        if match:
            return match.group(selector)
    except IndexError:
        raise FilterError(f"invalid interface filter selector: '{selector}' for '{left_value}'") from None

    raise FilterError(f"invalid interface filter interface: '{left_value}'")


def camel_filter(left_value: str) -> str:
    if len(left_value) == 0:
        raise FilterError("invalid value for camel filter, empty string provided")

    return f'{left_value[0].lower()}{left_value[1:]}'


def one_item_filter[V](left_value: Iterable[V]) -> Iterable[V]:
    for item in left_value:
        yield item
        break


def find_next_hop_filter(left_value: IPv4Interface | str, next_hop_index: int = 1) -> IPv4Address:
    try:
        ipv4_interface = left_value if isinstance(left_value, IPv4Interface) else IPv4Interface(left_value)
    except ValueError as ex:
        raise FilterError(ex) from None

    next_hop_list = [ipv4_host for ipv4_host in ipv4_interface.network.hosts() if ipv4_host != ipv4_interface.ip]
    if len(next_hop_list) == 0:
        raise FilterError(f"no next hop available for {left_value}")
    if next_hop_index < 1:
        raise FilterError(f"next_hop_index must be greater than 0, value: {next_hop_index}")
    if next_hop_index > len(next_hop_list):
        raise FilterError(f"next_hop_index is invalid, only {len(next_hop_list)} "
                          f"{'next-hop is' if len(next_hop_list) == 1 else 'next-hops are'} available.")

    return next_hop_list[next_hop_index - 1]


def format_route_policy_filter(left_value: str, condition: bool = True) -> str:
    if not condition:
        return left_value

    def replacement(match: re.Match) -> str:
        return (f'{match.group('prefix')}\n'
                f'  "  {"\\r\\n".join(match.group('content').strip().splitlines())}\\r\\n"\n'
                f'  {match.group('suffix')}')

    formatted_left_value, num_subs = re.subn(
        r"^(?P<prefix>route-policy\s+\S+)(?P<content>.+?)(?P<suffix>end-policy)", replacement, left_value,
        flags=re.MULTILINE | re.DOTALL
    )
    if num_subs == 0:
        raise FilterError("no route-policy was found in format_route_policy filter block")

    return formatted_left_value


def format_class_map_filter(left_value: str, condition: bool = True) -> str:
    if not condition:
        return left_value

    def line_replacement(match: re.Match) -> str:
        return f"{match.group('prefix')}{','.join(match.group('dscp').split())}"

    def block_replacement(match: re.Match) -> str:
        updated = re.sub(
            r"(?P<prefix>match dscp\s+)(?P<dscp>\S+(?:\s+\S+)*)", line_replacement, match.group('content'),
            flags=re.MULTILINE | re.DOTALL
        )
        return (f'{match.group('prefix')}\n'
                f' {"\n ".join(line.strip() for line in updated.strip().splitlines())}\n'
                f' {match.group('suffix')}')

    formatted_left_value, num_subs = re.subn(
        r"^(?P<prefix>class-map\s+\S+\s+\S+)(?P<content>.+?)(?P<suffix>end-class-map)", block_replacement, left_value,
        flags=re.MULTILINE | re.DOTALL
    )
    if num_subs == 0:
        raise FilterError("no class-map was found in format_class_map filter block")

    return formatted_left_value


#
# Custom Jinja2 tests
#
class TestError(ValueError):
    """ Test processing exception """
    pass


def matches_test(left_value: str, regex: str) -> bool:
    try:
        return re.search(regex, left_value) is not None
    except re.PatternError as ex:
        raise TestError(f'invalid regex: {ex}') from None


#
# Selectors
#
def match_tag(desired_tag: str | None, tag: str) -> bool:
    return desired_tag is None or desired_tag == tag


def match_regex(regex: str | None, value: str) -> bool:
    return regex is None or re.search(regex, value)


#
# Command implementation
#

def render_cmd(cli_args: argparse.Namespace) -> None:
    """
    Render configuration files
    :param cli_args: Parsed CLI args
    :return: None
    """
    logger = logging.getLogger('config_builder.commands.render_cmd')

    try:
        config_obj = load_yaml(ConfigModel, 'config', cli_args.configuration)
    except LoaderException as ex:
        logger.critical(f"Failed loading config file: {ex}")
        return

    jinja_env = Environment(
        autoescape=select_autoescape(
            disabled_extensions=('txt', 'j2',),
            default_for_string=True,
            default=True
        ),
        loader=FileSystemLoader(config_obj.targets_config.jinja_renderer.templates_dir),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    jinja_env.filters.update({
        'read_file': read_file_filter,
        'ipv4_address': ipv4_address_filter,
        'ipv4_netmask': ipv4_netmask_filter,
        'ipv4_subnet': ipv4_subnet_filter,
        'ipv4_subnet_host': ipv4_subnet_host_filter,
        'to_yaml': to_yaml_filter,
        'interface_field': interface_field_filter,
        'camel': camel_filter,
        'one_item': one_item_filter,
        'find_next_hop': find_next_hop_filter,
        'format_route_policy': format_route_policy_filter,
        'format_class_map': format_class_map_filter
    })
    jinja_env.tests.update({
        'matches': matches_test,
    })

    if config_obj.global_vars is not None:
        global_vars = config_obj.global_vars.model_dump(by_alias=True, exclude_none=True)
    else:
        global_vars = {}

    jinja_targets = config_obj.targets_config.jinja_renderer.targets
    selected_non_global_items = (
        (target, group, device)
        for target in jinja_targets if not target.is_global and match_tag(cli_args.tag, target.tag)
        for group in config_obj.groups if match_regex(cli_args.groups, group.name)
        for device in group.devices if match_regex(cli_args.devices, device.name)
    )
    for target, group, device in selected_non_global_items:
        logger.info(f"Rendering {target.description}: Group: {group.name}, Device: {device.name}")
        iteration_vars = {"group": group.name, "device": device.name}
        target_filename = target.filename.format(**iteration_vars)
        target_template = target.template.format(**iteration_vars)

        target_path = Path(target_filename)
        if not cli_args.update and target_path.exists():
            logger.info(f"Skipped '{target_filename}' target, file already exists")
            continue

        try:
            group_vars = group.vars.model_dump(by_alias=True, exclude_none=True) if group.vars is not None else {}
            device_vars = device.vars.model_dump(by_alias=True, exclude_none=True) if device.vars is not None else {}

            rendition = jinja_env.get_template(target_template).render(
                global_vars | group_vars | device_vars | iteration_vars
            )

            target_path.parent.mkdir(parents=True, exist_ok=True)
            with open(target_path, 'w') as target_file:
                target_file.write(rendition)

            logger.info(f"Done {target.description}: '{target_template}' -> '{target_filename}'")

        except TemplateNotFound as ex:
            logger.debug(f"Template file not found, skipping: {ex}")
        except TemplateSyntaxError as ex:
            logger.critical(f"Template '{target_template}' syntax error: {ex}")
        except UndefinedError as ex:
            logger.critical(f"Template '{target_template}' error: {ex}")
        except FilterError as ex:
            logger.critical(f"Template '{target_template}' Jinja2 filter error: {ex}")
        except TestError as ex:
            logger.critical(f"Template '{target_template}' Jinja2 test error: {ex}")

    selected_global_items = (
        target for target in jinja_targets if target.is_global and match_tag(cli_args.tag, target.tag)
    )
    for target in selected_global_items:
        logger.info(f"Rendering {target.description}")

        target_filename = target.filename.format(environment=config_obj.metadata.environment)
        target_path = Path(target_filename)
        if not cli_args.update and target_path.exists():
            logger.info(f"Skipped '{target_filename}' target, file already exists")
            continue

        try:
            rendition = jinja_env.get_template(target.template).render(
                merged_rendering_vars(global_vars, config_obj.groups).model_dump(by_alias=True, exclude_none=True)
            )

            target_path.parent.mkdir(parents=True, exist_ok=True)
            with open(target_path, 'w') as target_file:
                target_file.write(rendition)

            logger.info(f"Done {target.description}: '{target.template}' -> '{target_filename}'")

        except TemplateNotFound as ex:
            logger.critical(f"Template file not found: {ex}")
        except TemplateSyntaxError as ex:
            logger.critical(f"Template '{target.template}' syntax error: {ex}")
        except UndefinedError as ex:
            logger.critical(f"Template '{target.template}' error: {ex}")
        except FilterError as ex:
            logger.critical(f"Template '{target.template}' Jinja2 filter error: {ex}")
        except TestError as ex:
            logger.critical(f"Template '{target.template}' Jinja2 test error: {ex}")


def export_cmd(cli_args: argparse.Namespace) -> None:
    """
    Export source configuration as JSON file
    :param cli_args: Parsed CLI args
    :return: None
    """
    logger = logging.getLogger('config_builder.commands.export_cmd')

    try:
        config_obj = load_yaml(ConfigModel, 'config', cli_args.configuration)
        with open(cli_args.file, 'w') as export_file:
            export_file.write(config_obj.model_dump_json(by_alias=True, exclude_none=False, indent=2))

        logger.info(f"Exported source configuration as '{cli_args.file}'")

    except LoaderException as ex:
        logger.critical(f"Failed loading config file: {ex}")


def schema_cmd(cli_args: argparse.Namespace) -> None:
    """
    Generate source configuration JSON schema
    :param cli_args: Parsed CLI args
    :return: None
    """
    logger = logging.getLogger('config_builder.commands.schema_cmd')

    with open(cli_args.file, 'w') as schema_file:
        schema_file.write(json.dumps(ConfigModel.model_json_schema(), indent=2))

    logger.info(f"Saved configuration schema as '{cli_args.file}'")
