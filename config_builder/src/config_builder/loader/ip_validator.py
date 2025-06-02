"""
IP address uniqueness validator for NetIn configuration.

This module provides functions to validate that IP addresses are unique across all interfaces
in a NetIn configuration.
"""
import yaml
from ipaddress import IPv4Interface, IPv6Interface
from typing import Dict, Tuple, List, Optional, Any


def validate_unique_ip_addresses(config_file: str) -> bool:
    """
    Validate that all IP addresses in the configuration file are unique.
    
    Args:
        config_file: Path to the configuration YAML file
        
    Returns:
        True if all IP addresses are unique, False otherwise
    """
    print(f"Loading configuration from {config_file}")
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    ipv4_addresses = {}  # IP -> (device_name, interface_type, interface_id)
    ipv6_addresses = {}  # IP -> (device_name, interface_type, interface_id)
    validation_errors = []
    
    def collect_ip_addresses(device_name: str, vars_model: Dict[str, Any]) -> None:
        """
        Collect and validate IP addresses from a vars model.
        
        Args:
            device_name: Name of the device or scope (e.g., 'global', 'group-X')
            vars_model: The vars model to collect IP addresses from
        """
        if vars_model is None:
            return
        
        for bundle in vars_model.get('bundle_interfaces', []):
            if 'ipv4_address' in bundle:
                ip_str = bundle['ipv4_address'].split('/')[0]
                print(f"Found IPv4 address {ip_str} on {device_name} Bundle-Ether{bundle['bundle_id']}")
                if ip_str in ipv4_addresses:
                    existing = ipv4_addresses[ip_str]
                    error_msg = (f"ERROR: IPv4 address {ip_str} is assigned to multiple interfaces: "
                                f"{existing[0]} {existing[1]}{existing[2]} and "
                                f"{device_name} Bundle-Ether{bundle['bundle_id']}")
                    print(error_msg)
                    validation_errors.append(error_msg)
                ipv4_addresses[ip_str] = (device_name, 'Bundle-Ether', bundle['bundle_id'])
            
            if 'ipv6_address' in bundle:
                ip_str = bundle['ipv6_address'].split('/')[0]
                print(f"Found IPv6 address {ip_str} on {device_name} Bundle-Ether{bundle['bundle_id']}")
                if ip_str in ipv6_addresses:
                    existing = ipv6_addresses[ip_str]
                    error_msg = (f"ERROR: IPv6 address {ip_str} is assigned to multiple interfaces: "
                                f"{existing[0]} {existing[1]}{existing[2]} and "
                                f"{device_name} Bundle-Ether{bundle['bundle_id']}")
                    print(error_msg)
                    validation_errors.append(error_msg)
                ipv6_addresses[ip_str] = (device_name, 'Bundle-Ether', bundle['bundle_id'])
            
            for sub in bundle.get('sub_interfaces', []):
                if 'ipv4_address' in sub:
                    ip_str = sub['ipv4_address'].split('/')[0]
                    print(f"Found IPv4 address {ip_str} on {device_name} Bundle-Ether{bundle['bundle_id']}.{sub['sub_interface_id']}")
                    if ip_str in ipv4_addresses:
                        existing = ipv4_addresses[ip_str]
                        error_msg = (f"ERROR: IPv4 address {ip_str} is assigned to multiple interfaces: "
                                    f"{existing[0]} {existing[1]}{existing[2]} and "
                                    f"{device_name} Bundle-Ether{bundle['bundle_id']}.{sub['sub_interface_id']}")
                        print(error_msg)
                        validation_errors.append(error_msg)
                    ipv4_addresses[ip_str] = (device_name, 'Bundle-Ether', f"{bundle['bundle_id']}.{sub['sub_interface_id']}")
                
                if 'ipv6_address' in sub:
                    ip_str = sub['ipv6_address'].split('/')[0]
                    print(f"Found IPv6 address {ip_str} on {device_name} Bundle-Ether{bundle['bundle_id']}.{sub['sub_interface_id']}")
                    if ip_str in ipv6_addresses:
                        existing = ipv6_addresses[ip_str]
                        error_msg = (f"ERROR: IPv6 address {ip_str} is assigned to multiple interfaces: "
                                    f"{existing[0]} {existing[1]}{existing[2]} and "
                                    f"{device_name} Bundle-Ether{bundle['bundle_id']}.{sub['sub_interface_id']}")
                        print(error_msg)
                        validation_errors.append(error_msg)
                    ipv6_addresses[ip_str] = (device_name, 'Bundle-Ether', f"{bundle['bundle_id']}.{sub['sub_interface_id']}")
        
        if 'routing_igp' in vars_model and 'loopback_0' in vars_model['routing_igp']:
            loopback = vars_model['routing_igp']['loopback_0']
            if 'ipv4_address' in loopback:
                ip_str = loopback['ipv4_address'].split('/')[0]
                print(f"Found IPv4 address {ip_str} on {device_name} Loopback0")
                if ip_str in ipv4_addresses:
                    existing = ipv4_addresses[ip_str]
                    error_msg = (f"ERROR: IPv4 address {ip_str} is assigned to multiple interfaces: "
                                f"{existing[0]} {existing[1]}{existing[2]} and "
                                f"{device_name} Loopback0")
                    print(error_msg)
                    validation_errors.append(error_msg)
                ipv4_addresses[ip_str] = (device_name, 'Loopback', 0)
            
            if 'ipv6_address' in loopback:
                ip_str = loopback['ipv6_address'].split('/')[0]
                print(f"Found IPv6 address {ip_str} on {device_name} Loopback0")
                if ip_str in ipv6_addresses:
                    existing = ipv6_addresses[ip_str]
                    error_msg = (f"ERROR: IPv6 address {ip_str} is assigned to multiple interfaces: "
                                f"{existing[0]} {existing[1]}{existing[2]} and "
                                f"{device_name} Loopback0")
                    print(error_msg)
                    validation_errors.append(error_msg)
                ipv6_addresses[ip_str] = (device_name, 'Loopback', 0)
        
        if 'management_oob' in vars_model:
            mgmt = vars_model['management_oob']
            if 'vip_ipv4_address' in mgmt:
                ip_str = mgmt['vip_ipv4_address'].split('/')[0]
                print(f"Found IPv4 address {ip_str} on {device_name} Management-VIP")
                if ip_str in ipv4_addresses:
                    existing = ipv4_addresses[ip_str]
                    error_msg = (f"ERROR: IPv4 address {ip_str} is assigned to multiple interfaces: "
                                f"{existing[0]} {existing[1]}{existing[2]} and "
                                f"{device_name} Management-VIP")
                    print(error_msg)
                    validation_errors.append(error_msg)
                ipv4_addresses[ip_str] = (device_name, 'Management-VIP', '')
            
            for mgmt_int in mgmt.get('interfaces', []):
                if 'ipv4_address' in mgmt_int:
                    ip_str = mgmt_int['ipv4_address'].split('/')[0]
                    print(f"Found IPv4 address {ip_str} on {device_name} {mgmt_int['name']}")
                    if ip_str in ipv4_addresses:
                        existing = ipv4_addresses[ip_str]
                        error_msg = (f"ERROR: IPv4 address {ip_str} is assigned to multiple interfaces: "
                                    f"{existing[0]} {existing[1]}{existing[2]} and "
                                    f"{device_name} {mgmt_int['name']}")
                        print(error_msg)
                        validation_errors.append(error_msg)
                    ipv4_addresses[ip_str] = (device_name, mgmt_int['name'], '')
    
    if 'global_vars' in config:
        collect_ip_addresses('global', config['global_vars'])
    
    for group in config.get('groups', []):
        if 'vars' in group:
            collect_ip_addresses(f"group-{group['name']}", group['vars'])
        
        for device in group.get('devices', []):
            if 'vars' in device:
                collect_ip_addresses(device['name'], device['vars'])
    
    print(f"Validation complete. Found {len(ipv4_addresses)} unique IPv4 addresses and {len(ipv6_addresses)} unique IPv6 addresses.")
    
    if validation_errors:
        print(f"Found {len(validation_errors)} validation errors:")
        for error in validation_errors:
            print(f"  - {error}")
        return False
    
    print("No duplicate IP addresses found.")
    return True
