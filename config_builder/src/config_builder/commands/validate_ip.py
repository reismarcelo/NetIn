#!/usr/bin/env python3
"""
Command-line tool to validate IP address uniqueness in NetIn configuration.
"""
import sys
import argparse
from ..loader.ip_validator import validate_unique_ip_addresses


def main():
    """
    Main entry point for the IP address uniqueness validator.
    """
    parser = argparse.ArgumentParser(description='Validate IP address uniqueness in NetIn configuration')
    parser.add_argument('config_file', help='Path to the configuration YAML file')
    args = parser.parse_args()
    
    if validate_unique_ip_addresses(args.config_file):
        print("SUCCESS: All IP addresses are unique.")
        sys.exit(0)
    else:
        print("ERROR: Found duplicate IP addresses in the configuration.")
        sys.exit(1)


if __name__ == '__main__':
    main()
