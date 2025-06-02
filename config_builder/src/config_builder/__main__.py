"""
Config Builder Tool

"""
import argparse
import logging
from datetime import date
from .__version__ import __version__ as version
from .commands import render_cmd, export_cmd, schema_cmd
from .loader.validators import validate_existing_file, validate_regex
from . import setup_logging, app_config


def main():
    cli_parser = argparse.ArgumentParser(description=__doc__)
    cli_parser.add_argument("--version", action="version", version=f"Config Builder Tool Version {version}")
    cli_parser.add_argument('--verbose', action='store_true', help='increase console output verbosity')
    cli_parser.add_argument('--debug', action='store_true', help='enable debug logging to log file')

    cli_parser.add_argument("-c", "--configuration", metavar="<filename>", type=existing_file_type,
                            default="configuration.yaml",
                            help="config builder configuration file (default: %(default)s)")

    commands = cli_parser.add_subparsers(title="commands")
    commands.required = True

    render_parser = commands.add_parser("render", help="render configuration files")
    render_parser.set_defaults(cmd_handler=render_cmd)
    render_parser.add_argument("-t", "--tag", metavar="<tag>",
                               help=f"tag to select specific targets, by default all targets are rendered")
    render_parser.add_argument("-g", "--groups", metavar="<regex>", type=regex_type,
                               help="regular expression matching group names to select")
    render_parser.add_argument("-d", "--devices", metavar="<regex>", type=regex_type,
                               help="regular expression matching device names to select")
    render_parser.add_argument("-u", "--update", action="store_true",
                               help="override target files that already exist, by default they are skipped")

    export_parser = commands.add_parser("export", help="export source configuration as JSON file")
    export_parser.set_defaults(cmd_handler=export_cmd)
    export_parser.add_argument("-f", "--file", metavar="<filename>", default=f"config_{date.today():%Y%m%d}.json",
                               help="export filename (default: %(default)s)")

    schema_parser = commands.add_parser("schema", help="generate source configuration JSON schema")
    schema_parser.set_defaults(cmd_handler=schema_cmd)
    schema_parser.add_argument("-f", "--file", metavar="<filename>", default="config_schema.json",
                               help="export filename (default: %(default)s)")

    cli_args = cli_parser.parse_args()
    setup_logging(app_config.logging_config, is_verbose=cli_args.verbose, is_debug=cli_args.debug)

    # Execute command
    try:
        cli_args.cmd_handler(cli_args)
    except KeyboardInterrupt:
        logging.getLogger('config_builder.main').critical("Interrupted by user")


#
# CLI input validators
#
def existing_file_type(filename: str) -> str:
    try:
        validate_existing_file(filename)
    except ValueError as ex:
        raise argparse.ArgumentTypeError(ex) from None

    return filename


def regex_type(regex: str) -> str:
    try:
        validate_regex(regex)
    except ValueError as ex:
        raise argparse.ArgumentTypeError(ex) from None

    return regex


if __name__ == '__main__':
    main()
