# Configuration Builder Tool

## Installation

Config builder requires Python 3.12 or newer. This can be verified by pasting the following to a terminal window:
```
% python3 -c "import sys;assert sys.version_info>(3,12)" && echo "ALL GOOD"
```

If 'ALL GOOD' is printed it means Python requirements are met. If not, download and install the latest 3.x version at Python.org (https://www.python.org/downloads/).

Go to the config_builder directory and create a virtual environment
```
% cd config_builder
% python3 -m venv venv
```

Activate the virtual environment:
```
% source venv/bin/activate
(venv) %
```
- Note that the prompt is updated with the virtual environment name (venv), indicating that the virtual environment is active.
    
Upgrade built-in virtual environment packages:
```
(venv) % pip install --upgrade pip
```

Install config builder:
```
(venv) % pip install --upgrade .
```

Validate that config builder is installed:
```
% config_build --version                                                                                                                  
Config Builder Tool Version 1.0
```

## Rendering Configuration files with config_build

Once installed, config_build --help can be used to navigate through CLI options.

```
% config_build --help   
usage: config_build [-h] [--version] [--verbose] [--debug] [-c <filename>] {render,export,schema} ...

Config Builder Tool

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --verbose             increase console output verbosity
  --debug               enable debug logging to log file
  -c <filename>, --configuration <filename>
                        config builder configuration file (default: configuration.yaml)

commands:
  {render,export,schema}
    render              render configuration files
    export              export source configuration as JSON file
    schema              generate source configuration JSON schema

```

```
% config_build render --help
usage: config_build render [-h] [-t <tag>] [-g <regex>] [-d <regex>] [-u]

options:
  -h, --help            show this help message and exit
  -t <tag>, --tag <tag>
                        tag to select specific targets, by default all targets are rendered
  -g <regex>, --groups <regex>
                        regular expression matching group names to select
  -d <regex>, --devices <regex>
                        regular expression matching device names to select
  -u, --update          override target files that already exist, by default they are skipped

```

In order to render network device configuration, change to the network_configuration directory:
```
(venv) Rogers-IP-Core-Segmentation-Config % pwd
/Rogers-IP-Core-Segmentation-Config
% cd network_configuration 
(venv) network_configuration % pwd
/Rogers-IP-Core-Segmentation-Config/network_configuration
(venv) network_configuration % ls
configuration.yaml	inventory		pre_post_checks		templates
```

Rendering day1 configurations:
```
(venv) network_configuration % config_build --verbose render -u --tag day1
INFO: Rendering Day1 Template: Group: WCR, Device: WCR01.FLBASP
INFO: Done Day1 Template: 'day_1/day1_config_WCR.j2' -> 'rendered_configs/day1/day1_config_WCR_WCR01.FLBASP.txt'
INFO: Rendering Day1 Template: Group: WCR, Device: WCR01.FLMS1
INFO: Done Day1 Template: 'day_1/day1_config_WCR.j2' -> 'rendered_configs/day1/day1_config_WCR_WCR01.FLMS1.txt'
INFO: Rendering Day1 Template: Group: WCR, Device: WCR01.FLTO3
INFO: Done Day1 Template: 'day_1/day1_config_WCR.j2' -> 'rendered_configs/day1/day1_config_WCR_WCR01.FLTO3.txt'
INFO: Rendering Day1 Template: Group: WCR, Device: WCR01.FLBR1
INFO: Done Day1 Template: 'day_1/day1_config_WCR.j2' -> 'rendered_configs/day1/day1_config_WCR_WCR01.FLBR1.txt'
(venv) network_configuration % ls

```
