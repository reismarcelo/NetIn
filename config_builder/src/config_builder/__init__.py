import logging
import logging.config
import logging.handlers
from pathlib import Path
from typing import Any
from .loader import load_metadata


METADATA_CONFIG = """
---
logging_config:
  version: 1
  formatters:
    simple:
      format: "%(levelname)s: %(message)s"
    detailed:
      format: "%(asctime)s: %(name)s: %(levelname)s: %(message)s"
  handlers:
    console:
      class: "logging.StreamHandler"
      level: "WARN"
      formatter: "simple"
    file:
      class: "logging.handlers.RotatingFileHandler"
      filename: "logs/config_build.log"
      backupCount: 3
      maxBytes: 204800
      level: "DEBUG"
      formatter: "detailed"
  root:
    handlers:
      - "console"
      - "file"
    level: "DEBUG"   
...
"""


def setup_logging(logging_config: dict[str, Any], is_verbose: bool = False, is_debug: bool = False) -> None:
    file_handler = logging_config.get("handlers", {}).get("file")
    if file_handler is not None:
        Path(file_handler["filename"]).parent.mkdir(parents=True, exist_ok=True)

    console_handler = logging_config.get('handlers', {}).get('console')
    if is_verbose and console_handler is not None:
        console_handler['level'] = 'INFO'

    file_handler = logging_config.get('handlers', {}).get('file')
    if is_debug and file_handler is not None:
        file_handler['level'] = 'DEBUG'

    logging.config.dictConfig(logging_config)


app_config = load_metadata(METADATA_CONFIG)
