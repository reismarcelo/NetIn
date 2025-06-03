import os
import sys
import yaml
from typing import Any, TypeVar
from pydantic import BaseModel, ValidationError
from .models import ConfigModel, merged_rendering_vars


class LoaderException(Exception):
    """ Exception indicating loader errors """
    pass


M = TypeVar('M', bound=BaseModel)


def validation_error_summary(validation_error: ValidationError) -> str:
    def error_loc(error: dict) -> str:
        return ' -> '.join(str(e) for e in error['loc'])

    errors = validation_error.errors()
    display_errors = '\n'.join(f'{error_loc(e)}\n  {e["msg"]}' for e in errors)
    no_errors = len(errors)
    return (
        f'{no_errors} validation error{"" if no_errors == 1 else "s"} for {validation_error.title}\n'
        f'{display_errors}'
    )


def load_yaml(model_cls: type[M], description: str, filename: os.PathLike | str) -> M:
    try:
        with open(filename) as yaml_file:
            yaml_dict = yaml.safe_load(yaml_file)

        model_instance = model_cls(**yaml_dict)
        
        return model_instance

    except FileNotFoundError as ex:
        raise LoaderException(f"Could not open {description} file: {ex}") from None
    except yaml.YAMLError as ex:
        raise LoaderException(f'YAML syntax error in {description} file: {ex}') from None
    except ValidationError as ex:
        raise LoaderException(f"Invalid {description} file: {validation_error_summary(ex)}") from None


class MetadataModel(BaseModel):
    logging_config: dict[str, Any]


def load_metadata(metadata: str) -> MetadataModel:
    try:
        yaml_dict = yaml.safe_load(metadata)
        return MetadataModel(**yaml_dict)
    except (yaml.YAMLError, ValidationError) as ex:
        print(ex)

    sys.exit(1)
