"""Common logging functions"""
import logging
import os
from logging.config import dictConfig
from typing import Optional

import yaml

LOGGING_CONF = "logging.yaml"

LOGGING_DEFAULT = {
    "version": 1,
    "formatters": {"default": {"format": "%(asctime)s %(name)s %(levelname)s %(message)s"}},
    "handlers": {"default": {"class": "logging.StreamHandler", "formatter": "default"}},
    "root": {"handlers": ["default"], "level": "INFO"},
}


def configure_logging(
    debug: Optional[bool] = False,
    config: Optional[dict] = None,
    filename: Optional[str] = "",
) -> logging.Logger:
    """Configure logging"""

    if config is not None:
        config_dict = config
        config_source = "dictionary"
    elif filename and os.path.exists(filename):
        with open(filename, "rt") as file:
            config_dict = yaml.safe_load(file)
        config_source = "file"
    else:
        config_dict = LOGGING_DEFAULT
        config_source = "default"

    if debug:
        config_dict["root"]["level"] = "DEBUG"

    dictConfig(config_dict)
    logger = logging.getLogger()
    logger.debug("Configured logging using: {}".format(config_source))
    return logger
