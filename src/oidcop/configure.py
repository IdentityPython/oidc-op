"""Configuration management for IDP"""

import os
from typing import Dict

from cryptojwt.key_bundle import init_key

from oidcop.logging import configure_logging
from oidcop.utils import load_yaml_config

try:
    from secrets import token_urlsafe as rnd_token
except ImportError:
    from oidcendpoint import rndstr as rnd_token


class Configuration:
    """OP Configuration"""

    def __init__(self, conf: Dict) -> None:
        self.logger = configure_logging(config=conf.get('logging')).getChild(__name__)

        # OIDC provider configuration
        self.op = conf.get('op')
        self.webserver = conf.get('webserver')

        # set OP session key
        _key_args = self.op['server_info'].get('session_key')
        if _key_args is not None:
            self.session_key = init_key(**_key_args)
            # self.op['server_info']['password'] = self.session_key
            self.logger.debug("Set server password to %s", self.session_key)

        # templates and Jinja environment
        self.template_dir = os.path.abspath(conf.get('template_dir', 'templates'))
        self.jinja_env = conf.get('jinja_env', {})

    @classmethod
    def create_from_config_file(cls, filename: str):
        """Load configuration as YAML"""
        return cls(load_yaml_config(filename))
