"""Configuration management for IDP"""

import os
from typing import Dict

from cryptojwt.key_jar import init_key_jar

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

        # session key
        _kj_args = {k: v for k, v in conf.get('SESSION_KEYS').items() if k != 'uri_path'}
        _kj = init_key_jar(**_kj_args)
        self.session_key = _kj.get_signing_key()[0]

        # set OP session key
        if self.op is not None:
            if self.op['server_info'].get('password') is None:
                key = self.session_key
                self.op['server_info']['password'] = key
                self.logger.debug("Set server password to %s", key)

        # templates and Jinja environment
        self.template_dir = os.path.abspath(conf.get('template_dir', 'templates'))
        self.jinja_env = conf.get('jinja_env', {})

    @classmethod
    def create_from_config_file(cls, filename: str):
        """Load configuration as YAML"""
        return cls(load_yaml_config(filename))
