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
        self.op = None

        # OIDC provider configuration
        for section in ['op', 'webserver', 'http_params', 'jinja_env']:
            setattr(self, section, conf.get(section, {}))

        # set OP session key
        _key_args = self.op['server_info'].get('session_key')
        if _key_args is not None:
            self.session_key = init_key(**_key_args)
            # self.op['server_info']['password'] = self.session_key
            self.logger.debug("Set server password to %s", self.session_key)

        # templates and Jinja environment
        self.template_dir = os.path.abspath(conf.get('template_dir', 'templates'))

        # server info
        self.domain = conf.get("domain")
        self.port = conf.get("port")
        for param in ["server_name", "base_url"]:
            _pre = conf.get(param)
            if _pre:
                if '{domain}' in _pre:
                    setattr(self, param, _pre.format(domain=self.domain, port=self.port))
                else:
                    setattr(self, param, _pre)

    @classmethod
    def create_from_config_file(cls, filename: str):
        """Load configuration as YAML"""
        return cls(load_yaml_config(filename))
