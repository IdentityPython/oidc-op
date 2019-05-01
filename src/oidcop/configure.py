"""Configuration management for IDP"""

import json
import os
import sys
from typing import Dict

from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwx import key_from_jwk_dict

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
        # self.oidc_clients = conf.get('oidc_clients', {})

        # session key
        self.session_jwk = conf.get('session_jwk')
        if self.session_jwk is not None:
            self.logger.debug("Reading session signer from %s", self.session_jwk)
            try:
                with open(self.session_jwk) as jwk_file:
                    jwk_dict = json.loads(jwk_file.read())
                    self.session_key = key_from_jwk_dict(jwk_dict).k
            except Exception:
                self.logger.critical("Failed reading session signer from %s",
                                     self.session_jwk)
                sys.exit(-1)
        else:
            self.logger.debug("Generating random session signer")
            self.session_key = SYMKey(key=rnd_token(32)).k

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
