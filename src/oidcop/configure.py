"""Configuration management for IDP"""
import ast
import json
import logging
import os
from typing import Dict
from typing import Optional

from cryptojwt.key_bundle import init_key
from oidcmsg import add_base_path

from oidcop.logging import configure_logging
from oidcop.utils import load_yaml_config

try:
    from secrets import token_urlsafe as rnd_token
except ImportError:
    from oidcop import rndstr as rnd_token

DEFAULT_ITEM_PATHS = {
    "webserver": ['server_key', 'server_cert'],
    "op": {
        "server_info": {
            "session_key": ["filename"],
            "template_dir": None,
            "token_handler_args": {
                "jwks_def": ["private_path", "public_path"]
            },
            "keys": ["private_path", "public_path"],
            "cookie_handler": {
                "kwargs": {
                    "sign_jwk": ["private_path", "public_path"],
                    "enc_jwk": ["private_path", "public_path"]
                }
            }
        }
    }
}


class Configuration:
    """OP Configuration"""

    def __init__(self, conf: Dict, base_path: str = '', item_paths: Optional[dict] = None):
        log_conf = conf.get('logging')
        if log_conf:
            self.logger = configure_logging(config=log_conf).getChild(__name__)
        else:
            self.logger = logging.getLogger('oidcop')

        self.op = {}
        if item_paths is None:
            item_paths = DEFAULT_ITEM_PATHS

        if base_path and item_paths:
            # this adds a base path to all paths in the configuration
            add_base_path(conf, item_paths, base_path)

        # OIDC provider configuration
        for section in ['op', 'webserver', 'httpc_params', 'jinja_env']:
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
    def create_from_config_file(cls, filename: str, base_path: str = '',
                                item_paths: Optional[dict] = None):
        if filename.endswith(".yaml"):
            """Load configuration as YAML"""
            return cls(load_yaml_config(filename), base_path, item_paths)
        elif filename.endswith(".json"):
            _str = open(filename).read()
            return cls(json.loads(_str), base_path, item_paths)
        elif filename.endswith(".py"):
            _str = open(filename).read()
            return cls(ast.literal_eval(_str), base_path, item_paths)
