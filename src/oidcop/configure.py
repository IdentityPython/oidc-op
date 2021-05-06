"""Configuration management for IDP"""
import importlib
import json
import logging
import os
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from oidcop.logging import configure_logging
from oidcop.utils import load_yaml_config

DEFAULT_FILE_ATTRIBUTE_NAMES = ['server_key', 'server_cert', 'filename', 'template_dir',
                                'private_path', 'public_path', 'db_file']

DEFAULT_CONFIG = {
    "cookie_handler": {
        "class": "oidcop.cookie_handler.CookieHandler",
        "kwargs": {
            "keys": {
                "private_path": "private/cookie_jwks.json",
                "key_defs": [
                    {
                        "type": "OCT",
                        "use": [
                            "enc"
                        ],
                        "kid": "enc"
                    },
                    {
                        "type": "OCT",
                        "use": [
                            "sig"
                        ],
                        "kid": "sig"
                    }
                ],
                "read_only": False
            },
            "name": {
                "session": "oidc_op",
                "register": "oidc_op_rp",
                "session_management": "sman"
            }
        }
    },
    "authz": {
        "class": "oidcop.authz.AuthzHandling",
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": [
                            "access_token",
                            "refresh_token",
                            "id_token"
                        ],
                        "max_usage": 1
                    },
                    "access_token": {},
                    "refresh_token": {
                        "supports_minting": [
                            "access_token",
                            "refresh_token"
                        ]
                    }
                },
                "expires_in": 43200
            }
        }
    },
    "httpc_params": {
        "verify": False
    },
    "id_token": {
        "class": "oidcop.id_token.IDToken",
        "kwargs": {}
    },
    "issuer": "https://{domain}:{port}",
    "session_key": {
        "filename": "private/session_jwk.json",
        "type": "OCT",
        "use": "sig"
    },
    "template_dir": "templates"
}


def add_base_path(conf: dict, base_path: str, file_attributes: List[str]):
    for key, val in conf.items():
        if key in file_attributes:
            if val.startswith("/"):
                continue
            elif val == "":
                conf[key] = "./" + val
            else:
                conf[key] = os.path.join(base_path, val)
        if isinstance(val, dict):
            conf[key] = add_base_path(val, base_path, file_attributes)

    return conf


def create_from_config_file(cls,
                            entity_conf_class,
                            filename: str,
                            base_path: str = '',
                            file_attributes: Optional[List[str]] = None,
                            domain: Optional[str] = "",
                            port: Optional[int] = 0):
    if filename.endswith(".yaml"):
        """Load configuration as YAML"""
        return cls(load_yaml_config(filename),
                   entity_conf_class=entity_conf_class,
                   base_path=base_path, file_attributes=file_attributes,
                   domain=domain, port=port)
    elif filename.endswith(".json"):
        _str = open(filename).read()
        return cls(json.loads(_str),
                   entity_conf_class=entity_conf_class,
                   base_path=base_path, file_attributes=file_attributes, domain=domain, port=port)
    elif filename.endswith(".py"):
        head, tail = os.path.split(filename)
        tail = tail[:-3]
        module = importlib.import_module(tail)
        _cnf = getattr(module, "CONFIG")
        return cls(_cnf,
                   entity_conf_class=entity_conf_class,
                   base_path=base_path, file_attributes=file_attributes,
                   domain=domain, port=port)


class Base:
    """ Configuration base class """

    def __init__(self,
                 conf: Dict,
                 base_path: str = '',
                 file_attributes: Optional[List[str]] = None,
                 ):

        if file_attributes is None:
            file_attributes = DEFAULT_FILE_ATTRIBUTE_NAMES

        if base_path and file_attributes:
            # this adds a base path to all paths in the configuration
            add_base_path(conf, base_path, file_attributes)

    def __getitem__(self, item):
        if item in self.__dict__:
            return self.__dict__[item]
        else:
            raise KeyError

    def get(self, item, default=None):
        return getattr(self, item, default)

    def __contains__(self, item):
        return item in self.__dict__


class OPConfiguration(Base):
    "Provider configuration"

    def __init__(self,
                 conf: Dict,
                 base_path: Optional[str] = '',
                 domain: Optional[str] = "127.0.0.1",
                 port: Optional[int] = 80,
                 file_attributes: Optional[List[str]] = None,
                 ):

        Base.__init__(self, conf, base_path, file_attributes)

        self.add_on = None
        self.authz = None
        self.authentication = None
        self.base_url = ""
        self.capabilities = None
        self.cookie_handler = None
        self.endpoint = {}
        self.httpc_params = {}
        self.id_token = None
        self.issuer = ""
        self.keys = None
        self.login_hint2acrs = {}
        self.login_hint_lookup = None
        self.session_key = None
        self.sub_func = {}
        self.template_dir = None
        self.token_handler_args = {}
        self.userinfo = None

        for key in self.__dict__.keys():
            _val = conf.get(key)
            if not _val and key in DEFAULT_CONFIG:
                _val = DEFAULT_CONFIG[key]
            if not _val:
                continue

            if key in ["issuer", "base_url"]:
                if '{domain}' in _val:
                    setattr(self, key, _val.format(domain=domain, port=port))
                else:
                    setattr(self, key, _val)
            else:
                setattr(self, key, _val)

        if self.template_dir is None:
            self.template_dir = os.path.abspath('templates')
        else:
            self.template_dir = os.path.abspath(self.template_dir)


class Configuration(Base):
    """Server Configuration"""

    def __init__(self,
                 conf: Dict,
                 entity_conf_class: Optional[Any] = OPConfiguration,
                 base_path: str = '',
                 file_attributes: Optional[List[str]] = None,
                 domain: Optional[str] = "",
                 port: Optional[int] = 0
                 ):
        Base.__init__(self, conf, base_path, file_attributes)

        log_conf = conf.get('logging')
        if log_conf:
            self.logger = configure_logging(config=log_conf).getChild(__name__)
        else:
            self.logger = logging.getLogger('oidcop')

        self.webserver = conf.get("webserver", {})

        if domain:
            args = {"domain": domain}
        else:
            args = {"domain": conf.get("domain", "127.0.0.1")}

        if port:
            args["port"] = port
        else:
            args["port"] = conf.get("port", 80)

        self.op = entity_conf_class(conf["op"]["server_info"], **args)
