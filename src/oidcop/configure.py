"""Configuration management for IDP"""
import copy
import importlib
import json
import logging
import os
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

from oidcop.logging import configure_logging
from oidcop.scopes import SCOPE2CLAIMS
from oidcop.utils import load_yaml_config

logger = logging.getLogger(__name__)


DEFAULT_FILE_ATTRIBUTE_NAMES = [
    "server_key",
    "server_cert",
    "filename",
    "template_dir",
    "private_path",
    "public_path",
    "db_file",
    "jwks_file"
]

OP_DEFAULT_CONFIG = {
    "capabilities": {
        "subject_types_supported": ["public", "pairwise"],
        "grant_types_supported": [
            "authorization_code",
            "implicit",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "refresh_token",
        ],
    },
    "cookie_handler": {
        "class": "oidcop.cookie_handler.CookieHandler",
        "kwargs": {
            "keys": {
                "private_path": "private/cookie_jwks.json",
                "key_defs": [
                    {"type": "OCT", "use": ["enc"], "kid": "enc"},
                    {"type": "OCT", "use": ["sig"], "kid": "sig"},
                ],
                "read_only": False,
            },
            "name": {"session": "oidc_op", "register": "oidc_op_rp",
                     "session_management": "sman", },
        },
    },
    "claims_interface": {"class": "oidcop.session.claims.ClaimsInterface", "kwargs": {}},
    "authz": {
        "class": "oidcop.authz.AuthzHandling",
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": ["access_token", "refresh_token", "id_token", ],
                        "max_usage": 1,
                    },
                    "access_token": {},
                    "refresh_token": {
                        "supports_minting": ["access_token", "refresh_token"],
                        "expires_in": -1
                    },
                },
                "expires_in": 43200,
            }
        },
    },
    "httpc_params": {"verify": False, "timeout": 4},
    "issuer": "https://{domain}:{port}",
    "template_dir": "templates",
    "token_handler_args": {
        "jwks_file": "private/token_jwks.json",
        "code": {"kwargs": {"lifetime": 600}},
        "token": {"class": "oidcop.token.jwt_token.JWTToken", "kwargs": {"lifetime": 3600}, },
        "refresh": {"class": "oidcop.token.jwt_token.JWTToken", "kwargs": {"lifetime": 86400}, },
        "id_token": {"class": "oidcop.token.id_token.IDToken", "kwargs": {}},
    },
    "scopes_to_claims": SCOPE2CLAIMS,
}

AS_DEFAULT_CONFIG = copy.deepcopy(OP_DEFAULT_CONFIG)
AS_DEFAULT_CONFIG["claims_interface"] = {
    "class": "oidcop.session.claims.OAuth2ClaimsInterface", "kwargs": {}
}


def add_base_path(conf: Union[dict, str], base_path: str, file_attributes: List[str]):
    if isinstance(conf, str):
        if conf.startswith("/"):
            pass
        elif conf == "":
            conf = "./" + conf
        else:
            conf = os.path.join(base_path, conf)
    elif isinstance(conf, dict):
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


def set_domain_and_port(conf: dict, uris: List[str], domain: str, port: int):
    for key, val in conf.items():
        if key in uris:
            if isinstance(val, list):
                _new = [v.format(domain=domain, port=port) for v in val]
            else:
                _new = val.format(domain=domain, port=port)
            conf[key] = _new
        elif isinstance(val, dict):
            conf[key] = set_domain_and_port(val, uris, domain, port)
    return conf


def create_from_config_file(
        cls,
        filename: str,
        base_path: str = "",
        entity_conf: Optional[List[dict]] = None,
        file_attributes: Optional[List[str]] = None,
        domain: Optional[str] = "",
        port: Optional[int] = 0,
):
    if filename.endswith(".yaml"):
        """Load configuration as YAML"""
        _conf = load_yaml_config(filename)
    elif filename.endswith(".json"):
        _str = open(filename).read()
        _conf = json.loads(_str)
    elif filename.endswith(".py"):
        head, tail = os.path.split(filename)
        tail = tail[:-3]
        module = importlib.import_module(tail)
        _conf = getattr(module, "OIDCOP_CONFIG")
    else:
        raise ValueError("Unknown file type")

    return cls(
        _conf,
        entity_conf=entity_conf,
        base_path=base_path,
        file_attributes=file_attributes,
        domain=domain,
        port=port,
    )


class Base(dict):
    """ Configuration base class """

    parameter = {}

    def __init__(
            self, conf: Dict, base_path: str = "", file_attributes: Optional[List[str]] = None,
    ):
        dict.__init__(self)

        if file_attributes is None:
            file_attributes = DEFAULT_FILE_ATTRIBUTE_NAMES

        if base_path and file_attributes:
            # this adds a base path to all paths in the configuration
            add_base_path(conf, base_path, file_attributes)

    def __getattr__(self, item):
        return self[item]

    def __setattr__(self, key, value):
        if key in self:
            raise KeyError('{} has already been set'.format(key))
        super(Base, self).__setitem__(key, value)

    def __setitem__(self, key, value):
        if key in self:
            raise KeyError('{} has already been set'.format(key))
        super(Base, self).__setitem__(key, value)


class EntityConfiguration(Base):
    default_config = AS_DEFAULT_CONFIG
    uris = ["issuer", "base_url"]
    parameter = {
        "add_on": None,
        "authz": None,
        "authentication": None,
        "base_url": "",
        "capabilities": None,
        "claims_interface": None,
        "client_db": None,
        "cookie_handler": None,
        "endpoint": {},
        "httpc_params": {},
        "issuer": "",
        "keys": None,
        "session_params": None,
        "template_dir": None,
        "token_handler_args": {},
        "userinfo": None,
    }

    def __init__(
            self,
            conf: Dict,
            base_path: Optional[str] = "",
            entity_conf: Optional[List[dict]] = None,
            domain: Optional[str] = "",
            port: Optional[int] = 0,
            file_attributes: Optional[List[str]] = None,
    ):

        conf = copy.deepcopy(conf)
        Base.__init__(self, conf, base_path, file_attributes)

        if file_attributes is None:
            file_attributes = DEFAULT_FILE_ATTRIBUTE_NAMES

        if not domain:
            domain = conf.get("domain", "127.0.0.1")

        if not port:
            port = conf.get("port", 80)

        for key in self.parameter.keys():
            _val = conf.get(key)
            if not _val:
                if key in self.default_config:
                    _val = copy.deepcopy(self.default_config[key])
                    self.format(_val, base_path=base_path, file_attributes=file_attributes,
                                domain=domain, port=port)
                else:
                    continue

            if key not in DEFAULT_EXTENDED_CONF:
                logger.warning(
                    f"{key} not seems to be a valid configuration parameter"
                )
            elif not _val:
                logger.warning(
                        f"{key} not configured, using default configuration values"
                    )

            if key == "template_dir":
                _val = os.path.abspath(_val)

            setattr(self, key, _val)

        # try:
        #     _dir = self.template_dir
        # except AttributeError:
        #     self.template_dir = os.path.abspath("templates")
        # else:
        #     self.template_dir =

    def format(self, conf, base_path, file_attributes, domain, port):
        """
        Formats parts of the configuration. That includes replacing the strings {domain} and {port}
        with the used domain and port and making references to files and directories absolute
        rather then relative. The formatting is done in place.

        :param conf: The configuration part
        :param base_path: The base path used to make file/directory refrences absolute
        :param file_attributes: Attribute names that refer to files or directories.
        :param domain: The domain name
        :param port: The port used
        """
        add_base_path(conf, base_path, file_attributes)
        if isinstance(conf, dict):
            set_domain_and_port(conf, self.uris, domain=domain, port=port)


class OPConfiguration(EntityConfiguration):
    "Provider configuration"
    default_config = OP_DEFAULT_CONFIG
    parameter = EntityConfiguration.parameter.copy()
    parameter.update(
        {
            "id_token": None,
            "login_hint2acrs": {},
            "login_hint_lookup": None,
            "sub_func": {},
            "scopes_to_claims": {},
        }
    )

    def __init__(
        self,
        conf: Dict,
        base_path: Optional[str] = "",
        entity_conf: Optional[List[dict]] = None,
        domain: Optional[str] = "",
        port: Optional[int] = 0,
        file_attributes: Optional[List[str]] = None,
    ):
        super().__init__(
            conf=conf,
            base_path=base_path,
            entity_conf=entity_conf,
            domain=domain,
            port=port,
            file_attributes=file_attributes,
        )
        scopes_to_claims = self.scopes_to_claims


class ASConfiguration(EntityConfiguration):
    "Authorization server configuration"

    def __init__(
            self,
            conf: Dict,
            base_path: Optional[str] = "",
            entity_conf: Optional[List[dict]] = None,
            domain: Optional[str] = "",
            port: Optional[int] = 0,
            file_attributes: Optional[List[str]] = None,
    ):
        EntityConfiguration.__init__(self, conf=conf, base_path=base_path,
                                     entity_conf=entity_conf, domain=domain, port=port,
                                     file_attributes=file_attributes)


class Configuration(Base):
    """Server Configuration"""
    uris = ["issuer", "base_url"]

    def __init__(
            self,
            conf: Dict,
            entity_conf: Optional[List[dict]] = None,
            base_path: str = "",
            file_attributes: Optional[List[str]] = None,
            domain: Optional[str] = "",
            port: Optional[int] = 0,
    ):
        Base.__init__(self, conf, base_path, file_attributes)

        log_conf = conf.get("logging")
        if log_conf:
            self.logger = configure_logging(config=log_conf).getChild(__name__)
        else:
            self.logger = logging.getLogger("oidcop")

        self.webserver = conf.get("webserver", {})

        if not domain:
            domain = conf.get("domain", "127.0.0.1")

        if not port:
            port = conf.get("port", 80)

        set_domain_and_port(conf, self.uris, domain=domain, port=port)

        if entity_conf:
            for econf in entity_conf:
                _path = econf.get("path")
                _cnf = conf
                if _path:
                    for step in _path:
                        _cnf = _cnf[step]
                _attr = econf["attr"]
                _cls = econf["class"]
                setattr(
                    self,
                    _attr,
                    _cls(
                        _cnf,
                        base_path=base_path,
                        file_attributes=file_attributes,
                        domain=domain,
                        port=port,
                    ),
                )


DEFAULT_EXTENDED_CONF = {
    "add_on": {
        "pkce": {
            "function": "oidcop.oidc.add_on.pkce.add_pkce_support",
            "kwargs": {"essential": False, "code_challenge_method": "S256 S384 S512"},
        },
        "claims": {
            "function": "oidcop.oidc.add_on.custom_scopes.add_custom_scopes",
            "kwargs": {
                "research_and_scholarship": [
                    "name",
                    "given_name",
                    "family_name",
                    "email",
                    "email_verified",
                    "sub",
                    "iss",
                    "eduperson_scoped_affiliation",
                ]
            },
        },
    },
    "authz": {
        "class": "oidcop.authz.AuthzHandling",
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": ["access_token", "refresh_token", "id_token", ],
                        "max_usage": 1,
                    },
                    "access_token": {},
                    "refresh_token": {
                        "supports_minting": ["access_token", "refresh_token"],
                        "expires_in": -1
                    },
                },
                "expires_in": 43200,
            }
        },
    },
    "authentication": {
        "user": {
            "acr": "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword",
            "class": "oidcop.user_authn.user.UserPassJinja2",
            "kwargs": {
                "verify_endpoint": "verify/user",
                "template": "user_pass.jinja2",
                "db": {"class": "oidcop.util.JSONDictDB", "kwargs": {"filename": "passwd.json"}, },
                "page_header": "Testing log in",
                "submit_btn": "Get me in!",
                "user_label": "Nickname",
                "passwd_label": "Secret sauce",
            },
        }
    },
    "capabilities": {
        "subject_types_supported": ["public", "pairwise"],
        "grant_types_supported": [
            "authorization_code",
            "implicit",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "refresh_token",
        ],
    },
    "cookie_handler": {
        "class": "oidcop.cookie_handler.CookieHandler",
        "kwargs": {
            "keys": {
                "private_path": "private/cookie_jwks.json",
                "key_defs": [
                    {"type": "OCT", "use": ["enc"], "kid": "enc"},
                    {"type": "OCT", "use": ["sig"], "kid": "sig"},
                ],
                "read_only": False,
            },
            "name": {"session": "oidc_op", "register": "oidc_op_rp",
                     "session_management": "sman", },
        },
    },
    "endpoint": {
        "webfinger": {
            "path": ".well-known/webfinger",
            "class": "oidcop.oidc.discovery.Discovery",
            "kwargs": {"client_authn_method": None},
        },
        "provider_info": {
            "path": ".well-known/openid-configuration",
            "class": "oidcop.oidc.provider_config.ProviderConfiguration",
            "kwargs": {"client_authn_method": None},
        },
        "registration": {
            "path": "registration",
            "class": "oidcop.oidc.registration.Registration",
            "kwargs": {"client_authn_method": None, "client_secret_expiration_time": 432000, },
        },
        "registration_api": {
            "path": "registration_api",
            "class": "oidcop.oidc.read_registration.RegistrationRead",
            "kwargs": {"client_authn_method": ["bearer_header"]},
        },
        "introspection": {
            "path": "introspection",
            "class": "oidcop.oauth2.introspection.Introspection",
            "kwargs": {"client_authn_method": ["client_secret_post"], "release": ["username"], },
        },
        "authorization": {
            "path": "authorization",
            "class": "oidcop.oidc.authorization.Authorization",
            "kwargs": {
                "client_authn_method": None,
                "claims_parameter_supported": True,
                "request_parameter_supported": True,
                "request_uri_parameter_supported": True,
                "response_types_supported": [
                    "code",
                    "token",
                    "id_token",
                    "code token",
                    "code id_token",
                    "id_token token",
                    "code id_token token",
                    # "none"
                ],
                "response_modes_supported": ["query", "fragment", "form_post"],
            },
        },
        "token": {
            "path": "token",
            "class": "oidcop.oidc.token.Token",
            "kwargs": {
                "client_authn_method": [
                    "client_secret_post",
                    "client_secret_basic",
                    "client_secret_jwt",
                    "private_key_jwt",
                ]
            },
        },
        "userinfo": {
            "path": "userinfo",
            "class": "oidcop.oidc.userinfo.UserInfo",
            "kwargs": {"claim_types_supported": ["normal", "aggregated", "distributed"]},
        },
        "end_session": {
            "path": "session",
            "class": "oidcop.oidc.session.Session",
            "kwargs": {
                "logout_verify_url": "verify_logout",
                "post_logout_uri_path": "post_logout",
                "signing_alg": "ES256",
                "frontchannel_logout_supported": True,
                "frontchannel_logout_session_supported": True,
                "backchannel_logout_supported": True,
                "backchannel_logout_session_supported": True,
                "check_session_iframe": "check_session_iframe",
            },
        },
    },
    "httpc_params": {"verify": False, "timeout": 4},
    "issuer": "https://{domain}:{port}",
    "keys": {
        "private_path": "private/jwks.json",
        "key_defs": [
            {"type": "RSA", "use": ["sig"]},
            {"type": "EC", "crv": "P-256", "use": ["sig"]},
        ],
        "public_path": "static/jwks.json",
        "read_only": False,
        "uri_path": "static/jwks.json",
    },
    "login_hint2acrs": {
        "class": "oidcop.login_hint.LoginHint2Acrs",
        "kwargs": {
            "scheme_map": {
                "email": ["urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"]}
        },
    },
    "template_dir": "templates",
    "token_handler_args": {
        "jwks_def": {
            "private_path": "private/token_jwks.json",
            "read_only": False,
            "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
        },
        "code": {"kwargs": {"lifetime": 600}},
        "token": {
            "class": "oidcop.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "add_claims_by_scope": True,
                "aud": ["https://example.org/appl"],
            },
        },
        "refresh": {
            "class": "oidcop.token.jwt_token.JWTToken",
            "kwargs": {"lifetime": 3600, "aud": ["https://example.org/appl"], },
        },
        "id_token": {
            "class": "oidcop.token.id_token.IDToken",
            "kwargs": {
                "base_claims": {
                    "email": {"essential": True},
                    "email_verified": {"essential": True},
                }
            },
        },
    },
    "userinfo": {"class": "oidcop.user_info.UserInfo", "kwargs": {"db_file": "users.json"}, },
    "scopes_to_claims": SCOPE2CLAIMS,
    "session_params": {
      "password": "ses_key",
      "salt": "ses_salt",
      "sub_func": {
        "public": {
          "class": "oidcop.session.manager.PublicID",
          "kwargs": {
            "salt": "mysalt"
          }
        },
        "pairwise": {
          "class": "oidcop.session.manager.PairWiseID",
          "kwargs": {
            "salt": "mysalt"
          }
        }
     }
    },
}
