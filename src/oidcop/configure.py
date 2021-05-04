"""Configuration management for IDP"""
import importlib
import json
import logging
import os
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


def create_from_config_file(cls, filename: str,
                            base_path: str = '',
                            file_attributes: Optional[List[str]] = None,
                            domain: Optional[str] = "localhost",
                            port: Optional[int] = 80):
    if filename.endswith(".yaml"):
        """Load configuration as YAML"""
        return cls(load_yaml_config(filename),
                   base_path=base_path, file_attributes=file_attributes,
                   domain=domain, port=port)
    elif filename.endswith(".json"):
        _str = open(filename).read()
        return cls(json.loads(_str),
                   base_path=base_path, file_attributes=file_attributes, domain=domain, port=port)
    elif filename.endswith(".py"):
        head, tail = os.path.split(filename)
        tail = tail[:-3]
        module = importlib.import_module(tail)
        _cnf = getattr(module, "CONFIG")

        # _str = open(filename).read()
        # _cnf = ast.literal_eval(_str)
        return cls(_cnf, base_path=base_path, file_attributes=file_attributes,
                   domain=domain, port=port)


class Configuration:
    """Server Configuration"""

    def __init__(self,
                 conf: Dict,
                 base_path: str = '',
                 file_attributes: Optional[List[str]] = None,
                 domain: Optional[str] = "",
                 port: Optional[int] = 0
                 ):

        log_conf = conf.get('logging')
        if log_conf:
            self.logger = configure_logging(config=log_conf).getChild(__name__)
        else:
            self.logger = logging.getLogger('oidcop')

        if file_attributes is None:
            file_attributes = DEFAULT_FILE_ATTRIBUTE_NAMES

        if base_path and file_attributes:
            # this adds a base path to all paths in the configuration
            add_base_path(conf, base_path, file_attributes)

        self.webserver = conf.get("webserver", {})
        if domain:
            args = {"domain": domain}
        else:
            args = {"domain": conf.get("domain", "127.0.0.1")}

        if port:
            args["port"] = port
        else:
            args["port"] = conf.get("port", 80)

        self.op = OPConfiguration(conf["op"]["server_info"], **args)

    def __getitem__(self, item):
        if item in self.__dict__:
            return self.__dict__[item]
        else:
            raise KeyError

    def get(self, item, default=None):
        return getattr(self, item, default)

    def __contains__(self, item):
        return item in self.__dict__


class OPConfiguration(object):
    "Provider configuration"

    def __init__(self,
                 conf: Dict,
                 base_path: Optional[str] = '',
                 domain: Optional[str] = "127.0.0.1",
                 port: Optional[int] = 80,
                 file_attributes: Optional[List[str]] = None,
                 ):

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

        if file_attributes is None:
            file_attributes = DEFAULT_FILE_ATTRIBUTE_NAMES

        if base_path and file_attributes:
            # this adds a base path to all paths in the configuration
            add_base_path(conf, base_path, file_attributes)

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

    def __getitem__(self, item):
        if item in self.__dict__:
            return self.__dict__[item]
        else:
            raise KeyError

    def get(self, item, default=None):
        return getattr(self, item, default)

    def __contains__(self, item):
        return item in self.__dict__


c = {
    "add_on": {
        "pkce": {
            "function": "oidcop.oidc.add_on.pkce.add_pkce_support",
            "kwargs": {
                "essential": False,
                "code_challenge_method": "S256 S384 S512"
            }
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
                    "eduperson_scoped_affiliation"
                ]
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
    "authentication": {
        "user": {
            "acr": "oidcop.user_authn.authn_context.INTERNETPROTOCOLPASSWORD",
            "class": "oidcop.user_authn.user.UserPassJinja2",
            "kwargs": {
                "verify_endpoint": "verify/user",
                "template": "user_pass.jinja2",
                "db": {
                    "class": "oidcop.util.JSONDictDB",
                    "kwargs": {
                        "filename": "passwd.json"
                    }
                },
                "page_header": "Testing log in",
                "submit_btn": "Get me in!",
                "user_label": "Nickname",
                "passwd_label": "Secret sauce"
            }
        }
    },
    "capabilities": {
        "subject_types_supported": [
            "public",
            "pairwise"
        ],
        "grant_types_supported": [
            "authorization_code",
            "implicit",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "refresh_token"
        ]
    },
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
    "endpoint": {
        "webfinger": {
            "path": ".well-known/webfinger",
            "class": "oidcop.oidc.discovery.Discovery",
            "kwargs": {
                "client_authn_method": None
            }
        },
        "provider_info": {
            "path": ".well-known/openid-configuration",
            "class": "oidcop.oidc.provider_config.ProviderConfiguration",
            "kwargs": {
                "client_authn_method": None
            }
        },
        "registration": {
            "path": "registration",
            "class": "oidcop.oidc.registration.Registration",
            "kwargs": {
                "client_authn_method": None,
                "client_secret_expiration_time": 432000
            }
        },
        "registration_api": {
            "path": "registration_api",
            "class": "oidcop.oidc.read_registration.RegistrationRead",
            "kwargs": {
                "client_authn_method": [
                    "bearer_header"
                ]
            }
        },
        "introspection": {
            "path": "introspection",
            "class": "oidcop.oauth2.introspection.Introspection",
            "kwargs": {
                "client_authn_method": [
                    "client_secret_post"
                ],
                "release": [
                    "username"
                ]
            }
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
                    "none"
                ],
                "response_modes_supported": [
                    "query",
                    "fragment",
                    "form_post"
                ]
            }
        },
        "token": {
            "path": "token",
            "class": "oidcop.oidc.token.Token",
            "kwargs": {
                "client_authn_method": [
                    "client_secret_post",
                    "client_secret_basic",
                    "client_secret_jwt",
                    "private_key_jwt"
                ]
            }
        },
        "userinfo": {
            "path": "userinfo",
            "class": "oidcop.oidc.userinfo.UserInfo",
            "kwargs": {
                "claim_types_supported": [
                    "normal",
                    "aggregated",
                    "distributed"
                ]
            }
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
                "check_session_iframe": "check_session_iframe"
            }
        }
    },
    "httpc_params": {
        "verify": False
    },
    "id_token": {
        "class": "oidcop.id_token.IDToken",
        "kwargs": {
            "default_claims": {
                "email": {
                    "essential": True
                },
                "email_verified": {
                    "essential": True
                }
            }
        }
    },
    "issuer": "https://{domain}:{port}",
    "keys": {
        "private_path": "private/jwks.json",
        "key_defs": [
            {
                "type": "RSA",
                "use": [
                    "sig"
                ]
            },
            {
                "type": "EC",
                "crv": "P-256",
                "use": [
                    "sig"
                ]
            }
        ],
        "public_path": "static/jwks.json",
        "read_only": False,
        "uri_path": "static/jwks.json"
    },
    "login_hint2acrs": {
        "class": "oidcop.login_hint.LoginHint2Acrs",
        "kwargs": {
            "scheme_map": {
                "email": [
                    "oidcop.user_authn.authn_context.INTERNETPROTOCOLPASSWORD"
                ]
            }
        }
    },
    "session_key": {
        "filename": "private/session_jwk.json",
        "type": "OCT",
        "use": "sig"
    },
    "template_dir": "templates",
    "token_handler_args": {
        "jwks_def": {
            "private_path": "private/token_jwks.json",
            "read_only": False,
            "key_defs": [
                {
                    "type": "oct",
                    "bytes": 24,
                    "use": [
                        "enc"
                    ],
                    "kid": "code"
                },
                {
                    "type": "oct",
                    "bytes": 24,
                    "use": [
                        "enc"
                    ],
                    "kid": "refresh"
                }
            ]
        },
        "code": {
            "kwargs": {
                "lifetime": 600
            }
        },
        "token": {
            "class": "oidcop.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "add_claims": [
                    "email",
                    "email_verified",
                    "phone_number",
                    "phone_number_verified"
                ],
                "add_claim_by_scope": True,
                "aud": [
                    "https://example.org/appl"
                ]
            }
        },
        "refresh": {
            "kwargs": {
                "lifetime": 86400
            }
        }
    },
    "userinfo": {
        "class": "oidcop.user_info.UserInfo",
        "kwargs": {
            "db_file": "users.json"
        }
    }
}
