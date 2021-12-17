"""Configuration management for OP"""
import copy
import logging
import os
from typing import Dict
from typing import List
from typing import Optional

from oidcmsg.configure import Base

from oidcop.scopes import SCOPE2CLAIMS

logger = logging.getLogger(__name__)

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
            "name": {
                "session": "oidc_op",
                "register": "oidc_op_rp",
                "session_management": "sman",
            },
        },
    },
    "claims_interface": {"class": "oidcop.session.claims.ClaimsInterface", "kwargs": {}},
    "authz": {
        "class": "oidcop.authz.AuthzHandling",
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": [
                            "access_token",
                            "refresh_token",
                            "id_token",
                        ],
                        "max_usage": 1,
                    },
                    "access_token": {},
                    "refresh_token": {
                        "supports_minting": ["access_token", "refresh_token"],
                        "expires_in": -1,
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
        "token": {
            "class": "oidcop.token.jwt_token.JWTToken",
            "kwargs": {"lifetime": 3600},
        },
        "refresh": {
            "class": "oidcop.token.jwt_token.JWTToken",
            "kwargs": {"lifetime": 86400},
        },
        "id_token": {"class": "oidcop.token.id_token.IDToken", "kwargs": {}},
    },
    "scopes_to_claims": SCOPE2CLAIMS,
}

AS_DEFAULT_CONFIG = copy.deepcopy(OP_DEFAULT_CONFIG)
AS_DEFAULT_CONFIG["claims_interface"] = {
    "class": "oidcop.session.claims.OAuth2ClaimsInterface",
    "kwargs": {},
}


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
            dir_attributes: Optional[List[str]] = None,
    ):

        conf = copy.deepcopy(conf)
        Base.__init__(self, conf, base_path, file_attributes, dir_attributes=dir_attributes)

        for key in self.parameter.keys():
            _val = conf.get(key)
            if not _val:
                if key in self.default_config:
                    _val = copy.deepcopy(self.default_config[key])
                    self.format(
                        _val,
                        base_path=base_path,
                        file_attributes=file_attributes,
                        domain=domain,
                        port=port,
                        dir_attributes=dir_attributes
                    )
                else:
                    continue

            if key not in DEFAULT_EXTENDED_CONF:
                logger.warning(f"{key} not seems to be a valid configuration parameter")
            elif not _val:
                logger.warning(f"{key} not configured, using default configuration values")

            if key == "template_dir":
                _val = os.path.abspath(_val)
            if key == "keys":
                key = "key_conf"

            setattr(self, key, _val)


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
            dir_attributes: Optional[List[str]] = None,
    ):
        super().__init__(
            conf=conf,
            base_path=base_path,
            entity_conf=entity_conf,
            domain=domain,
            port=port,
            file_attributes=file_attributes,
            dir_attributes=dir_attributes
        )


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
            dir_attributes: Optional[List[str]] = None,
    ):
        EntityConfiguration.__init__(
            self,
            conf=conf,
            base_path=base_path,
            entity_conf=entity_conf,
            domain=domain,
            port=port,
            file_attributes=file_attributes,
            dir_attributes=dir_attributes
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
                        "supports_minting": [
                            "access_token",
                            "refresh_token",
                            "id_token",
                        ],
                        "max_usage": 1,
                    },
                    "access_token": {},
                    "refresh_token": {
                        "supports_minting": ["access_token", "refresh_token"],
                        "expires_in": -1,
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
                "db": {
                    "class": "oidcop.util.JSONDictDB",
                    "kwargs": {"filename": "passwd.json"},
                },
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
            "name": {
                "session": "oidc_op",
                "register": "oidc_op_rp",
                "session_management": "sman",
            },
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
            "kwargs": {
                "client_authn_method": None,
                "client_secret_expiration_time": 432000,
            },
        },
        "registration_api": {
            "path": "registration_api",
            "class": "oidcop.oidc.read_registration.RegistrationRead",
            "kwargs": {"client_authn_method": ["bearer_header"]},
        },
        "introspection": {
            "path": "introspection",
            "class": "oidcop.oauth2.introspection.Introspection",
            "kwargs": {
                "client_authn_method": ["client_secret_post"],
                "release": ["username"],
            },
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
                "email": ["urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"]
            }
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
            "kwargs": {
                "lifetime": 3600,
                "aud": ["https://example.org/appl"],
            },
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
    "userinfo": {
        "class": "oidcop.user_info.UserInfo",
        "kwargs": {"db_file": "users.json"},
    },
    "scopes_to_claims": SCOPE2CLAIMS,
    "session_params": {
        "password": "ses_key",
        "salt": "ses_salt",
        "sub_func": {
            "public": {"class": "oidcop.session.manager.PublicID", "kwargs": {"salt": "mysalt"}},
            "pairwise": {
                "class": "oidcop.session.manager.PairWiseID",
                "kwargs": {"salt": "mysalt"},
            },
        },
    },
}
