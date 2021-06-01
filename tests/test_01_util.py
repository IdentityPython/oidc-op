from oidcop.oidc.authorization import Authorization
from oidcop.oidc.provider_config import ProviderConfiguration
from oidcop.oidc.registration import Registration
from oidcop.oidc.token import Token
from oidcop.oidc.userinfo import UserInfo
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

conf = {
    "issuer": "https://example.com/",
    "password": "mycket hemligt",
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "verify_ssl": False,
    "capabilities": {},
    "jwks_uri": "https://example.com/jwks.json",
    "keys": {"private_path": "own/jwks.json", "key_defs": KEYDEFS, "uri_path": "static/jwks.json",},
    "endpoint": {
        "provider_config": {
            "path": ".well-known/openid-configuration",
            "class": ProviderConfiguration,
            "kwargs": {},
        },
        "registration_endpoint": {"path": "registration", "class": Registration, "kwargs": {},},
        "authorization_endpoint": {"path": "authorization", "class": Authorization, "kwargs": {},},
        "token_endpoint": {"path": "token", "class": Token, "kwargs": {}},
        "userinfo_endpoint": {
            "path": "userinfo",
            "class": UserInfo,
            "kwargs": {"db_file": "users.json"},
        },
    },
    "authentication": {
        "anon": {
            "acr": INTERNETPROTOCOLPASSWORD,
            "class": "oidcop.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
    "template_dir": "template",
}
