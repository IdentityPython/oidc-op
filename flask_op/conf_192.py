from oidcendpoint import user_info

from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.discovery import Discovery
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.session import Session
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.oidc.userinfo import UserInfo
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_authn.authn_context import UNSPECIFIED
from oidcendpoint.user_authn.user import NoAuthn
from oidcendpoint.user_authn.user import UserPassJinja2

from oidcop.util import JSONDictDB

SESSION_COOKIE_NAME = 'flop'

RESPONSE_TYPES_SUPPORTED = [
    ["code"], ["token"], ["id_token"], ["code", "token"], ["code", "id_token"],
    ["id_token", "token"], ["code", "token", "id_token"], ['none']]

CAPABILITIES = {
    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post", "client_secret_basic",
        "client_secret_jwt", "private_key_jwt"],
    "response_modes_supported": ['query', 'fragment', 'form_post'],
    "subject_types_supported": ["public", "pairwise"],
    "grant_types_supported": [
        "authorization_code", "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer", "refresh_token"],
    "claim_types_supported": ["normal", "aggregated", "distributed"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
    "frontchannel_logout_supported": True,
    "frontchannel_logout_session_supported": True,
    "backchannel_logout_supported": True,
    "backchannel_logout_session_supported": True
}

KEY_DEF = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

PORT = 5000
DOMAIN = '192.168.1.109'
SERVER_NAME = '{}:{}'.format(DOMAIN, str(PORT))
BASE_URL = 'https://{}'.format(SERVER_NAME)

PATH = {
    'userinfo:kwargs:db_file': '{}/users.json',
    'authentication:user:kwargs:db:kwargs:json_path': '{}/passwd.json'
}


CONFIG = {
    'provider': {
        'key_defs': [
            {"type": "RSA", "use": ["sig"]},
            {"type": "EC", "crv": "P-256", "use": ["sig"]}
        ],
    },
    'server_info': {
        "issuer": BASE_URL,
        "password": "mycket hemlig information",
        "token_expires_in": 600,
        "grant_expires_in": 300,
        "refresh_token_expires_in": 86400,
        "verify_ssl": False,
        "capabilities": CAPABILITIES,
        'template_dir': 'templates',
        "jwks": {
            'private_path': 'own/jwks.json',
            'key_defs': KEY_DEF,
            'public_path': 'static/jwks.json'
        },
        'endpoint': {
            'webfinger': {
                'path': '.well-known/webfinger',
                'class': Discovery,
                'kwargs': {'client_authn_method': None}
            },
            'provider_info': {
                'path': '.well-known/openid-configuration',
                'class': ProviderConfiguration,
                'kwargs': {'client_authn_method': None}
            },
            'registration': {
                'path': 'registration',
                'class': Registration,
                'kwargs': {
                    'client_authn_method': None,
                    'client_secret_expiration_time': 5*86400
                }
            },
            'authorization': {
                'path': 'authorization',
                'class': Authorization,
                'kwargs': {'client_authn_method': None}
            },
            'token': {
                'path': 'token',
                'class': AccessToken,
                'kwargs': {}
            },
            'userinfo': {
                'path': 'userinfo',
                'class': UserInfo,
            },
            'end_session': {
                'path': 'session',
                'class': Session,
                'kwargs': {
                    'logout_uri': "{}/verify_logout".format(BASE_URL),
                    'post_logout_uri': "{}/post_logout".format(BASE_URL),
                    'signing_alg': "ES256"
                }
            }
        },
        'userinfo': {
            'class': user_info.UserInfo,
            'kwargs': {'db_file': 'users.json'}
        },
        'authentication': {
            'user':
                {
                    'acr': INTERNETPROTOCOLPASSWORD,
                    'class': UserPassJinja2,
                    'kwargs': {
                        'template': 'user_pass.jinja2',
                        'sym_key': '24AA/LR6HighEnergy',
                        'db': {
                            'class': JSONDictDB,
                            'kwargs':
                                {'json_path': 'passwd.json'}
                        },
                        'page_header': "Testing log in",
                        'submit_btn': "Get me in!",
                        'user_label': "Nickname",
                        'passwd_label': "Secret sauce"
                    }
                },
            'anon':
                {
                    'acr': UNSPECIFIED,
                    'class': NoAuthn,
                    'kwargs': {'user': 'diana'}
                }
        },
        'cookie_dealer': {
            'symkey': 'ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch',
            'default_values': {
                'name': 'oidc_op',
                'domain': DOMAIN,
                'path': '/',
                'max_age': 3600
            }
        }
    },
    'webserver': {
        'cert': '{}/certs/cert.pem',
        'key': '{}/certs/key.pem',
        'cert_chain': '',
        'port': PORT,
    }
}
