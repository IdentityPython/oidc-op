from oidcop import user_info
from oidcop.oidc.authorization import Authorization
from oidcop.oidc.discovery import Discovery
from oidcop.oidc.provider_config import ProviderConfiguration
from oidcop.oidc.registration import Registration
from oidcop.oidc.session import Session
from oidcop.oidc.token import AccessToken
from oidcop.oidc.userinfo import UserInfo
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcop.user_authn.user import NoAuthn
from oidcop.user_authn.user import UserPassJinja2
from oidcop.util import JSONDictDB

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
    "request_uri_parameter_supported": True
    }

# Make sure capabilities match key set !!!
KEY_DEF = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
    ]

PORT = 8100
DOMAIN = '127.0.0.1'

BASEURL = "https://{}:{}/".format(DOMAIN, PORT)
PUBLIC_JWKS_PATH: 'https://127.0.0.1:8089/static/jwks.json'

OIDC_KEYS = {
    'private_path': "./jwks_dir/jwks.json",
    'key_defs': KEY_DEF,
    'public_path': './static/jwks.json',
    'read_only': False
    }


CONFIG = {
    'server_info': {
        "issuer": BASEURL,
        "password": "mycket hemligt",
        "token_expires_in": 600,
        "grant_expires_in": 300,
        "refresh_token_expires_in": 86400,
        "verify_ssl": False,
        "capabilities": CAPABILITIES,
        'template_dir': 'templates',
        "jwks": OIDC_KEYS,
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
                'kwargs': {'client_authn_method': None}
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
                'path': 'end_session',
                'class': Session,
                'provider_info': {
                    'check_session_iframe': "{}check_session".format(BASEURL)
                    }
                }
            },
        'userinfo': {
            'class': user_info.UserInfo,
            'kwargs': {'db_file': 'users.json'}
            },
        'authentication': [
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
            {
                'acr': 'anon',
                'class': NoAuthn,
                'kwargs': {'user': 'diana'}
                }
            ],
        'cookie_dealer': {
            'symkey': 'ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch',
            'cookie': {
                'name': 'oidc_op',
                'domain': "127.0.0.1",
                'path': '/',
                'max_age': 3600
                }
            },
        'post_logout_page': "https://{}:{}/post_logout.html".format(DOMAIN,
                                                                    PORT)
        },
    'webserver': {
        'cert': 'certs/cert.pem',
        'key': 'certs/key.pem',
        'cert_chain': '',
        'port': PORT,
        }
    }
