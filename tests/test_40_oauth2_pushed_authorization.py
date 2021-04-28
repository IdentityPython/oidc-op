import io

from cryptojwt import JWT
from cryptojwt.jwt import remove_jwt_parameters
from cryptojwt.key_jar import init_key_jar
from oidcmsg.message import Message
from oidcmsg.oauth2 import AuthorizationRequest
import pytest
import yaml

from oidcop.cookie_handler import CookieHandler
from oidcop.id_token import IDToken
from oidcop.oauth2.authorization import Authorization
from oidcop.oauth2.pushed_authorization import PushedAuthorization
from oidcop.oidc.provider_config import ProviderConfiguration
from oidcop.oidc.registration import Registration
from oidcop.server import Server

CAPABILITIES = {
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ],
}

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]}
    # {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["token"],
    ["id_token"],
    ["code", "token"],
    ["code", "id_token"],
    ["id_token", "token"],
    ["code", "token", "id_token"],
    ["none"],
]

client_yaml = """
oidc_clients:
  s6BhdRkqt3:
    "client_secret": 7Fjfp0ZBr1KtDRbnfVdmIw
    "redirect_uris": 
        - ['https://client.example.org/cb', '']
    "client_salt": "salted"
    'token_endpoint_auth_method': 'client_secret_post'
    'response_types': 
        - 'code'
        - 'token'
        - 'code id_token'
        - 'id_token'
        - 'code id_token token'
"""

AUTHN_REQUEST = (
    "response_type=code&state=af0ifjsldkj&client_id=s6BhdRkqt3&redirect_uri"
    "=https%3A%2F%2Fclient.example.org%2Fcb&code_challenge=K2"
    "-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U&code_challenge_method=S256"
    "&scope=ais"
)


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt zebra",
            "token_handler_args": {
                "jwks_def": {
                    "private_path": "private/token_jwks.json",
                    "read_only": False,
                    "key_defs": [
                        {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "code"},
                        {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "refresh"},
                    ],
                },
                "code": {"lifetime": 600},
                "token": {
                    "class": "oidcop.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "add_claims": [
                            "email",
                            "email_verified",
                            "phone_number",
                            "phone_number_verified",
                        ],
                        "add_claim_by_scope": True,
                        "aud": ["https://example.org/appl"],
                    },
                },
                "refresh": {"lifetime": 86400},
            },
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
            "id_token": {
                "class": IDToken,
                "kwargs": {
                    "available_claims": {
                        "email": {"essential": True},
                        "email_verified": {"essential": True},
                    }
                },
            },
            "endpoint": {
                "provider_config": {
                    "path": ".well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "registration": {
                    "path": "registration",
                    "class": Registration,
                    "kwargs": {},
                },
                "authorization": {
                    "path": "authorization",
                    "class": Authorization,
                    "kwargs": {
                        "response_types_supported": [
                            " ".join(x) for x in RESPONSE_TYPES_SUPPORTED
                        ],
                        "response_modes_supported": ["query", "fragment", "form_post"],
                        "claims_parameter_supported": True,
                        "request_parameter_supported": True,
                        "request_uri_parameter_supported": True,
                    },
                },
                "pushed_authorization": {
                    "path": "pushed_authorization",
                    "class": PushedAuthorization,
                    "kwargs": {
                        "client_authn_method": [
                            "client_secret_post",
                            "client_secret_basic",
                            "client_secret_jwt",
                            "private_key_jwt",
                        ]
                    },
                },
            },
            "authentication": {
                "anon": {
                    "acr": "http://www.swamid.se/policy/assurance/al1",
                    "class": "oidcop.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
            "cookie_handler": {
                "class": CookieHandler,
                "kwargs": {
                    "sign_key": "ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch",
                    "name": {
                        "session": "oidc_op",
                        "register": "oidc_op_reg",
                        "session_management": "oidc_op_sman"
                    },
                },
            },
        }
        server = Server(conf)
        endpoint_context = server.endpoint_context
        _clients = yaml.safe_load(io.StringIO(client_yaml))
        endpoint_context.cdb = _clients["oidc_clients"]
        endpoint_context.keyjar.import_jwks(
            endpoint_context.keyjar.export_jwks(True, ""), conf["issuer"]
        )

        self.rp_keyjar = init_key_jar(key_defs=KEYDEFS, issuer_id="s6BhdRkqt3")
        # Add RP's keys to the OP's keyjar
        endpoint_context.keyjar.import_jwks(
            self.rp_keyjar.export_jwks(issuer_id="s6BhdRkqt3"), "s6BhdRkqt3"
        )

        self.pushed_authorization_endpoint = server.server_get("endpoint", "pushed_authorization")
        self.authorization_endpoint = server.server_get("endpoint", "authorization")

    def test_init(self):
        assert self.pushed_authorization_endpoint

    def test_pushed_auth_urlencoded(self):
        http_info = {
            "headers": {"authorization": "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3"}}

        _req = self.pushed_authorization_endpoint.parse_request(AUTHN_REQUEST, http_info=http_info)

        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {
            "state",
            "redirect_uri",
            "response_type",
            "scope",
            "code_challenge_method",
            "client_id",
            "code_challenge",
        }

    def test_pushed_auth_request(self):
        _msg = Message().from_urlencoded(AUTHN_REQUEST)
        _jwt = JWT(key_jar=self.rp_keyjar, iss="s6BhdRkqt3")
        _jws = _jwt.pack(_msg.to_dict())

        authn_request = "request={}".format(_jws)
        http_info = {
            "headers": {"authorization": "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3"}}

        _req = self.pushed_authorization_endpoint.parse_request(authn_request, http_info=http_info)

        assert isinstance(_req, AuthorizationRequest)
        _req = remove_jwt_parameters(_req)
        assert set(_req.keys()) == {
            "state",
            "redirect_uri",
            "response_type",
            "scope",
            "code_challenge_method",
            "client_id",
            "code_challenge",
            "request",
            "__verified_request",
        }

    def test_pushed_auth_urlencoded_process(self):
        http_info = {
            "headers": {"authorization": "Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3"}}

        _req = self.pushed_authorization_endpoint.parse_request(AUTHN_REQUEST, http_info=http_info)

        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == {
            "state",
            "redirect_uri",
            "response_type",
            "scope",
            "code_challenge_method",
            "client_id",
            "code_challenge",
        }

        _resp = self.pushed_authorization_endpoint.process_request(_req)

        _msg = Message().from_urlencoded(AUTHN_REQUEST)
        assert _resp["return_uri"] == _msg["redirect_uri"]

        # And now for the authorization request with the OP provided request_uri

        _msg["request_uri"] = _resp["http_response"]["request_uri"]
        for parameter in ["code_challenge", "code_challenge_method"]:
            del _msg[parameter]

        _req = self.authorization_endpoint.parse_request(_msg)

        assert "code_challenge" in _req
