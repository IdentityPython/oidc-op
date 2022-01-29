import os

from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import init_key_jar
from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.time_util import utc_time_sans_frac

from oidcop.authn_event import create_authn_event
import pytest

from oidcop import user_info
from oidcop.client_authn import verify_client
from oidcop.configure import OPConfiguration
from oidcop.oauth2.authorization import Authorization
from oidcop.oidc.token import Token
from oidcop.server import Server
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD


KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

ISSUER = "https://example.com/"

KEYJAR = init_key_jar(key_defs=KEYDEFS, issuer_id=ISSUER)
KEYJAR.import_jwks(KEYJAR.export_jwks(True, ISSUER), "")

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

CAPABILITIES = {
    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt",
    ],
    "response_modes_supported": ["query", "fragment", "form_post"],
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
    ],
    "claim_types_supported": ["normal", "aggregated", "distributed"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
}

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

BASEDIR = os.path.abspath(os.path.dirname(__file__))


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": ISSUER,
            "httpc_params": {"verify": False, "timeout": 1},
            "capabilities": CAPABILITIES,
            "add_on": {
                "extra_args": {
                    "function": "oidcop.oauth2.add_on.extra_args.add_support",
                    "kwargs": {
                        "authorization": {"iss": "issuer"}
                    }
                },
            },
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "token_handler_args": {
                "jwks_file": "private/token_jwks.json",
                "code": {"lifetime": 600},
                "token": {
                    "class": "oidcop.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "base_claims": {"eduperson_scoped_affiliation": None},
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
            "endpoint": {
                "authorization": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {},
                },
                "token": {
                    "path": "{}/token",
                    "class": Token,
                    "kwargs": {}},
            },
            "client_authn": verify_client,
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "oidcop.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
            "userinfo": {
                "class": user_info.UserInfo,
                "kwargs": {"db_file": "users.json"},
            },
        }
        server = Server(OPConfiguration(conf, base_path=BASEDIR), keyjar=KEYJAR)
        self.endpoint_context = server.endpoint_context
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        self.endpoint = server.server_get("endpoint", "authorization")

    def test_process_request(self):
        _context = self.endpoint.server_get("endpoint_context")
        assert _context.add_on["extra_args"] == {'authorization': {'iss': 'issuer'}}

        _pr_resp = self.endpoint.parse_request(AUTH_REQ.to_dict())
        _resp = self.endpoint.process_request(_pr_resp)
        assert set(_resp.keys()) == {
            "response_args",
            "fragment_enc",
            "return_uri",
            "cookie",
            "session_id",
        }

        assert 'iss' in _resp["response_args"]
        assert _resp["response_args"]["iss"] == _context.issuer
