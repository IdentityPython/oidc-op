import json
import os
from urllib.parse import urlparse

from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import init_key_jar
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import AuthorizationResponse
import pytest

from oidcop import user_info
from oidcop.client_authn import verify_client
from oidcop.configure import OPConfiguration
from oidcop.oauth2.authorization import Authorization
from oidcop.oidc.provider_config import ProviderConfiguration
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
                "jarm": {
                    "function": "oidcop.oauth2.add_on.jarm.add_support",
                    "kwargs": {
                        "signed_response_alg": "ES256"
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
                "provider_config": {
                    "path": ".well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "authorization": {
                    "path": "authorization",
                    "class": Authorization,
                    "kwargs": {},
                },
                "token": {
                    "path": "token",
                    "class": Token,
                    "kwargs": {}
                },
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
        self.server = Server(OPConfiguration(conf, base_path=BASEDIR), keyjar=KEYJAR)
        self.endpoint_context = self.server.endpoint_context
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        self.endpoint = self.server.server_get("endpoint", "authorization")

    def test_process_request(self):
        _context = self.endpoint.server_get("endpoint_context")
        assert _context.add_on["jarm"] == {"signed_response_alg": "ES256"}

        _request = AUTH_REQ.copy()
        _request["response_mode"] = "query.jwt"
        _pr_resp = self.endpoint.parse_request(_request)
        _args = self.endpoint.process_request(_pr_resp)
        _resp = self.endpoint.do_response(request=_request, **_args)
        parse_res = urlparse(_resp["response"])
        _payload = AuthorizationResponse().from_urlencoded(parse_res.query)
        assert 'response' in _payload
        _jws = factory(_payload["response"])
        assert _jws
        _jarm = _jws.jwt.payload()
        assert _jarm['iss'] == ISSUER
        assert _jarm["aud"] == ["client_1"]


    def test_process_request_2(self):
        _request = AUTH_REQ.copy()
        _request["response_mode"] = "jwt"
        _pr_resp = self.endpoint.parse_request(_request)
        _args = self.endpoint.process_request(_pr_resp)
        _resp = self.endpoint.do_response(request=_request, **_args)
        parse_res = urlparse(_resp["response"])
        _payload = AuthorizationResponse().from_urlencoded(parse_res.query)
        assert 'response' in _payload
        _jws = factory(_payload["response"])
        assert _jws
        _jarm = _jws.jwt.payload()
        assert _jarm['iss'] == ISSUER
        assert _jarm["aud"] == ["client_1"]

    def test_provider_info(self):
        _provider_endpoint = self.server.server_get("endpoint", "provider_config")
        args = _provider_endpoint.process_request()
        msg = _provider_endpoint.do_response(args["response_args"])
        assert isinstance(msg, dict)
        _msg = json.loads(msg["response"])
        assert "authorization_signed_response_alg" in _msg

