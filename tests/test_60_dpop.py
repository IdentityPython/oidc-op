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
from oidcop.oauth2.add_on.dpop import DPoPProof
from oidcop.oauth2.add_on.dpop import post_parse_request
from oidcop.oauth2.authorization import Authorization
from oidcop.oidc.token import Token
from oidcop.server import Server
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD

DPOP_HEADER = (
    "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMz"
    "R0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFq"
    "SG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwia"
    "HRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY"
    "yNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
)


def test_verify_header():
    _dpop = DPoPProof()
    assert _dpop.verify_header(DPOP_HEADER)
    assert set(_dpop.keys()) == {'typ', 'alg', 'jwk', 'jti', 'htm', 'htu', 'iat'}
    assert _dpop.verify() is None

    _dpop_dict = _dpop.to_dict()
    _dpop2 = DPoPProof().from_dict(_dpop_dict)
    assert isinstance(_dpop2.key, ECKey)

    ec_key = new_ec_key(crv="P-256")
    _dpop2.key = ec_key
    _dpop2["jwk"] = ec_key.to_dict()

    _header = _dpop2.create_header()

    _dpop3 = DPoPProof()
    assert _dpop3.verify_header(_header)
    # should have the same content as _dpop only the key is different

    assert _dpop["htm"] == _dpop3["htm"]


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

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
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
                "dpop": {
                    "function": "oidcop.oauth2.add_on.dpop.add_support",
                    "kwargs": {
                        "dpop_signing_alg_values_supported": ["ES256"]
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
        self.user_id = "diana"
        self.token_endpoint = server.server_get("endpoint", "token")
        self.session_manager = self.endpoint_context.session_manager

    def _create_session(self, auth_req, sub_type="public", sector_identifier=""):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req
        client_id = authz_req["client_id"]
        ae = create_authn_event(self.user_id)
        return self.session_manager.create_session(
            ae, authz_req, self.user_id, client_id=client_id, sub_type=sub_type
        )

    def _mint_code(self, grant, client_id):
        session_id = self.session_manager.encrypted_session_id(
            self.user_id, client_id, grant.id
        )
        usage_rules = grant.usage_rules.get("authorization_code", {})
        _exp_in = usage_rules.get("expires_in")

        # Constructing an authorization code is now done
        _code = grant.mint_token(
            session_id=session_id,
            endpoint_context=self.endpoint_context,
            token_class="authorization_code",
            token_handler=self.session_manager.token_handler["authorization_code"],
            usage_rules=usage_rules,
        )

        if _exp_in:
            if isinstance(_exp_in, str):
                _exp_in = int(_exp_in)
            if _exp_in:
                _code.expires_at = utc_time_sans_frac() + _exp_in
        return _code

    def test_post_parse_request(self):
        auth_req = post_parse_request(AUTH_REQ, AUTH_REQ["client_id"], self.endpoint_context,
                                      http_info={
                                          "headers": {"dpop": DPOP_HEADER},
                                          "url": 'https://server.example.com/token',
                                          "method": "POST"
                                      })
        assert auth_req
        assert "dpop_jkt" in auth_req

    def test_process_request(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, AUTH_REQ["client_id"])

        _token_request = TOKEN_REQ.to_dict()
        _context = self.endpoint_context
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(_token_request, http_info={
            "headers": {"dpop": DPOP_HEADER},
            "url": 'https://server.example.com/token',
            "method": "POST"
        })

        assert "dpop_jkt" in _req

        _resp = self.token_endpoint.process_request(request=_req)
        assert _resp["response_args"]["token_type"] == "DPoP"

        access_token = _resp["response_args"]["access_token"]
        jws = factory(access_token)
        _payload = jws.jwt.payload()
        assert "cnf" in _payload
        assert _payload["cnf"]["jkt"] == _req["dpop_jkt"]

        # Make sure DPoP also is in the session access token instance.
        _session_info = self.session_manager.get_session_info_by_token(access_token)
        _token = self.session_manager.find_token(_session_info["session_id"], access_token)
        assert _token.token_type == "DPoP"
