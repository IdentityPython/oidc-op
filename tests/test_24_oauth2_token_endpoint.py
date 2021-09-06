import json
import os

from cryptojwt import JWT
from cryptojwt.key_jar import build_keyjar
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import RefreshAccessTokenRequest
from oidcmsg.oidc import TokenErrorResponse
from oidcmsg.time_util import utc_time_sans_frac
import pytest

from oidcop import JWT_BEARER
from oidcop.authn_event import create_authn_event
from oidcop.authz import AuthzHandling
from oidcop.client_authn import verify_client
from oidcop.configure import ASConfiguration
from oidcop.exception import UnAuthorizedClient
from oidcop.oauth2.authorization import Authorization
from oidcop.oauth2.token import Token
from oidcop.server import Server
from oidcop.session import MintingNotAllowed
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcop.user_info import UserInfo

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLIENT_KEYJAR = build_keyjar(KEYDEFS)

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["token"],
]

CAPABILITIES = {
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ],
}

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["email"],
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

REFRESH_TOKEN_REQ = RefreshAccessTokenRequest(
    grant_type="refresh_token", client_id="client_1", client_secret="hemligt"
)

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO = UserInfo(json.loads(open(full_path("users.json")).read()))


@pytest.fixture
def conf():
    return {
        "issuer": "https://example.com/",
        "password": "mycket hemligt",
        "verify_ssl": False,
        "capabilities": CAPABILITIES,
        "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
        "token_handler_args": {
            "jwks_file": "private/token_jwks.json",
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
                "kwargs": {"lifetime": 3600, "aud": ["https://example.org/appl"],},
            },
        },
        "endpoint": {
            "authorization": {"path": "authorization", "class": Authorization, "kwargs": {},},
            "token": {
                "path": "token",
                "class": Token,
                "kwargs": {
                    "client_authn_method": [
                        "client_secret_basic",
                        "client_secret_post",
                        "client_secret_jwt",
                        "private_key_jwt",
                    ]
                },
            },
        },
        "authentication": {
            "anon": {
                "acr": INTERNETPROTOCOLPASSWORD,
                "class": "oidcop.user_authn.user.NoAuthn",
                "kwargs": {"user": "diana"},
            }
        },
        "userinfo": {"class": UserInfo, "kwargs": {"db": {}}},
        "client_authn": verify_client,
        "template_dir": "template",
        "claims_interface": {"class": "oidcop.session.claims.OAuth2ClaimsInterface", "kwargs": {}},
        "authz": {
            "class": AuthzHandling,
            "kwargs": {
                "grant_config": {
                    "usage_rules": {
                        "authorization_code": {
                            "expires_in": 300,
                            "supports_minting": ["access_token", "refresh_token"],
                            "max_usage": 1,
                        },
                        "access_token": {"expires_in": 600},
                        "refresh_token": {
                            "expires_in": 86400,
                            "supports_minting": ["access_token", "refresh_token"],
                        },
                    },
                    "expires_in": 43200,
                }
            },
        },
    }


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self, conf):
        server = Server(ASConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
        endpoint_context = server.endpoint_context
        endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        endpoint_context.keyjar.import_jwks(CLIENT_KEYJAR.export_jwks(), "client_1")
        self.session_manager = endpoint_context.session_manager
        self.token_endpoint = server.server_get("endpoint", "token")
        self.user_id = "diana"
        self.endpoint_context = endpoint_context

    def test_init(self):
        assert self.token_endpoint

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
        session_id = self.session_manager.encrypted_session_id(self.user_id, client_id, grant.id)
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

    def _mint_access_token(self, grant, session_id, token_ref=None):
        _session_info = self.session_manager.get_session_info(session_id)
        usage_rules = grant.usage_rules.get("access_token", {})
        _exp_in = usage_rules.get("expires_in", 0)

        _token = grant.mint_token(
            _session_info,
            endpoint_context=self.endpoint_context,
            token_class="access_token",
            token_handler=self.session_manager.token_handler["access_token"],
            based_on=token_ref,  # Means the token (tok) was used to mint this token
            usage_rules=usage_rules,
        )
        if isinstance(_exp_in, str):
            _exp_in = int(_exp_in)
        if _exp_in:
            _token.expires_at = utc_time_sans_frac() + _exp_in

        return _token

    def test_parse(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, AUTH_REQ["client_id"])

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(_token_request)

        assert set(_req.keys()) == set(_token_request.keys())

    def test_process_request(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, AUTH_REQ["client_id"])

        _token_request = TOKEN_REQ_DICT.copy()
        _context = self.endpoint_context
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req)

        assert _resp
        assert set(_resp.keys()) == {"cookie", "http_headers", "response_args"}

    def test_process_request_using_code_twice(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, AUTH_REQ["client_id"])

        _token_request = TOKEN_REQ_DICT.copy()
        _context = self.endpoint_context
        _token_request["code"] = code.value

        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req)

        # 2nd time used
        _2nd_response = self.token_endpoint.parse_request(_token_request)
        assert "error" in _2nd_response

    def test_do_response(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, AUTH_REQ["client_id"])

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(_token_request)

        _resp = self.token_endpoint.process_request(request=_req)
        msg = self.token_endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg, dict)

    def test_process_request_using_private_key_jwt(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, AUTH_REQ["client_id"])

        _token_request = TOKEN_REQ_DICT.copy()
        del _token_request["client_id"]
        del _token_request["client_secret"]
        _context = self.endpoint_context

        _jwt = JWT(CLIENT_KEYJAR, iss=AUTH_REQ["client_id"], sign_alg="RS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [self.token_endpoint.full_path]})
        _token_request.update({"client_assertion": _assertion, "client_assertion_type": JWT_BEARER})
        _token_request["code"] = code.value

        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req)

        # 2nd time used
        with pytest.raises(UnAuthorizedClient):
            self.token_endpoint.parse_request(_token_request)

    def test_do_refresh_access_token(self):
        areq = AUTH_REQ.copy()
        areq["scope"] = ["email"]

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq["client_id"])

        _cntx = self.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req, issue_refresh=True)

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _resp["response_args"]["refresh_token"]

        _token_value = _resp["response_args"]["refresh_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)
        _token.usage_rules["supports_minting"] = ["access_token", "refresh_token"]

        _req = self.token_endpoint.parse_request(_request.to_json())
        _resp = self.token_endpoint.process_request(request=_req, issue_refresh=True)
        assert set(_resp.keys()) == {"cookie", "response_args", "http_headers"}
        assert set(_resp["response_args"].keys()) == {
            "access_token",
            "token_type",
            "expires_in",
            "refresh_token",
            "scope",
        }
        msg = self.token_endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg, dict)

    def test_do_2nd_refresh_access_token(self):
        areq = AUTH_REQ.copy()
        areq["scope"] = ["email"]

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq["client_id"])

        _cntx = self.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req, issue_refresh=True)

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _resp["response_args"]["refresh_token"]

        # Make sure ID Tokens can also be used by this refesh token
        _token_value = _resp["response_args"]["refresh_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)
        _token.usage_rules["supports_minting"] = [
            "access_token",
            "refresh_token",
        ]

        _req = self.token_endpoint.parse_request(_request.to_json())
        _resp = self.token_endpoint.process_request(request=_req, issue_refresh=True)

        _2nd_request = REFRESH_TOKEN_REQ.copy()
        _2nd_request["refresh_token"] = _resp["response_args"]["refresh_token"]
        _2nd_req = self.token_endpoint.parse_request(_request.to_json())
        _2nd_resp = self.token_endpoint.process_request(request=_req, issue_refresh=True)

        assert set(_2nd_resp.keys()) == {"cookie", "response_args", "http_headers"}
        assert set(_2nd_resp["response_args"].keys()) == {
            "access_token",
            "token_type",
            "expires_in",
            "refresh_token",
            "scope",
        }
        msg = self.token_endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg, dict)

    def test_new_refresh_token(self, conf):
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }

        areq = AUTH_REQ.copy()
        areq["scope"] = ["email"]

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq["client_id"])

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req, issue_refresh=True)
        assert "refresh_token" in _resp["response_args"]
        first_refresh_token = _resp["response_args"]["refresh_token"]

        _refresh_request = REFRESH_TOKEN_REQ.copy()
        _refresh_request["refresh_token"] = first_refresh_token
        _2nd_req = self.token_endpoint.parse_request(_refresh_request.to_json())
        _2nd_resp = self.token_endpoint.process_request(request=_2nd_req, issue_refresh=True)
        assert "refresh_token" in _2nd_resp["response_args"]
        second_refresh_token = _2nd_resp["response_args"]["refresh_token"]

        _2d_refresh_request = REFRESH_TOKEN_REQ.copy()
        _2d_refresh_request["refresh_token"] = second_refresh_token
        _3rd_req = self.token_endpoint.parse_request(_2d_refresh_request.to_json())
        _3rd_resp = self.token_endpoint.process_request(request=_3rd_req, issue_refresh=True)
        assert "access_token" in _3rd_resp["response_args"]
        assert "refresh_token" in _3rd_resp["response_args"]

        assert first_refresh_token != second_refresh_token

    def test_refresh_scopes(self):
        areq = AUTH_REQ.copy()
        areq["scope"] = ["email", "profile"]

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq["client_id"])

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req, issue_refresh=True)

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _resp["response_args"]["refresh_token"]
        _request["scope"] = ["email"]

        _req = self.token_endpoint.parse_request(_request.to_json())
        _resp = self.token_endpoint.process_request(request=_req, issue_refresh=True)
        assert set(_resp.keys()) == {"cookie", "response_args", "http_headers"}
        assert set(_resp["response_args"].keys()) == {
            "access_token",
            "token_type",
            "expires_in",
            "refresh_token",
            "scope",
        }

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        at = self.session_manager.find_token(
            _session_info["session_id"], _token_value
        )
        rt = self.session_manager.find_token(
            _session_info["session_id"], _resp["response_args"]["refresh_token"]
        )

        assert at.scope == rt.scope == _request["scope"] == _resp["response_args"]["scope"]

    def test_refresh_more_scopes(self):
        areq = AUTH_REQ.copy()
        areq["scope"] = ["email"]

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq["client_id"])

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req, issue_refresh=True)

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _resp["response_args"]["refresh_token"]
        _request["scope"] = ["ema"]

        _req = self.token_endpoint.parse_request(_request.to_json())
        assert isinstance(_req, TokenErrorResponse)
        _resp = self.token_endpoint.process_request(request=_req, issue_refresh=True)

        assert _resp.to_dict() == {
            "error": "invalid_request",
            "error_description": "Invalid refresh scopes"
        }

    def test_refresh_more_scopes_2(self):
        areq = AUTH_REQ.copy()
        areq["scope"] = ["email", "profile"]

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq["client_id"])

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req, issue_refresh=True)

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _resp["response_args"]["refresh_token"]
        _request["scope"] = ["email"]

        _token_value = _resp["response_args"]["refresh_token"]

        _req = self.token_endpoint.parse_request(_request.to_json())
        _resp = self.token_endpoint.process_request(request=_req, issue_refresh=True)

        _token_value = _resp["response_args"]["refresh_token"]
        _request["refresh_token"] = _token_value
        # We should be able to request the original requests scopes
        _request["scope"] = ["email", "profile"]

        _req = self.token_endpoint.parse_request(_request.to_json())
        _resp = self.token_endpoint.process_request(request=_req, issue_refresh=True)

        assert set(_resp.keys()) == {"cookie", "response_args", "http_headers"}
        assert set(_resp["response_args"].keys()) == {
            "access_token",
            "token_type",
            "expires_in",
            "refresh_token",
            "scope",
        }

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        at = self.session_manager.find_token(
            _session_info["session_id"], _token_value
        )
        rt = self.session_manager.find_token(
            _session_info["session_id"], _resp["response_args"]["refresh_token"]
        )

        assert at.scope == rt.scope == _request["scope"] == _resp["response_args"]["scope"]

    def test_do_refresh_access_token_not_allowed(self):
        areq = AUTH_REQ.copy()
        areq["scope"] = ["email"]

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq["client_id"])

        _cntx = self.token_endpoint.server_get("endpoint_context")

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        # This is weird, issuing a refresh token that can't be used to mint anything
        # but it's testing so anything goes.
        grant.usage_rules["refresh_token"] = {"supports_minting": []}
        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req, issue_refresh=True)

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _resp["response_args"]["refresh_token"]
        _req = self.token_endpoint.parse_request(_request.to_json())
        with pytest.raises(MintingNotAllowed):
            self.token_endpoint.process_request(_req)

    def test_do_refresh_access_token_revoked(self):
        areq = AUTH_REQ.copy()
        areq["scope"] = ["email"]

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq["client_id"])

        _cntx = self.token_endpoint.server_get("endpoint_context")

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req, issue_refresh=True)

        _refresh_token = _resp["response_args"]["refresh_token"]
        _cntx.session_manager.revoke_token(session_id, _refresh_token)

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _refresh_token
        _req = self.token_endpoint.parse_request(_request.to_json())
        # A revoked token is caught already when parsing the query.
        assert isinstance(_req, TokenErrorResponse)

    def test_configure_grant_types(self):
        conf = {"access_token": {"class": "oidcop.oidc.token.AccessTokenHelper"}}

        self.token_endpoint.configure_grant_types(conf)

        assert len(self.token_endpoint.helper) == 1
        assert "access_token" in self.token_endpoint.helper
        assert "refresh_token" not in self.token_endpoint.helper

    def test_token_request_other_client(self):
        _context = self.endpoint_context
        _context.cdb["client_2"] = _context.cdb["client_1"]
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, AUTH_REQ["client_id"])

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["client_id"] = "client_2"
        _token_request["code"] = code.value

        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req)

        assert isinstance(_resp, TokenErrorResponse)
        assert _resp.to_dict() == {
            "error": "invalid_client", "error_description": "Invalid client"
        }

    def test_refresh_token_request_other_client(self):
        _context = self.endpoint_context
        _context.cdb["client_2"] = _context.cdb["client_1"]
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, AUTH_REQ["client_id"])

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value

        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(
            request=_req, issue_refresh=True
        )

        _request = REFRESH_TOKEN_REQ.copy()
        _request["client_id"] = "client_2"
        _request["refresh_token"] = _resp["response_args"]["refresh_token"]

        _token_value = _resp["response_args"]["refresh_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)
        _token.usage_rules["supports_minting"] = ["access_token", "refresh_token"]

        _req = self.token_endpoint.parse_request(_request.to_json())
        _resp = self.token_endpoint.process_request(request=_req,)
        assert isinstance(_resp, TokenErrorResponse)
        assert _resp.to_dict() == {
            "error": "invalid_client", "error_description": "Invalid client"
        }
