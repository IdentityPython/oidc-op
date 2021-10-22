import json
import os

from cryptojwt.key_jar import build_keyjar
from oidcmsg.oauth2 import TokenExchangeRequest
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import RefreshAccessTokenRequest
import pytest


from oidcop.authn_event import create_authn_event
from oidcop.authz import AuthzHandling
from oidcop.client_authn import verify_client
from oidcop.configure import ASConfiguration
from oidcop.cookie_handler import CookieHandler
from oidcop.oauth2.authorization import Authorization
from oidcop.oauth2.token import Token
from oidcop.server import Server
from oidcop.session.grant import ExchangeGrant
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcop.user_info import UserInfo

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLIENT_KEYJAR = build_keyjar(KEYDEFS)

COOKIE_KEYDEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]},
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

CAPABILITIES = {
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "urn:ietf:params:oauth:grant-type:token-exchange",
        "refresh_token",
    ],
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

REFRESH_TOKEN_REQ = RefreshAccessTokenRequest(
    grant_type="refresh_token", client_id="https://example2.com/", client_secret="hemligt"
)

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO = UserInfo(json.loads(open(full_path("users.json")).read()))


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": "https://example.com/",
            "httpc_params": {"verify": False, "timeout": 1},
            "capabilities": CAPABILITIES,
            "cookie_handler": {
                "class": CookieHandler,
                "kwargs": {"keys": {"key_defs": COOKIE_KEYDEFS}},
            },
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "endpoint": {
                "authorization": {
                    "path": "authorization",
                    "class": 'oidcop.oauth2.authorization.Authorization',
                    "kwargs": {},
                },
                "token": {
                    "path": "token",
                    "class": 'oidcop.oidc.token.Token',
                    "kwargs": {
                        "client_authn_method": [
                            "client_secret_basic",
                            "client_secret_post",
                            "client_secret_jwt",
                            "private_key_jwt",
                        ],
                    },
                },
                "introspection": {
                    "path": "introspection",
                    "class": "oidcop.oauth2.introspection.Introspection",
                    "kwargs": {},
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
            "authz": {
                "class": AuthzHandling,
                "kwargs": {
                    "grant_config": {
                        "usage_rules": {
                            "authorization_code": {
                                "supports_minting": ["access_token", "refresh_token" ],
                                "max_usage": 1,
                            },
                            "access_token": {
                                "supports_minting": ["access_token", "refresh_token"],
                                "expires_in": 600,
                            },
                            "refresh_token": {
                                "supports_minting": ["access_token", "refresh_token"],
                                "audience": ["https://example.com/", "https://example2.com/"],
                                "expires_in": 43200
                            },
                        },
                        "expires_in": 43200,
                    }
                },
            },
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
                    "kwargs": {"lifetime": 3600, "aud": ["https://example.org/appl"], },
                },
            },
        }
        server = Server(ASConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
        self.endpoint_context = server.endpoint_context
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
            "allowed_scopes": ["openid", "profile", "offline_access"],
        }
        self.endpoint_context.cdb["https://example2.com/"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
            "allowed_scopes": ["openid", "profile", "offline_access"],
        }
        self.endpoint_context.keyjar.import_jwks(CLIENT_KEYJAR.export_jwks(), "client_1")
        self.endpoint = server.server_get("endpoint", "token")
        self.introspection_endpoint = server.server_get("endpoint", "introspection")
        self.session_manager = self.endpoint_context.session_manager
        self.user_id = "diana"

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
            endpoint_context=self.endpoint.server_get("endpoint_context"),
            token_class="authorization_code",
            token_handler=self.session_manager.token_handler["authorization_code"],
            usage_rules=usage_rules
        )

        if _exp_in:
            if isinstance(_exp_in, str):
                _exp_in = int(_exp_in)
            if _exp_in:
                _code.expires_at = utc_time_sans_frac() + _exp_in
        return _code

    def test_token_exchange(self):
        """
        Test that token exchange requests work correctly, removing a scope.
        """
        areq = AUTH_REQ.copy()
        areq["scope"] = ["openid", "profile"]
        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            resource=["https://example.com/api"],
            scope=["openid"],
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            {
                "headers": {
                    "authorization": "Basic {}".format("Y2xpZW50XzE6aGVtbGlndA==")
                }
            },
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp["response_args"].keys()) == {
            'access_token', 'token_type', 'scope', 'expires_in', 'issued_token_type'
        }
        assert _resp["response_args"]["scope"] == ["openid"]

    def test_additional_parameters(self):
        """
        Test that a token exchange with additional parameters including
        audience and subject_token_type works.
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            resource=["https://example.com/api"],
            requested_token_type="urn:ietf:params:oauth:token-type:access_token",
            audience=["https://example.com/"],
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            {
                "headers": {
                    "authorization": "Basic {}".format("Y2xpZW50XzE6aGVtbGlndA==")
                }
            },
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp["response_args"].keys()) == {
            'access_token', 'token_type', 'expires_in', 'issued_token_type', 'scope'
        }
        msg = self.endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg, dict)

    def test_token_exchange_fails_if_disabled(self):
        """
        Test that token exchange fails if it's not included in Token's
        grant_types_supported (that are set in its helper attribute).
        """
        del self.endpoint.helper[
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ]

        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            resource=["https://example.com/api"]
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            {
                "headers": {
                    "authorization": "Basic {}".format("Y2xpZW50XzE6aGVtbGlndA==")
                }
            },
        )
        _resp = self.endpoint.process_request(request=_req)
        assert _resp["error"] == "invalid_request"
        assert(
            _resp["error_description"]
            == "Unsupported grant_type: urn:ietf:params:oauth:grant-type:token-exchange"
        )

    def test_wrong_resource(self):
        """
        Test that requesting a token for an unknown resource fails.

        We currently only allow resources that match the issuer's host part.
        TODO: Should we do this?
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            resource=["https://unknown-resource.com/api"]
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            {
                "headers": {
                    "authorization": "Basic {}".format("Y2xpZW50XzE6aGVtbGlndA==")
                }
            },
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_target"
        assert _resp["error_description"] == "Unknown resource"

    def test_wrong_audience(self):
        """
        Test that requesting a token for an unknown audience fails.

        We currently only allow audience that matches the owner of the subject_token or 
        the allowed audience as configured in authz/grant_config
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            audience=["https://unknown-audience.com/"],
            resource=["https://example.com/api"]
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            {
                "headers": {
                    "authorization": "Basic {}".format("Y2xpZW50XzE6aGVtbGlndA==")
                }
            },
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_target"
        assert _resp["error_description"] == "Unknown audience"

    @pytest.mark.parametrize("aud", [
        "https://example.com/",
    ])
    def test_exchanged_refresh_token_wrong_audience(self, aud):
        """
        Test that requesting a token for an unknown audience fails.

        We currently only allow audience that matches the owner of the subject_token or 
        the allowed audience as configured in authz/grant_config
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            requested_token_type="urn:ietf:params:oauth:token-type:refresh_token",
            audience=aud
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            {
                "headers": {
                    "authorization": "Basic {}".format("Y2xpZW50XzE6aGVtbGlndA==")
                }
            },
        )
        _resp = self.endpoint.process_request(request=_req)

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _resp["response_args"]["refresh_token"]
        _req = self.endpoint.parse_request(_request.to_json())
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_grant"
        assert _resp["error_description"] == "Wrong client"

    @pytest.mark.parametrize("missing_attribute", [
        "subject_token_type",
        "subject_token",
    ])
    def test_missing_parameters(self, missing_attribute):
        """
        Test that omitting the subject_token_type fails.
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            audience=["https://example.com/"],
            resource=["https://example.com/api"]
        )

        del token_exchange_req[missing_attribute]

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            {
                "headers": {
                    "authorization": "Basic {}".format("Y2xpZW50XzE6aGVtbGlndA==")
                }
            },
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_request"
        assert (
            _resp["error_description"]
            == f"Missing required attribute '{missing_attribute}'"
        )

    @pytest.mark.parametrize("unsupported_type", [
        "unknown",
        "urn:ietf:params:oauth:token-type:id_token",
        "urn:ietf:params:oauth:token-type:saml2",
        "urn:ietf:params:oauth:token-type:saml1",
    ])
    def test_unsupported_requested_token_type(self, unsupported_type):
        """
        Test that requesting a token type that is unknown or unsupported fails.
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            requested_token_type=unsupported_type,
            audience=["https://example.com/"],
            resource=["https://example.com/api"]
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            {
                "headers": {
                    "authorization": "Basic {}".format("Y2xpZW50XzE6aGVtbGlndA==")
                }
            },
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_target"
        assert (
            _resp["error_description"]
            == "Unsupported requested token type"
        )

    @pytest.mark.parametrize("unsupported_type", [
        "unknown",
        "urn:ietf:params:oauth:token-type:id_token",
        "urn:ietf:params:oauth:token-type:saml2",
        "urn:ietf:params:oauth:token-type:saml1",
    ])
    def test_unsupported_subject_token_type(self, unsupported_type):
        """
        Test that providing an unsupported subject token type fails.
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type=unsupported_type,
            audience=["https://example.com/"],
            resource=["https://example.com/api"]
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            {
                "headers": {
                    "authorization": "Basic {}".format("Y2xpZW50XzE6aGVtbGlndA==")
                }
            },
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_request"
        assert (
            _resp["error_description"]
            == "Unsupported subject token type"
        )

    def test_unsupported_actor_token(self):
        """
        Test that providing an actor token fails as it's unsupported.
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            actor_token=_resp['response_args']['access_token']
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            {
                "headers": {
                    "authorization": "Basic {}".format("Y2xpZW50XzE6aGVtbGlndA==")
                }
            },
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_request"
        assert (
            _resp["error_description"]
            == "Actor token not supported"
        )

    def test_invalid_token(self):
        """
        Test that providing an invalid token fails.
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token="invalid_token",
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            {
                "headers": {
                    "authorization": "Basic {}".format("Y2xpZW50XzE6aGVtbGlndA==")
                }
            },
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_request"
        assert (
            _resp["error_description"]
            == "Subject token invalid"
        )

