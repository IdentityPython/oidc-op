import base64
import json
import os

from oidcop.configure import ASConfiguration

from oidcop.configure import OPConfiguration
import pytest
from cryptojwt import JWT
from cryptojwt import as_unicode
from cryptojwt.key_jar import build_keyjar
from cryptojwt.utils import as_bytes
from oidcmsg.oauth2 import TokenIntrospectionRequest
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.time_util import time_sans_frac
from oidcmsg.time_util import utc_time_sans_frac

from oidcop.authn_event import create_authn_event
from oidcop.authz import AuthzHandling
from oidcop.client_authn import verify_client
from oidcop.exception import UnAuthorizedClient
from oidcop.oauth2.authorization import Authorization
from oidcop.oauth2.introspection import Introspection
from oidcop.oidc.token import Token
from oidcop.server import Server
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcop.user_info import UserInfo

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
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
        "refresh_token",
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
    response_type="code id_token",
)

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


@pytest.mark.parametrize("jwt_token", [True, False])
class TestEndpoint:
    @pytest.fixture(autouse=True)
    def create_endpoint(self, jwt_token):
        conf = {
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
                "id_token": {
                    "class": "oidcop.token.id_token.IDToken",
                }
            },
            "endpoint": {
                "authorization": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {},
                },
                "introspection": {
                    "path": "{}/intro",
                    "class": Introspection,
                    "kwargs": {
                        "client_authn_method": ["client_secret_post"],
                        "enable_claims_per_client": False,
                    },
                },
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
            "userinfo": {
                "path": "{}/userinfo",
                "class": UserInfo,
                "kwargs": {"db_file": full_path("users.json")},
            },
            "client_authn": verify_client,
            "template_dir": "template",
            "authz": {
                "class": AuthzHandling,
                "kwargs": {
                    "grant_config": {
                        "usage_rules": {
                            "authorization_code": {
                                "supports_minting": ["access_token", "refresh_token", "id_token",],
                                "max_usage": 1,
                            },
                            "access_token": {},
                            "refresh_token": {
                                "supports_minting": ["access_token", "refresh_token"],
                            },
                        },
                        "expires_in": 43200,
                    }
                },
            },
        }
        if jwt_token:
            conf["token_handler_args"]["token"] = {
                "class": "oidcop.token.jwt_token.JWTToken",
                "kwargs": {},
            }
        server = Server(ASConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
        endpoint_context = server.endpoint_context
        endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
            "add_claims": {
                "always": {
                    "introspection": ["nickname", "eduperson_scoped_affiliation"],
                },
                "by_scope": {},
            },
        }
        endpoint_context.keyjar.import_jwks_as_json(
            endpoint_context.keyjar.export_jwks_as_json(private=True), endpoint_context.issuer,
        )
        self.introspection_endpoint = server.server_get("endpoint", "introspection")
        self.token_endpoint = server.server_get("endpoint", "token")
        self.session_manager = endpoint_context.session_manager
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

    def _mint_token(self, token_class, grant, session_id, based_on=None, **kwargs):
        # Constructing an authorization code is now done
        return grant.mint_token(
            session_id=session_id,
            endpoint_context=self.token_endpoint.server_get("endpoint_context"),
            token_class=token_class,
            token_handler=self.session_manager.token_handler.handler[token_class],
            expires_at=time_sans_frac() + 300,  # 5 minutes from now
            based_on=based_on,
            **kwargs
        )

    def _get_access_token(self, areq):
        session_id = self._create_session(areq)
        # Consent handling
        grant = self.token_endpoint.server_get("endpoint_context").authz(session_id, areq)
        self.session_manager[session_id] = grant
        # grant = self.session_manager[session_id]
        code = self._mint_token("authorization_code", grant, session_id)
        return self._mint_token("access_token", grant, session_id, code)

    def test_parse_no_authn(self):
        access_token = self._get_access_token(AUTH_REQ)
        with pytest.raises(UnAuthorizedClient):
            self.introspection_endpoint.parse_request({"token": access_token.value})

    def test_parse_with_client_auth_in_req(self):
        access_token = self._get_access_token(AUTH_REQ)

        _context = self.introspection_endpoint.server_get("endpoint_context")
        _req = self.introspection_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )

        assert isinstance(_req, TokenIntrospectionRequest)
        assert set(_req.keys()) == {"token", "client_id", "client_secret"}

    def test_parse_with_wrong_client_authn(self):
        access_token = self._get_access_token(AUTH_REQ)

        _basic_token = "{}:{}".format(
            "client_1",
            self.introspection_endpoint.server_get("endpoint_context").cdb["client_1"][
                "client_secret"
            ],
        )
        _basic_token = as_unicode(base64.b64encode(as_bytes(_basic_token)))
        _basic_authz = "Basic {}".format(_basic_token)
        http_info = {"headers": {"authorization": _basic_authz}}

        with pytest.raises(UnAuthorizedClient):
            self.introspection_endpoint.parse_request(
                {"token": access_token.value}, http_info=http_info
            )

    def test_process_request(self):
        access_token = self._get_access_token(AUTH_REQ)

        _req = self.introspection_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": self.introspection_endpoint.server_get("endpoint_context").cdb[
                    "client_1"
                ]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)

        assert _resp
        assert set(_resp.keys()) == {"response_args"}
        assert "username" not in _resp["response_args"]

        _resp = self.introspection_endpoint.process_request(_req, release=["username"])

        assert _resp
        assert set(_resp.keys()) == {"response_args"}
        assert "username" in _resp["response_args"]

    def test_do_response(self):
        access_token = self._get_access_token(AUTH_REQ)

        _req = self.introspection_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": self.introspection_endpoint.server_get("endpoint_context").cdb[
                    "client_1"
                ]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        msg_info = self.introspection_endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg_info, dict)
        assert set(msg_info.keys()) == {"response", "http_headers"}
        assert msg_info["http_headers"] == [
            ("Content-type", "application/json; charset=utf-8"),
            ("Pragma", "no-cache"),
            ("Cache-Control", "no-store"),
        ]
        _payload = json.loads(msg_info["response"])
        assert set(_payload.keys()) == {
            "active",
            "iss",
            "sub",
            "client_id",
            "exp",
            "iat",
            "scope",
            "aud",
            "token_type"
        }
        assert _payload["active"] is True
        assert _payload["token_type"] == "bearer"

    def test_do_response_no_token(self):
        # access_token = self._get_access_token(AUTH_REQ)
        _context = self.introspection_endpoint.server_get("endpoint_context")
        _req = self.introspection_endpoint.parse_request(
            {"client_id": "client_1", "client_secret": _context.cdb["client_1"]["client_secret"],}
        )
        _resp = self.introspection_endpoint.process_request(_req)
        assert "error" in _resp

    def test_access_token(self):
        access_token = self._get_access_token(AUTH_REQ)
        _context = self.introspection_endpoint.server_get("endpoint_context")
        _req = self.introspection_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        _resp_args = _resp["response_args"]
        assert "sub" in _resp_args
        assert _resp_args["active"]
        assert _resp_args["scope"] == "openid"

    def test_code(self):
        session_id = self._create_session(AUTH_REQ)

        # Apply consent
        grant = self.token_endpoint.server_get("endpoint_context").authz(session_id, AUTH_REQ)
        self.session_manager[session_id] = grant

        code = self._mint_token("authorization_code", grant, session_id)

        _context = self.introspection_endpoint.server_get("endpoint_context")

        _req = self.introspection_endpoint.parse_request(
            {
                "token": code.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        _resp_args = _resp["response_args"]
        assert _resp_args["active"] is False

    def test_introspection_claims(self):
        session_id = self._create_session(AUTH_REQ)
        # Apply consent
        grant = self.token_endpoint.server_get("endpoint_context").authz(session_id, AUTH_REQ)
        self.session_manager[session_id] = grant

        code = self._mint_token("authorization_code", grant, session_id)
        access_token = self._mint_token("access_token", grant, session_id, code)

        self.introspection_endpoint.kwargs["enable_claims_per_client"] = True

        _c_interface = self.introspection_endpoint.server_get("endpoint_context").claims_interface
        grant.claims = {
            "introspection": _c_interface.get_claims(
                session_id, scopes=AUTH_REQ["scope"], claims_release_point="introspection"
            )
        }

        _context = self.introspection_endpoint.server_get("endpoint_context")
        _req = self.introspection_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        _resp_args = _resp["response_args"]
        assert "nickname" in _resp_args
        assert _resp_args["nickname"] == "Dina"
        assert "eduperson_scoped_affiliation" in _resp_args
        assert _resp_args["eduperson_scoped_affiliation"] == ["staff@example.org"]
        assert "family_name" not in _resp_args

    def test_jwt_unknown_key(self):
        _keyjar = build_keyjar(KEYDEFS)

        _jwt = JWT(
            _keyjar,
            iss=self.introspection_endpoint.server_get("endpoint_context").issuer,
            lifetime=3600,
        )

        _jwt.with_jti = True

        _payload = {"sub": "subject_id"}
        _token = _jwt.pack(_payload, aud="client_1")
        _context = self.introspection_endpoint.server_get("endpoint_context")

        _req = self.introspection_endpoint.parse_request(
            {
                "token": _token,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )

        _req = self.introspection_endpoint.parse_request(_req)
        _resp = self.introspection_endpoint.process_request(_req)
        assert _resp["response_args"]["active"] is False

    def test_expired_access_token(self):
        access_token = self._get_access_token(AUTH_REQ)
        access_token.expires_at = utc_time_sans_frac() - 1000

        _context = self.introspection_endpoint.server_get("endpoint_context")

        _req = self.introspection_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        assert _resp["response_args"]["active"] is False

    def test_revoked_access_token(self):
        access_token = self._get_access_token(AUTH_REQ)
        access_token.revoked = True

        _context = self.introspection_endpoint.server_get("endpoint_context")

        _req = self.introspection_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        assert _resp["response_args"]["active"] is False

    def test_introspect_id_token(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.token_endpoint.server_get("endpoint_context").authz(session_id, AUTH_REQ)
        self.session_manager[session_id] = grant
        code = self._mint_token("authorization_code", grant, session_id)
        id_token = self._mint_token("id_token", grant, session_id, code)

        _context = self.introspection_endpoint.server_get("endpoint_context")
        _req = self.introspection_endpoint.parse_request(
            {
                "token": id_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)

        assert _resp["response_args"]["active"] is False
