import json
import os

from cryptojwt.key_jar import build_keyjar
from oidcmsg.oauth2 import TokenExchangeRequest
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
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
            "password": "mycket hemligt",
            "verify_ssl": False,
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
                    "class": 'oidcop.oauth2.token.Token',
                    "kwargs": {
                        "client_authn_method": [
                            "client_secret_basic",
                            "client_secret_post",
                            "client_secret_jwt",
                            "private_key_jwt",
                        ]
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
                                "supports_minting": ["access_token", "refresh_token", "id_token", ],
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
        endpoint_context = server.endpoint_context
        endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        endpoint_context.keyjar.import_jwks(CLIENT_KEYJAR.export_jwks(), "client_1")
        self.endpoint = server.server_get("endpoint", "token")
        self.introspection_endpoint = server.server_get("endpoint", "introspection")
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

    def _mint_code(self, grant, session_id):
        return grant.mint_token(
            session_id=session_id,
            endpoint_context=self.endpoint.server_get("endpoint_context"),
            token_type="authorization_code",
            token_handler=self.session_manager.token_handler["code"],
        )

    def _mint_access_token(self, grant, session_id, token_ref=None, resources=None, scope=None):
        return grant.mint_token(
            session_id=session_id,
            endpoint_context=self.endpoint.server_get("endpoint_context"),
            token_type="access_token",
            token_handler=self.session_manager.token_handler["access_token"],
            based_on=token_ref,
            resources=resources,
            scope=scope
        )

    def exchange_grant(self, session_id, users, targets, scope):
        session_info = self.session_manager.get_session_info(session_id)
        exchange_grant = ExchangeGrant(scope=scope, resources=targets, users=users)

        # the grant is assigned to a session (user_id, client_id)
        self.session_manager.set(
            [self.user_id, session_info["client_id"], exchange_grant.id], exchange_grant
        )
        return exchange_grant

    def test_do_response(self):
        session_id = self._create_session(AUTH_REQ)

        grant = self.session_manager.get_grant(session_id)
        grant.usage_rules["access_token"] = {"supports_minting": ["access_token"]}

        grant_user_id = "https://frontend.example.com/resource"
        backend = "https://backend.example.com"
        _ = self.exchange_grant(session_id, [grant_user_id], [backend], scope=["api"])
        code = self._mint_code(grant, session_id)

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)

        _resp = self.endpoint.process_request(request=_req)
        msg = self.endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg, dict)
        token_response = json.loads(msg["response"])

        print(token_response["access_token"])
        # resource server sends a token exchange request with
        # access token as subject_token

        ter = TokenExchangeRequest(
            subject_token=token_response["access_token"],
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            resource="https://backend.example.com/api",
        )

        exch_grants = []
        for grant in self.session_manager.grants(session_id=session_id):
            if isinstance(grant, ExchangeGrant):
                if grant_user_id in grant.users:
                    exch_grants.append(grant)

        assert exch_grants
        exch_grant = exch_grants[0]

        session_info = self.session_manager.get_session_info_by_token(ter["subject_token"],
                                                                      grant=True)
        _token = self.session_manager.find_token(session_info["session_id"], ter["subject_token"])

        session_id = self.session_manager.encrypted_session_id(
            session_info["user_id"], session_info["client_id"], exch_grant.id
        )

        _scope = session_info["grant"].find_scope(ter["subject_token"])

        _token = self._mint_access_token(
            exch_grant, session_id, token_ref=_token, resources=["https://backend.example.com"],
            scope=_scope
        )

        print(_token.value)
        _req = self.introspection_endpoint.parse_request(
            {
                "token": _token.value,
                "client_id": "client_1",
                "client_secret": self.introspection_endpoint.server_get("endpoint_context").cdb[
                    "client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        msg_info = self.introspection_endpoint.do_response(request=_req, **_resp)
        assert msg_info
        print(json.loads(msg_info["response"]))
