import os

import pytest
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import init_key_jar
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.time_util import time_sans_frac

from oidcop import user_info
from oidcop.authn_event import create_authn_event
from oidcop.authz import AuthzHandling
from oidcop.client_authn import verify_client
from oidcop.oauth2.introspection import Introspection
from oidcop.oidc.authorization import Authorization
from oidcop.oidc.provider_config import ProviderConfiguration
from oidcop.oidc.registration import Registration
from oidcop.oidc.session import Session
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

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))

MAP = {
    "authorization_code": "code",
    "access_token": "access_token",
    "refresh_token": "refresh_token",
    "id_token": "id_token"
}


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": ISSUER,
            "password": "mycket hemligt",
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
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
                    "kwargs": {"lifetime": 3600, "aud": ["https://example.org/appl"],},
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
                    "path": "{}/.well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "registration": {
                    "path": "{}/registration",
                    "class": Registration,
                    "kwargs": {},
                },
                "authorization": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {},
                },
                "token": {"path": "{}/token", "class": Token, "kwargs": {}},
                "session": {"path": "{}/end_session", "class": Session},
                "introspection": {"path": "{}/introspection", "class": Introspection},
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
                "kwargs": {"db_file": full_path("users.json")},
            },
            "authz": {
                "class": AuthzHandling,
                "kwargs": {
                    "grant_config": {
                        "usage_rules": {
                            "authorization_code": {
                                "supports_minting": [
                                    "access_token",
                                    "refresh_token",
                                    "id_token",
                                ],
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
        server = Server(conf, keyjar=KEYJAR)
        self.endpoint_context = server.endpoint_context
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        self.session_manager = self.endpoint_context.session_manager
        self.user_id = "diana"
        self.endpoint = server.server_get("endpoint", "session")

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

    def _mint_token(self, type, grant, session_id, based_on=None, **kwargs):
        # Constructing an authorization code is now done
        return grant.mint_token(
            session_id=session_id,
            endpoint_context=self.endpoint_context,
            token_type=type,
            token_handler=self.session_manager.token_handler.handler[MAP[type]],
            expires_at=time_sans_frac() + 300,  # 5 minutes from now
            based_on=based_on,
            **kwargs
        )

    def test_parse(self):
        session_id = self._create_session(AUTH_REQ)
        # apply consent
        grant = self.endpoint_context.authz(session_id=session_id, request=AUTH_REQ)
        # grant = self.session_manager[session_id]
        code = self._mint_token("authorization_code", grant, session_id)
        access_token = self._mint_token(
            "access_token", grant, session_id, code, resources=[AUTH_REQ["client_id"]]
        )

        _verifier = JWT(self.endpoint_context.keyjar)
        _info = _verifier.unpack(access_token.value)

        assert _info["ttype"] == "T"
        # assert _info["eduperson_scoped_affiliation"] == ["staff@example.org"]
        assert set(_info["aud"]) == {"client_1"}

    def test_info(self):
        session_id = self._create_session(AUTH_REQ)
        # apply consent
        grant = self.endpoint_context.authz(session_id=session_id, request=AUTH_REQ)
        #
        code = self._mint_token("authorization_code", grant, session_id)
        access_token = self._mint_token("access_token", grant, session_id, code)

        _info = self.session_manager.token_handler.info(access_token.value)
        assert _info["type"] == "T"
        assert _info["sid"] == session_id

    @pytest.mark.parametrize("enable_claims_per_client", [True, False])
    def test_enable_claims_per_client(self, enable_claims_per_client):
        # Set up configuration
        self.endpoint_context.cdb["client_1"]["access_token_claims"] = {"address": None}
        self.endpoint_context.session_manager.token_handler.handler[
            "access_token"
        ].kwargs["enable_claims_per_client"] = enable_claims_per_client

        session_id = self._create_session(AUTH_REQ)
        # apply consent
        grant = self.endpoint_context.authz(session_id=session_id, request=AUTH_REQ)
        #
        code = self._mint_token("authorization_code", grant, session_id)
        access_token = self._mint_token("access_token", grant, session_id, code)

        _jwt = JWT(key_jar=KEYJAR, iss="client_1")
        res = _jwt.unpack(access_token.value)
        assert enable_claims_per_client is ("address" in res)

    def test_is_expired(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_token("authorization_code", grant, session_id)
        access_token = self._mint_token("access_token", grant, session_id, code)

        assert access_token.is_active()
        # 4000 seconds in the future. Passed the lifetime.
        assert access_token.is_active(now=time_sans_frac() + 4000) is False
