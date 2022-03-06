import os

import pytest
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.server.authn_event import create_authn_event

from oidcop.server import Server

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

AREQ = AuthorizationRequest(
    response_type="code",
    client_id="client_1",
    redirect_uri="http://example.com/authz",
    scope=["openid"],
    state="state000",
    nonce="nonce",
)

AREQ_2 = AuthorizationRequest(
    response_type="code",
    client_id="client_1",
    redirect_uri="http://example.com/authz",
    scope=["openid", "address", "email"],
    state="state000",
    nonce="nonce",
    claims={"id_token": {"nickname": None}},
)

AREQ_3 = AuthorizationRequest(
    response_type="code",
    client_id="client_1",
    redirect_uri="http://example.com/authz",
    scope=["openid", "address", "email"],
    state="state000",
    nonce="nonce",
    claims={
        "id_token": {"nickname": None},
        "userinfo": {"name": None, "email": None, "email_verified": None},
    },
)

conf = {
    "issuer": "https://example.com/",
    "template_dir": "template",
    "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS, "read_only": True},
    "endpoint": {
        "authorization_endpoint": {
            "path": "authorization",
            "class": "oidcop.oidc.authorization.Authorization",
            "kwargs": {},
        },
        "token_endpoint": {"path": "token", "class": "oidcop.oidc.token.Token", "kwargs": {}, },
        "userinfo_endpoint": {
            "path": "userinfo",
            "class": "oidcop.oidc.userinfo.UserInfo",
            "kwargs": {},
        },
        "introspection_endpoint": {
            "path": "introspection",
            "class": "oidcop.oauth2.introspection.Introspection",
            "kwargs": {},
        },
    },
    "token_handler_args": {
        "jwks_def": {
            "private_path": "private/token_jwks.json",
            "read_only": False,
            "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
        },
        "code": {"kwargs": {"lifetime": 600}},
        "token": {
            "class": "oidcmsg.server.token.jwt_token.JWTToken",
            "kwargs": {
                "lifetime": 3600,
                "add_claims_by_scope": True,
                "aud": ["https://example.org/appl"],
            },
        },
        "refresh": {
            "class": "oidcmsg.server.token.jwt_token.JWTToken",
            "kwargs": {"lifetime": 3600, "aud": ["https://example.org/appl"], },
        },
        "id_token": {"class": "oidcmsg.server.token.id_token.IDToken", "kwargs": {}},
    },
    "userinfo": {
        "class": "oidcmsg.server.user_info.UserInfo",
        "kwargs": {"db_file": full_path("users.json")},
    },
    "claims_interface": {"class": "oidcmsg.server.session.claims.ClaimsInterface", "kwargs": {}},
}

USER_ID = "diana"


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_idtoken(self):
        server = Server(conf)
        server.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligtochintekort",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
            "add_claims": {
                "always": {},
            },
        }
        server.endpoint_context.keyjar.add_symmetric(
            "client_1", "hemligtochintekort", ["sig", "enc"]
        )
        self.claims_interface = server.endpoint_context.claims_interface
        self.endpoint_context = server.endpoint_context
        self.session_manager = self.endpoint_context.session_manager
        self.user_id = USER_ID
        self.server = server

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

    @pytest.mark.parametrize("usage", ["id_token", "userinfo", "introspection", "access_token"])
    def test_get_claims(self, usage):
        session_id = self._create_session(AREQ)
        claims = self.claims_interface.get_claims(session_id, [], usage)
        assert claims == {}

    def test_get_claims_userinfo_3(self):
        _module = self.server.server_get("endpoint", "userinfo")
        session_id = self._create_session(AREQ)
        _module.kwargs = {
            "base_claims": {"email": None, "email_verified": None},
            "enable_claims_per_client": True,
            "add_claims_by_scope": True,
        }
        self.endpoint_context.cdb["client_1"]["add_claims"]["always"]["userinfo"] = ["name",
                                                                                     "email"]

        claims = self.claims_interface.get_claims(session_id, ["openid", "address"], "userinfo")
        assert set(claims.keys()) == {
            "name",
            "email",
            "email_verified",
            "sub",
            "address",
        }

    def test_get_claims_introspection_3(self):
        _module = self.server.server_get("endpoint", "introspection")
        _module.kwargs = {
            "base_claims": {"email": None, "email_verified": None},
            "enable_claims_per_client": True,
            "add_claims_by_scope": True,
        }
        self.endpoint_context.cdb["client_1"]["add_claims"]["always"]["introspection"] = [
            "name",
            "email",
        ]

        session_id = self._create_session(AREQ)
        claims = self.claims_interface.get_claims(
            session_id, ["openid", "address"], "introspection"
        )
        assert set(claims.keys()) == {
            "name",
            "email",
            "email_verified",
            "sub",
            "address",
        }

    def test_get_claims_all_usage(self):
        # Make sure everything is reset
        self.session_manager.token_handler["id_token"].kwargs = {}
        self.session_manager.token_handler["access_token"].kwargs = {}

        self.server.server_get("endpoint", "userinfo").kwargs = {}
        self.server.server_get("endpoint", "introspection").kwargs = {}

        session_id = self._create_session(AREQ)
        claims = self.claims_interface.get_claims_all_usage(session_id, ["openid", "address"])
        assert set(claims.keys()) == {
            "id_token",
            "userinfo",
            "introspection",
            "access_token",
        }
        for usage in ["id_token", "userinfo", "introspection", "access_token"]:
            assert claims[usage] == {}

    def test_get_claims_all_usage_2(self):
        # make all different
        self.session_manager.token_handler["id_token"].kwargs = {
            "base_claims": {"email": None, "email_verified": None}
        }

        self.server.server_get("endpoint", "userinfo").kwargs = {
            "enable_claims_per_client": True,
        }
        self.endpoint_context.cdb["client_1"]["add_claims"]["always"]["userinfo"] = ["name",
                                                                                     "email"]

        self.server.server_get("endpoint", "introspection").kwargs = {"add_claims_by_scope": True}

        self.endpoint_context.session_manager.token_handler["access_token"].kwargs = {}

        session_id = self._create_session(AREQ)
        claims = self.claims_interface.get_claims_all_usage(session_id, ["openid", "address"])

        assert set(claims.keys()) == {
            "id_token",
            "userinfo",
            "introspection",
            "access_token",
        }

        assert set(claims["id_token"].keys()) == {"email", "email_verified"}
        assert set(claims["userinfo"].keys()) == {"email", "name"}
        assert set(claims["introspection"].keys()) == {"address", "sub"}
        assert set(claims["access_token"].keys()) == set()

    def test_get_user_claims(self):
        self.session_manager.token_handler["id_token"].kwargs = {
            "base_claims": {"email": None, "email_verified": None}
        }

        self.server.server_get("endpoint", "userinfo").kwargs = {
            "enable_claims_per_client": True,
        }
        self.endpoint_context.cdb["client_1"]["add_claims"]["always"]["userinfo"] = ["name",
                                                                                     "email"]

        self.server.server_get("endpoint", "introspection").kwargs = {"add_claims_by_scope": True}

        self.endpoint_context.session_manager.token_handler["access_token"].kwargs = {}

        session_id = self._create_session(AREQ)
        claims_restriction = self.claims_interface.get_claims_all_usage(session_id,
                                                                        ["openid", "address"])

        _claims = self.claims_interface.get_user_claims(USER_ID, claims_restriction["userinfo"])
        assert _claims == {"name": "Diana Krall", "email": "diana@example.org"}

        _claims = self.claims_interface.get_user_claims(USER_ID, claims_restriction["id_token"])
        assert _claims == {"email_verified": False, "email": "diana@example.org"}

        _claims = self.claims_interface.get_user_claims(
            USER_ID, claims_restriction["introspection"]
        )
        # Note that sub is not a user claim
        assert _claims == {
            "address": {
                "country": "Sweden",
                "locality": "Umeå",
                "postal_code": "SE-90187",
                "street_address": "Umeå Universitet",
            }
        }

        _claims = self.claims_interface.get_user_claims(USER_ID, claims_restriction["access_token"])
        assert _claims == {}
