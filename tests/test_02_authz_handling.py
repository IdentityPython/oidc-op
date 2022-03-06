import pytest
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.server.authn_event import create_authn_event
from oidcmsg.server.session.grant import Grant

from oidcop.server import Server

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

conf = {
    "issuer": "https://example.com/",
    "template_dir": "template",
    "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS, "read_only": True},
    "authz": {
        "class": "oidcmsg.server.authz.AuthzHandling",
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": ["access_token", "refresh_token", "id_token", ],
                        "max_usage": 1,
                    },
                    "access_token": {},
                    "refresh_token": {"supports_minting": ["access_token", "refresh_token"]},
                },
                "expires_in": 43200,
            }
        },
    },
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
        }
        server.endpoint_context.keyjar.add_symmetric(
            "client_1", "hemligtochintekort", ["sig", "enc"]
        )
        self.session_manager = server.endpoint_context.session_manager
        self.user_id = USER_ID
        self.server = server
        self.authz = server.endpoint_context.authz

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

    def test_authz_handling(self):
        session_id = self._create_session(AREQ)
        _grant = self.authz(session_id, AREQ)
        assert isinstance(_grant, Grant)
        # defaults
        assert _grant.claims["userinfo"] == {"sub": None}
