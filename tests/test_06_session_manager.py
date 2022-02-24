from cryptojwt.jws.jws import factory
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.time_util import utc_time_sans_frac
import pytest

from oidcop.authn_event import AuthnEvent
from oidcop.authn_event import create_authn_event
from oidcop.authz import AuthzHandling
from oidcop.oidc.authorization import Authorization
from oidcop.oidc.token import Token
from oidcop.server import Server
from oidcop.session import MintingNotAllowed
from oidcop.session.info import ClientSessionInfo
from oidcop.session.token import AccessToken
from oidcop.session.token import AuthorizationCode
from oidcop.session.token import RefreshToken
from . import full_path

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

USER_ID = "diana"

CLI1 = "https://client1.example.com/"


class TestSessionManager:
    @pytest.fixture(autouse=True)
    def create_session_manager(self):
        conf = {
            "issuer": "https://example.com/",
            "httpc_params": {"verify": False, "timeout": 1},
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "keys": {"key_defs": KEYDEFS, "uri_path": "static/jwks.json"},
            "jwks_uri": "https://example.com/jwks.json",
            "token_handler_args": {
                "jwks_def": {
                    "private_path": "private/token_jwks.json",
                    "read_only": False,
                    "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
                },
                "code": {"lifetime": 600},
                "token": {
                    "class": "oidcop.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "add_claims": True,
                        "add_claims_by_scope": True,
                        "aud": ["https://example.org/appl"],
                    },
                },
                "refresh": {
                    "class": "oidcop.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "aud": ["https://example.org/appl"],
                    },
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
                "authorization_endpoint": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {},
                },
                "token_endpoint": {"path": "{}/token", "class": Token, "kwargs": {}},
            },
            "session_params": {
                "password": "ses_key",
                "salt": "ses_salt"
            },
            "template_dir": "template",
            "claims_interface": {"class": "oidcop.session.claims.ClaimsInterface", "kwargs": {}},
            "userinfo": {
                "class": "oidcop.user_info.UserInfo",
                "kwargs": {"db_file": full_path("users.json")},
            },
        }
        server = Server(conf)
        self.server = server
        self.endpoint_context = server.endpoint_context
        self.endpoint_context.cdb = {
            "client_1": {
                "client_secret": "hemligt",
                "redirect_uris": [("{}cb".format(CLI1), None)],
                "client_salt": "salted",
                "token_endpoint_auth_method": "client_secret_post",
                "response_types": ["code", "token", "code id_token", "id_token"],
                "post_logout_redirect_uri": (f"{CLI1}logout_cb", ""),
                "token_usage_rules": {
                    "authorization_code": {
                        "supports_minting": ["access_token", "refresh_token", "id_token"]
                    },
                    "refresh_token": {
                        "supports_minting": ["id_token"]
                    }
                }
            }
        }

        self.session_manager = server.endpoint_context.session_manager
        self.authn_event = AuthnEvent(
            uid="uid", valid_until=utc_time_sans_frac() + 1, authn_info="authn_class_ref"
        )
        self.dummy_session_id = self.session_manager.encrypted_session_id(
            "user_id", "client_id", "grant.id"
        )

    def _create_session(self, auth_req, sub_type="public", sector_identifier=""):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req

        client_id = authz_req["client_id"]
        ae = create_authn_event(USER_ID)
        return self.server.endpoint_context.session_manager.create_session(
            ae, authz_req, USER_ID, client_id=client_id, sub_type=sub_type
        )

    def test_session_manager_salt_key(self):
        sman = self.session_manager
        assert sman.key == "ses_key"
        assert sman.salt == "ses_salt"

    @pytest.mark.parametrize(
        "sub_type, sector_identifier",
        [("pairwise", "https://all.example.com"), ("public", ""), ("ephemeral", "")],
    )
    def test_create_session_sub_type(self, sub_type, sector_identifier):
        # First session
        authz_req = AUTH_REQ.copy()
        if sub_type == "pairwise":
            authz_req["sector_identifier_uri"] = sector_identifier

        session_key_1 = self.session_manager.create_session(
            authn_event=self.authn_event,
            auth_req=authz_req,
            user_id="diana",
            client_id="client_1",
            sub_type=sub_type,
        )

        _user_info_1 = self.session_manager.get_user_session_info(session_key_1)
        assert _user_info_1.subordinate == ["client_1"]
        _client_info_1 = self.session_manager.get_client_session_info(session_key_1)
        assert len(_client_info_1.subordinate) == 1
        # grant = self.session_manager.get_grant(session_key_1)

        # Second session
        authn_req = AUTH_REQ.copy()
        authn_req["client_id"] = "client_2"
        if sub_type == "pairwise":
            authn_req["sector_identifier_uri"] = sector_identifier

        session_key_2 = self.session_manager.create_session(
            authn_event=self.authn_event,
            auth_req=authn_req,
            user_id="diana",
            client_id="client_2",
            sub_type=sub_type,
        )

        _user_info_2 = self.session_manager.get_user_session_info(session_key_2)
        assert _user_info_2.subordinate == ["client_1", "client_2"]

        grant_1 = self.session_manager.get_grant(session_key_1)
        grant_2 = self.session_manager.get_grant(session_key_2)

        if sub_type in ["pairwise", "public"]:
            assert grant_1.sub == grant_2.sub
        else:
            assert grant_1.sub != grant_2.sub

        # Third session
        authn_req = AUTH_REQ.copy()
        authn_req["client_id"] = "client_3"
        if sub_type == "pairwise":
            authn_req["sector_identifier_uri"] = sector_identifier

        session_key_3 = self.session_manager.create_session(
            authn_event=self.authn_event,
            auth_req=authn_req,
            user_id="diana",
            client_id="client_3",
            sub_type=sub_type,
        )

        grant_3 = self.session_manager.get_grant(session_key_3)

        if sub_type == "pairwise":
            assert grant_1.sub == grant_2.sub
            assert grant_1.sub == grant_3.sub
            assert grant_3.sub == grant_2.sub
        elif sub_type == "public":
            assert grant_1.sub == grant_2.sub
            assert grant_1.sub == grant_3.sub
            assert grant_3.sub == grant_2.sub
        else:
            assert grant_1.sub != grant_2.sub
            assert grant_1.sub != grant_3.sub
            assert grant_3.sub != grant_2.sub

        # Sub types differ so do authentication request

        assert grant_1.authorization_request != grant_2.authorization_request
        assert grant_1.authorization_request != grant_3.authorization_request
        assert grant_3.authorization_request != grant_2.authorization_request

    def _mint_token(self, token_class, grant, session_id, based_on=None):
        # Constructing an authorization code is now done
        return grant.mint_token(
            session_id=session_id,
            endpoint_context=self.endpoint_context,
            token_class=token_class,
            token_handler=self.session_manager.token_handler.handler[token_class],
            expires_at=utc_time_sans_frac() + 300,  # 5 minutes from now
            based_on=based_on,
        )

    def test_code_usage(self):
        session_id = self._create_session(AUTH_REQ)
        session_info = self.endpoint_context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]

        assert grant.issued_token == []
        assert grant.is_active() is True

        code = self._mint_token("authorization_code", grant, session_id)
        assert isinstance(code, AuthorizationCode)
        assert code.is_active()
        assert len(grant.issued_token) == 1

        assert code.usage_rules["supports_minting"] == [
            "access_token",
            "refresh_token",
            "id_token",
        ]
        access_token = self._mint_token("access_token", grant, session_id, code)
        assert isinstance(access_token, AccessToken)
        assert access_token.is_active()
        assert len(grant.issued_token) == 2

        refresh_token = self._mint_token("refresh_token", grant, session_id, code)
        assert isinstance(refresh_token, RefreshToken)
        assert refresh_token.is_active()
        assert len(grant.issued_token) == 3

        code.register_usage()
        assert code.max_usage_reached() is True

        with pytest.raises(MintingNotAllowed):
            self._mint_token("access_token", grant, self.dummy_session_id, code)

        grant.revoke_token(based_on=code.value)

        assert access_token.revoked is True
        assert refresh_token.revoked is True

    def test_check_grant(self):
        session_id = self.session_manager.create_session(
            authn_event=self.authn_event,
            auth_req=AUTH_REQ,
            user_id="diana",
            client_id="client_1",
            scopes=["openid", "phoe"],
        )

        _session_info = self.session_manager.get_session_info(session_id=session_id, grant=True)
        grant = _session_info["grant"]
        assert grant.scope == ["openid", "phoe"]

        _grant = self.session_manager.get(["diana", "client_1", grant.id])

        assert _grant.scope == ["openid", "phoe"]

    def test_find_token(self):
        session_id = self.session_manager.create_session(
            authn_event=self.authn_event, auth_req=AUTH_REQ, user_id="diana", client_id="client_1",
        )

        _info = self.session_manager.get_session_info(session_id=session_id, grant=True)
        grant = _info["grant"]

        code = self._mint_token("authorization_code", grant, session_id)
        access_token = self._mint_token("access_token", grant, session_id, code)

        _session_id = self.session_manager.encrypted_session_id("diana", "client_1", grant.id)
        _token = self.session_manager.find_token(_session_id, access_token.value)

        assert _token.token_class == "access_token"
        assert _token.id == access_token.id

    def test_get_authentication_event(self):
        session_id = self.session_manager.create_session(
            authn_event=self.authn_event,
            auth_req=AUTH_REQ,
            user_id="diana",
            # test taking the client_id from the authn request
            # client_id="client_1",
        )

        _info = self.session_manager.get_session_info(session_id, authentication_event=True)
        authn_event = _info["authentication_event"]

        assert isinstance(authn_event, AuthnEvent)
        assert authn_event["uid"] == "uid"
        assert authn_event["authn_info"] == "authn_class_ref"

        # cover the remaining one ...
        _info = self.session_manager.get_session_info(session_id, authorization_request=True)

    def test_get_client_session_info(self):
        _session_id = self.session_manager.create_session(
            authn_event=self.authn_event, auth_req=AUTH_REQ, user_id="diana", client_id="client_1",
        )

        csi = self.session_manager.get_client_session_info(_session_id)

        assert isinstance(csi, ClientSessionInfo)

    def test_get_general_session_info(self):
        _session_id = self.session_manager.create_session(
            authn_event=self.authn_event, auth_req=AUTH_REQ, user_id="diana", client_id="client_1",
        )

        _session_info = self.session_manager.get_session_info(_session_id)

        assert set(_session_info.keys()) == {
            "client_id",
            "grant_id",
            "session_id",
            "user_id",
        }
        assert _session_info["user_id"] == "diana"
        assert _session_info["client_id"] == "client_1"

    def test_get_session_info_by_token(self):
        _session_id = self.session_manager.create_session(
            authn_event=self.authn_event, auth_req=AUTH_REQ, user_id="diana", client_id="client_1",
        )

        grant = self.session_manager.get_grant(_session_id)
        code = self._mint_token("authorization_code", grant, _session_id)
        _session_info = self.session_manager.get_session_info_by_token(code.value)

        assert set(_session_info.keys()) == {
            "client_id",
            "session_id",
            "grant_id",
            "user_id",
        }
        assert _session_info["user_id"] == "diana"
        assert _session_info["client_id"] == "client_1"

    def test_token_usage_default(self):
        _session_id = self.session_manager.create_session(
            authn_event=self.authn_event, auth_req=AUTH_REQ, user_id="diana", client_id="client_1",
        )
        grant = self.session_manager[_session_id]

        code = self._mint_token("authorization_code", grant, _session_id)

        assert code.usage_rules == {
            "max_usage": 1,
            "supports_minting": ["access_token", "refresh_token", "id_token"],
        }

        token = self._mint_token("access_token", grant, _session_id, code)

        assert token.usage_rules == {}

        refresh_token = self._mint_token("refresh_token", grant, _session_id, code)

        assert refresh_token.usage_rules == {"supports_minting": ["access_token", "refresh_token"]}

    def test_token_usage_grant(self):
        _session_id = self.session_manager.create_session(
            authn_event=self.authn_event, auth_req=AUTH_REQ, user_id="diana", client_id="client_1",
        )
        grant = self.session_manager[_session_id]
        grant.usage_rules = {
            "authorization_code": {
                "max_usage": 1,
                "supports_minting": ["access_token", "refresh_token", "id_token"],
                "expires_in": 300,
            },
            "access_token": {"expires_in": 3600},
            "refresh_token": {"supports_minting": ["access_token", "refresh_token", "id_token"]},
        }

        code = self._mint_token("authorization_code", grant, _session_id)
        assert code.usage_rules == {
            "max_usage": 1,
            "supports_minting": ["access_token", "refresh_token", "id_token"],
            "expires_in": 300,
        }

        token = self._mint_token("access_token", grant, _session_id, code)
        assert token.usage_rules == {"expires_in": 3600}

        refresh_token = self._mint_token("refresh_token", grant, _session_id, code)
        assert refresh_token.usage_rules == {
            "supports_minting": ["access_token", "refresh_token", "id_token"]
        }

    def test_token_usage_authz(self):
        grant_config = {
            "usage_rules": {
                "authorization_code": {
                    "supports_minting": ["access_token"],
                    "max_usage": 1,
                    "expires_in": 120,
                },
                "access_token": {"expires_in": 600},
            },
            "expires_in": 43200,
        }

        self.endpoint_context.authz = AuthzHandling(
            self.server.get_endpoint_context, grant_config=grant_config
        )

        self.endpoint_context.cdb["client_1"] = {}

        token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")

        _session_id = self.session_manager.create_session(
            authn_event=self.authn_event,
            auth_req=AUTH_REQ,
            user_id="diana",
            client_id="client_1",
            token_usage_rules=token_usage_rules,
        )
        grant = self.session_manager[_session_id]

        code = self._mint_token("authorization_code", grant, _session_id)
        assert code.usage_rules == {
            "max_usage": 1,
            "supports_minting": ["access_token"],
            "expires_in": 120,
        }

        token = self._mint_token("access_token", grant, _session_id, code)
        assert token.usage_rules == {"expires_in": 600}

        # Only allowed to mint access_tokens using the authorization_code
        with pytest.raises(MintingNotAllowed):
            self._mint_token("refresh_token", grant, _session_id, code)

    def test_token_usage_client_config(self):
        grant_config = {
            "usage_rules": {
                "authorization_code": {
                    "supports_minting": ["access_token"],
                    "max_usage": 1,
                    "expires_in": 120,
                },
                "access_token": {"expires_in": 600},
                "refresh_token": {},
            },
            "expires_in": 43200,
        }

        self.endpoint_context.authz = AuthzHandling(
            self.server.get_endpoint_context, grant_config=grant_config
        )

        # Change expiration time for the code and allow refresh tokens for this
        # specific client
        self.endpoint_context.cdb["client_1"] = {
            "token_usage_rules": {
                "authorization_code": {
                    "expires_in": 600,
                    "supports_minting": ["access_token", "refresh_token"],
                },
                "refresh_token": {"supports_minting": ["access_token"]},
            }
        }

        token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")

        _session_id = self.session_manager.create_session(
            authn_event=self.authn_event,
            auth_req=AUTH_REQ,
            user_id="diana",
            client_id="client_1",
            token_usage_rules=token_usage_rules,
        )
        grant = self.session_manager[_session_id]

        code = self._mint_token("authorization_code", grant, _session_id)
        assert code.usage_rules == {
            "max_usage": 1,
            "supports_minting": ["access_token", "refresh_token"],
            "expires_in": 600,
        }

        token = self._mint_token("access_token", grant, _session_id, code)
        assert token.usage_rules == {"expires_in": 600}

        refresh_token = self._mint_token("refresh_token", grant, _session_id, code)
        assert refresh_token.usage_rules == {"supports_minting": ["access_token"]}

        # Test with another client

        self.endpoint_context.cdb["client_2"] = {}

        token_usage_rules = self.endpoint_context.authz.usage_rules("client_2")

        _session_id = self.session_manager.create_session(
            authn_event=self.authn_event,
            auth_req=AUTH_REQ,
            user_id="diana",
            client_id="client_2",
            token_usage_rules=token_usage_rules,
        )
        grant = self.session_manager[_session_id]
        code = self._mint_token("authorization_code", grant, _session_id)
        # Not allowed to mint refresh token for this client
        with pytest.raises(MintingNotAllowed):
            self._mint_token("refresh_token", grant, _session_id, code)

        # test revoke token
        self.session_manager.revoke_token(_session_id, code.value, recursive=1)

    def test_authentication_events(self):
        token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
        _session_id = self.session_manager.create_session(
            authn_event=self.authn_event,
            auth_req=AUTH_REQ,
            user_id="diana",
            client_id="client_1",
            token_usage_rules=token_usage_rules,
        )
        res = self.session_manager.get_authentication_events(_session_id)

        assert isinstance(res[0], AuthnEvent)

        res = self.session_manager.get_authentication_events(user_id="diana", client_id="client_1")

        assert isinstance(res[0], AuthnEvent)

        try:
            self.session_manager.get_authentication_events(user_id="diana", )
        except AttributeError:
            pass
        else:
            raise Exception("get_authentication_events MUST return a list of AuthnEvent")

    def test_user_info(self):
        token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
        _session_id = self.session_manager.create_session(
            authn_event=self.authn_event,
            auth_req=AUTH_REQ,
            user_id="diana",
            client_id="client_1",
            token_usage_rules=token_usage_rules,
        )
        self.session_manager.get_user_info("diana")

    def test_revoke_client_session(self):
        token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
        _session_id = self.session_manager.create_session(
            authn_event=self.authn_event,
            auth_req=AUTH_REQ,
            user_id="diana",
            client_id="client_1",
            token_usage_rules=token_usage_rules,
        )
        self.session_manager.revoke_client_session(_session_id)

    def test_revoke_grant(self):
        token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
        _session_id = self.session_manager.create_session(
            authn_event=self.authn_event,
            auth_req=AUTH_REQ,
            user_id="diana",
            client_id="client_1",
            token_usage_rules=token_usage_rules,
        )
        grant = self.session_manager[_session_id]
        self.session_manager.revoke_grant(_session_id)

    def test_revoke_dependent(self):
        token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
        _session_id = self.session_manager.create_session(
            authn_event=self.authn_event,
            auth_req=AUTH_REQ,
            user_id="diana",
            client_id="client_1",
            token_usage_rules=token_usage_rules,
        )
        grant = self.session_manager[_session_id]

        code = self._mint_token("authorization_code", grant, _session_id)
        token = self._mint_token("access_token", grant, _session_id, code)

        grant.remove_inactive_token = True
        grant.revoke_token(value=token.value)
        assert len(grant.issued_token) == 1
        assert grant.issued_token[0].token_class == "authorization_code"

    def test_grants(self):
        token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
        _session_id = self.session_manager.create_session(
            authn_event=self.authn_event,
            auth_req=AUTH_REQ,
            user_id="diana",
            client_id="client_1",
            token_usage_rules=token_usage_rules,
        )
        res = self.session_manager.grants(_session_id)

        assert isinstance(res, list)

        res = self.session_manager.grants(user_id="diana", client_id="client_1")

        assert isinstance(res, list)

        try:
            self.session_manager.grants(user_id="diana", )
        except AttributeError:
            pass
        else:
            raise Exception("get_authentication_events MUST return a list of AuthnEvent")

        # and now cove add_grant
        grant = self.session_manager[_session_id]
        grant_kwargs = grant.parameter
        for i in ("not_before", "used"):
            grant_kwargs.pop(i)
        self.session_manager.add_grant("diana", "client_1", **grant_kwargs)

    def test_find_latest_idtoken(self):
        token_usage_rules = self.endpoint_context.authz.usage_rules("client_1")
        _session_id = self.session_manager.create_session(
            authn_event=self.authn_event,
            auth_req=AUTH_REQ,
            user_id="diana",
            client_id="client_1",
            token_usage_rules=token_usage_rules,
        )
        grant = self.session_manager[_session_id]

        code = self._mint_token("authorization_code", grant, _session_id)
        id_token_1 = self._mint_token("id_token", grant, _session_id)

        refresh_token = self._mint_token("refresh_token", grant, _session_id, code)
        id_token_2 = self._mint_token("id_token", grant, _session_id, code)

        _jwt1 = factory(id_token_1.value)
        _jwt2 = factory(id_token_2.value)
        assert _jwt1.jwt.payload()['sid'] == _jwt2.jwt.payload()['sid']

        assert id_token_1.session_id == id_token_2.session_id

        idt = grant.last_issued_token_of_type("id_token")

        assert idt.session_id == id_token_2.session_id

        id_token_3 = self._mint_token("id_token", grant, _session_id, refresh_token)

        idt = grant.last_issued_token_of_type("id_token")

        assert idt.session_id == id_token_3.session_id
