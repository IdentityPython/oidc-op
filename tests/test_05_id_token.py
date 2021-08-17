import json
import os

import pytest
from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.time_util import time_sans_frac

from oidcop.authn_event import create_authn_event
from oidcop.client_authn import verify_client
from oidcop.oidc import userinfo
from oidcop.oidc.authorization import Authorization
from oidcop.oidc.token import Token
from oidcop.server import Server
from oidcop.token.id_token import get_sign_and_encrypt_algorithms
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcop.user_info import UserInfo

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERS = json.loads(open(full_path("users.json")).read())
USERINFO = UserInfo(USERS)
LIFETIME = 200

AREQ = AuthorizationRequest(
    response_type="code",
    client_id="client_1",
    redirect_uri="http://example.com/authz",
    scope=["openid"],
    state="state000",
    nonce="nonce",
)

AREQS = AuthorizationRequest(
    response_type="code",
    client_id="client_1",
    redirect_uri="http://example.com/authz",
    scope=["openid", "address", "email"],
    state="state000",
    nonce="nonce",
)

AREQRC = AuthorizationRequest(
    response_type="code",
    client_id="client_1",
    redirect_uri="http://example.com/authz",
    scope=["openid", "address", "email"],
    state="state000",
    nonce="nonce",
    claims={"id_token": {"nickname": None}},
)

conf = {
    "issuer": "https://example.com/",
    "password": "mycket hemligt",
    "verify_ssl": False,
    "keys": {"key_defs": KEYDEFS, "uri_path": "static/jwks.json"},
    "token_handler_args": {
        "jwks_def": {
            "private_path": "private/token_jwks.json",
            "read_only": False,
            "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
        },
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
            "kwargs": {
                "base_claims": {
                    "email": {"essential": True},
                    "email_verified": {"essential": True},
                },
                "lifetime": LIFETIME,
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
        "userinfo_endpoint": {
            "path": "{}/userinfo",
            "class": userinfo.UserInfo,
            "kwargs": {"db_file": "users.json"},
        },
    },
    "authentication": {
        "anon": {
            "acr": INTERNETPROTOCOLPASSWORD,
            "class": "oidcop.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        },
        "mfa": {
            "acr": 'https://refeds.org/profile/mfa',
            "class": "oidcop.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
    "session_manager": {
        "grant_config": {
            "usage_rules": {
                "authorization_code": {
                    "supports_minting": ["access_token", "refresh_token", "id_token"],
                    "max_usage": 1,
                },
                "access_token": {},
                "refresh_token": {"supports_minting": ["access_token", "refresh_token"]},
            },
            "expires_in": 43200,
        }
    },
    "authz": {
        "class": "oidcop.authz.AuthzHandling",
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": ["access_token", "refresh_token", "id_token",],
                        "max_usage": 1,
                    },
                    "access_token": {},
                    "refresh_token": {"supports_minting": ["access_token", "refresh_token"]},
                },
                "expires_in": 43200,
            }
        },
    },
    "userinfo": {"class": "oidcop.user_info.UserInfo", "kwargs": {"db": USERS},},
    "client_authn": verify_client,
    "claims_interface": {"class": "oidcop.session.claims.ClaimsInterface", "kwargs": {}},
}

USER_ID = "diana"


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_session_manager(self):
        server = Server(conf)
        self.endpoint_context = server.endpoint_context
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligtochintekort",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        self.endpoint_context.keyjar.add_symmetric("client_1", "hemligtochintekort", ["sig", "enc"])
        self.session_manager = self.endpoint_context.session_manager
        self.user_id = USER_ID

    def _create_session(self, auth_req, sub_type="public", sector_identifier="", authn_info=''):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req

        client_id = authz_req["client_id"]
        ae = create_authn_event(self.user_id, authn_info=authn_info)
        return self.session_manager.create_session(
            ae, authz_req, self.user_id, client_id=client_id, sub_type=sub_type
        )

    def _mint_code(self, grant, session_id):
        # Constructing an authorization code is now done
        return grant.mint_token(
            session_id=session_id,
            endpoint_context=self.endpoint_context,
            token_class="authorization_code",
            token_handler=self.session_manager.token_handler["authorization_code"],
            expires_at=time_sans_frac() + 300,  # 5 minutes from now
        )

    def _mint_access_token(self, grant, session_id, token_ref):
        access_token = grant.mint_token(
            session_id=session_id,
            endpoint_context=self.endpoint_context,
            token_class="access_token",
            token_handler=self.session_manager.token_handler["access_token"],
            expires_at=time_sans_frac() + 900,  # 15 minutes from now
            based_on=token_ref,  # Means the token (tok) was used to mint this token
        )
        return access_token

    def _mint_id_token(self, grant, session_id, token_ref=None, code=None, access_token=None):
        return grant.mint_token(
            session_id=session_id,
            endpoint_context=self.endpoint_context,
            token_class="id_token",
            token_handler=self.session_manager.token_handler["id_token"],
            expires_at=time_sans_frac() + 900,  # 15 minutes from now
            based_on=token_ref,  # Means the token (tok) was used to mint this token
            code=code,
            access_token=access_token,
        )

    def test_id_token_payload_0(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        id_token = self._mint_id_token(grant, session_id, code)
        _jwt = factory(id_token.value)
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {
            "aud",
            "sub",
            "auth_time",
            "nonce",
            "iat",
            "exp",
            "email",
            "email_verified",
            "jti",
            "scope",
            "client_id",
            "iss",
        }

    def test_id_token_payload_with_code(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)

        id_token = self._mint_id_token(grant, session_id, token_ref=code, code=code.value)

        _jwt = factory(id_token.value)
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {
            "sub",
            "auth_time",
            "aud",
            "exp",
            "email",
            "email_verified",
            "jti",
            "scope",
            "client_id",
            "c_hash",
            "iss",
            "iat",
            "nonce",
        }

    def test_id_token_payload_with_access_token(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        access_token = self._mint_access_token(grant, session_id, code)

        id_token = self._mint_id_token(
            grant, session_id, token_ref=code, access_token=access_token.value
        )

        _jws = factory(id_token.value)
        assert _jws.jwt.headers["alg"] == "RS256"
        payload = _jws.jwt.payload()

        assert set(payload.keys()) == {
            "sub",
            "auth_time",
            "aud",
            "exp",
            "email",
            "email_verified",
            "jti",
            "scope",
            "client_id",
            "iss",
            "iat",
            "nonce",
            "at_hash",
        }

    def test_id_token_payload_with_code_and_access_token(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        access_token = self._mint_access_token(grant, session_id, code)

        id_token = self._mint_id_token(
            grant, session_id, token_ref=code, code=code.value, access_token=access_token.value,
        )

        _jwt = factory(id_token.value)
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {
            "sub",
            "auth_time",
            "aud",
            "exp",
            "email",
            "email_verified",
            "jti",
            "scope",
            "client_id",
            "iss",
            "iat",
            "nonce",
            "at_hash",
            "c_hash",
        }

    def test_id_token_payload_with_userinfo(self):
        req = dict(AREQ)
        req["claims"] = {"id_token": {"given_name": None}}
        session_id = self._create_session(req)
        grant = self.session_manager[session_id]

        id_token = self._mint_id_token(grant, session_id)

        _jwt = factory(id_token.value)
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {
            "nonce",
            "iat",
            "iss",
            "email",
            "email_verified",
            "jti",
            "scope",
            "client_id",
            "given_name",
            "aud",
            "exp",
            "auth_time",
            "sub",
        }

    def test_id_token_payload_many_0(self):
        req = dict(AREQ)
        req["claims"] = {"id_token": {"given_name": None}}
        session_id = self._create_session(req)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        access_token = self._mint_access_token(grant, session_id, code)

        id_token = self._mint_id_token(
            grant, session_id, token_ref=code, code=code.value, access_token=access_token.value,
        )

        _jwt = factory(id_token.value)
        payload = _jwt.jwt.payload()
        assert set(payload.keys()) == {
            "nonce",
            "c_hash",
            "at_hash",
            "email",
            "email_verified",
            "jti",
            "scope",
            "client_id",
            "sub",
            "auth_time",
            "given_name",
            "aud",
            "exp",
            "iat",
            "iss",
        }

    def test_sign_encrypt_id_token(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]
        id_token = self._mint_id_token(grant, session_id)

        _jws = factory(id_token.value)
        assert _jws.jwt.headers["alg"] == "RS256"

        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)

        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(id_token.value)
        assert isinstance(res, dict)
        assert res["aud"] == ["client_1"]

    def test_get_sign_algorithm(self):
        client_info = self.endpoint_context.cdb[AREQ["client_id"]]
        algs = get_sign_and_encrypt_algorithms(
            self.endpoint_context, client_info, "id_token", sign=True,
        )
        # default signing alg
        assert algs == {"sign": True, "encrypt": False, "sign_alg": "RS256"}

        algs = get_sign_and_encrypt_algorithms(
            self.endpoint_context, client_info, "id_token", sign=True, encrypt=True
        )
        # default signing alg
        assert algs == {
            "sign": True,
            "encrypt": True,
            "sign_alg": "RS256",
            "enc_alg": "RSA-OAEP",
            "enc_enc": "A128CBC-HS256",
        }

    def test_available_claims(self):
        req = dict(AREQ)
        req["claims"] = {"id_token": {"nickname": {"essential": True}}}
        session_id = self._create_session(req)
        grant = self.session_manager[session_id]

        id_token = self._mint_id_token(grant, session_id)

        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(id_token.value)
        assert "nickname" in res

    def test_lifetime_default(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]

        id_token = self._mint_id_token(grant, session_id)

        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(id_token.value)

        assert res["exp"] - res["iat"] == LIFETIME

    def test_lifetime(self):
        lifetime = 100

        self.session_manager.token_handler["id_token"].lifetime = lifetime
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]

        id_token = self._mint_id_token(grant, session_id)

        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(id_token.value)

        assert res["exp"] - res["iat"] == lifetime

    def test_no_available_claims(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]
        grant.claims = {"id_token": {"foobar": None}}

        id_token = self._mint_id_token(grant, session_id)

        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(id_token.value)
        assert "foobar" not in res

    def test_client_claims(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]

        self.session_manager.token_handler["id_token"].kwargs["enable_claims_per_client"] = True
        self.endpoint_context.cdb["client_1"]["id_token_claims"] = {"address": None}

        _claims = self.endpoint_context.claims_interface.get_claims(
            session_id=session_id, scopes=AREQ["scope"], claims_release_point="id_token"
        )
        grant.claims = {"id_token": _claims}

        id_token = self._mint_id_token(grant, session_id)

        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(id_token.value)
        assert "address" in res
        assert "nickname" not in res

    def test_client_claims_with_default(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]

        _claims = self.endpoint_context.claims_interface.get_claims(
            session_id=session_id, scopes=AREQ["scope"], claims_release_point="id_token"
        )
        grant.claims = {"id_token": _claims}

        id_token = self._mint_id_token(grant, session_id)

        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(id_token.value)

        # No user info claims should be there
        assert "address" not in res
        assert "nickname" not in res

    def test_client_claims_scopes(self):
        session_id = self._create_session(AREQS)
        grant = self.session_manager[session_id]

        self.session_manager.token_handler["id_token"].kwargs["add_claims_by_scope"] = True
        grant.scope = AREQS["scope"]

        id_token = self._mint_id_token(grant, session_id)

        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(id_token.value)
        assert "address" in res
        assert "email" in res
        assert "nickname" not in res

    def test_client_claims_scopes_and_request_claims_no_match(self):
        session_id = self._create_session(AREQRC)
        grant = self.session_manager[session_id]

        self.session_manager.token_handler["id_token"].kwargs["add_claims_by_scope"] = True
        grant.scope = AREQRC["scope"]

        id_token = self._mint_id_token(grant, session_id)

        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(id_token.value)
        # User information, from scopes -> claims
        assert "address" in res
        assert "email" in res
        # User info, requested by claims parameter
        assert "nickname" in res

    def test_client_claims_scopes_and_request_claims_one_match(self):
        _req = AREQS.copy()
        _req["claims"] = {"id_token": {"email": {"value": "diana@example.com"}}}

        session_id = self._create_session(_req)
        grant = self.session_manager[session_id]

        self.session_manager.token_handler["id_token"].kwargs["add_claims_by_scope"] = True
        grant.scope = _req["scope"]

        id_token = self._mint_id_token(grant, session_id)

        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(id_token.value)
        # Email didn't match
        assert "email" not in res
        # Scope -> claims
        assert "address" in res

    def test_id_token_info(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        access_token = self._mint_access_token(grant, session_id, code)

        id_token = self._mint_id_token(
            grant, session_id, token_ref=code, access_token=access_token.value
        )

        endpoint_context = self.endpoint_context
        sman = endpoint_context.session_manager
        _info = self.session_manager.token_handler.info(id_token.value)
        assert "sid" in _info
        assert "exp" in _info
        assert "aud" in _info

        client_id = AREQ.get("client_id")
        _id_token = sman.token_handler.handler["id_token"]
        _id_token.sign_encrypt(session_id, client_id)

        # TODO: we need an authentication event for this id_token for a better coverage
        _id_token.payload(session_id)

        client_info = endpoint_context.cdb[client_id]
        get_sign_and_encrypt_algorithms(
            endpoint_context, client_info, payload_type="id_token", sign=True, encrypt=True
        )

    def test_id_token_acr_claim(self):
        _req = AREQS.copy()
        _req["claims"] = {"id_token": {"acr": {"value": "https://refeds.org/profile/mfa"}}}

        session_id = self._create_session(_req,authn_info="https://refeds.org/profile/mfa")
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        access_token = self._mint_access_token(grant, session_id, code)

        id_token = self._mint_id_token(
            grant, session_id, token_ref=code, access_token=access_token.value
        )

        _jwt = factory(id_token.value)
        _id_token_content = _jwt.jwt.payload()
        assert _id_token_content["acr"] == "https://refeds.org/profile/mfa"

    def test_id_token_acr_none(self):
        _req = AREQS.copy()
        _req["claims"] = {"id_token": {"acr": None}}

        session_id = self._create_session(_req,authn_info="https://refeds.org/profile/mfa")
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        access_token = self._mint_access_token(grant, session_id, code)

        id_token = self._mint_id_token(
            grant, session_id, token_ref=code, access_token=access_token.value
        )

        _jwt = factory(id_token.value)
        _id_token_content = _jwt.jwt.payload()
        assert _id_token_content["acr"] == "https://refeds.org/profile/mfa"
