import json
import os

from cryptojwt.jws import jws
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import KeyJar
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import RegistrationResponse
from oidcmsg.time_util import time_sans_frac
import pytest

from oidcop.authn_event import create_authn_event
from oidcop.client_authn import verify_client
from oidcop.endpoint_context import EndpointContext
from oidcop.id_token import IDToken
from oidcop.id_token import get_sign_and_encrypt_algorithms
from oidcop.oidc import userinfo
from oidcop.oidc.authorization import Authorization
from oidcop.oidc.token import Token
from oidcop.server import Server
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
    claims={"id_token": {"nickname": None}}
)

conf = {
    "issuer": "https://example.com/",
    "password": "mycket hemligt",
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "verify_ssl": False,
    "keys": {"key_defs": KEYDEFS, "uri_path": "static/jwks.json"},
    "jwks_uri": "https://example.com/jwks.json",
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
        }
    },
    "userinfo": {"class": "oidcop.user_info.UserInfo", "kwargs": {"db": USERS}, },
    "client_authn": verify_client,
    "template_dir": "template",
    "id_token": {"class": IDToken, "kwargs": {"foo": "bar"}},
}

USER_ID = "diana"


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_idtoken(self):
        server = Server(conf)
        self.endpoint_context = server.endpoint_context
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligtochintekort",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        self.endpoint_context.keyjar.add_symmetric(
            "client_1", "hemligtochintekort", ["sig", "enc"]
        )
        self.session_manager = self.endpoint_context.session_manager
        self.user_id = USER_ID

    def _create_session(self, auth_req, sub_type="public", sector_identifier=''):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req

        client_id = authz_req['client_id']
        ae = create_authn_event(self.user_id)
        return self.session_manager.create_session(ae, authz_req, self.user_id,
                                                   client_id=client_id,
                                                   sub_type=sub_type)

    def _mint_code(self, grant, session_id):
        # Constructing an authorization code is now done
        return grant.mint_token(
            session_id=session_id,
            endpoint_context=self.endpoint_context,
            token_type="authorization_code",
            token_handler=self.session_manager.token_handler["code"],
            expires_at=time_sans_frac() + 300  # 5 minutes from now
        )

    def _mint_access_token(self, grant, session_id, token_ref):
        return grant.mint_token(
            session_id=session_id,
            endpoint_context=self.endpoint_context,
            token_type="access_token",
            token_handler=self.session_manager.token_handler["access_token"],
            expires_at=time_sans_frac() + 900,  # 15 minutes from now
            based_on=token_ref  # Means the token (tok) was used to mint this token
        )

    def test_id_token_payload_0(self):
        session_id = self._create_session(AREQ)
        payload = self.endpoint_context.idtoken.payload(session_id)
        assert set(payload.keys()) == {"sub", "nonce", "auth_time"}

    def test_id_token_payload_with_code(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]

        code = self._mint_code(grant, session_id)
        payload = self.endpoint_context.idtoken.payload(
            session_id, AREQ["client_id"], code=code.value
        )
        assert set(payload.keys()) == {"nonce", "c_hash", "sub", "auth_time"}

    def test_id_token_payload_with_access_token(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]

        code = self._mint_code(grant, session_id)
        access_token = self._mint_access_token(grant, session_id, code)

        payload = self.endpoint_context.idtoken.payload(
            session_id, AREQ["client_id"], access_token=access_token.value
        )
        assert set(payload.keys()) == {"nonce", "at_hash", "sub", "auth_time"}

    def test_id_token_payload_with_code_and_access_token(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]

        code = self._mint_code(grant, session_id)
        access_token = self._mint_access_token(grant, session_id, code)

        payload = self.endpoint_context.idtoken.payload(
            session_id, AREQ["client_id"], access_token=access_token.value, code=code.value
        )
        assert set(payload.keys()) == {"nonce", "c_hash", "at_hash", "sub", "auth_time"}

    def test_id_token_payload_with_userinfo(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]
        grant.claims = {"id_token": {"given_name": None}}

        payload = self.endpoint_context.idtoken.payload(session_id=session_id)
        assert set(payload.keys()) == {"nonce", "given_name", "sub", "auth_time"}

    def test_id_token_payload_many_0(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]
        grant.claims = {"id_token": {"given_name": None}}
        code = self._mint_code(grant, session_id)
        access_token = self._mint_access_token(grant, session_id, code)

        payload = self.endpoint_context.idtoken.payload(
            session_id, AREQ["client_id"],
            access_token=access_token.value,
            code=code.value
        )
        assert set(payload.keys()) == {"nonce", "c_hash", "at_hash", "sub", "auth_time",
                                       "given_name"}

    def test_sign_encrypt_id_token(self):
        session_id = self._create_session(AREQ)

        _token = self.endpoint_context.idtoken.sign_encrypt(session_id, AREQ['client_id'],
                                                            sign=True)
        assert _token

        _jws = jws.factory(_token)

        assert _jws.jwt.headers["alg"] == "RS256"

        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)

        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(_token)
        assert isinstance(res, dict)
        assert res["aud"] == ["client_1"]

    def test_get_sign_algorithm(self):
        client_info = self.endpoint_context.cdb[AREQ['client_id']]
        algs = get_sign_and_encrypt_algorithms(
            self.endpoint_context, client_info, "id_token", sign=True
        )
        # default signing alg
        assert algs == {"sign": True, "encrypt": False, "sign_alg": "RS256"}

    def test_no_default_encrypt_algorithms(self):
        client_info = RegistrationResponse()
        args = get_sign_and_encrypt_algorithms(
            self.endpoint_context, client_info, "id_token", sign=True, encrypt=True
        )
        assert args["sign_alg"] == "RS256"
        assert args["enc_enc"] == "A128CBC-HS256"
        assert args["enc_alg"] == "RSA1_5"

    def test_get_sign_algorithm_2(self):
        client_info = RegistrationResponse(id_token_signed_response_alg="RS512")
        algs = get_sign_and_encrypt_algorithms(
            self.endpoint_context, client_info, "id_token", sign=True
        )
        # default signing alg
        assert algs == {"sign": True, "encrypt": False, "sign_alg": "RS512"}

    def test_get_sign_algorithm_3(self):
        client_info = RegistrationResponse()
        self.endpoint_context.jwx_def["signing_alg"] = {"id_token": "RS384"}

        algs = get_sign_and_encrypt_algorithms(
            self.endpoint_context, client_info, "id_token", sign=True
        )
        # default signing alg
        assert algs == {"sign": True, "encrypt": False, "sign_alg": "RS384"}

    def test_get_sign_algorithm_4(self):
        client_info = RegistrationResponse(id_token_signed_response_alg="RS512")
        self.endpoint_context = EndpointContext(conf)
        self.endpoint_context.jwx_def["signing_alg"] = {"id_token": "RS384"}

        algs = get_sign_and_encrypt_algorithms(
            self.endpoint_context, client_info, "id_token", sign=True
        )
        # default signing alg
        assert algs == {"sign": True, "encrypt": False, "sign_alg": "RS512"}

    def test_available_claims(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]
        grant.claims = {"id_token": {"nickname": {"essential": True}}}

        _token = self.endpoint_context.idtoken.make(session_id=session_id)
        assert _token
        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(_token)
        assert "nickname" in res

    def test_no_available_claims(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]
        grant.claims = {"id_token": {"foobar": None}}

        req = {"client_id": "client_1"}
        _token = self.endpoint_context.idtoken.make(session_id=session_id)
        assert _token
        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(_token)
        assert "foobar" not in res

    def test_client_claims(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]

        self.endpoint_context.idtoken.kwargs["enable_claims_per_client"] = True
        self.endpoint_context.cdb["client_1"]["id_token_claims"] = {"address": None}

        _claims = self.endpoint_context.claims_interface.get_claims(
            session_id=session_id, scopes=AREQ["scope"], usage="id_token")
        grant.claims = {'id_token': _claims}

        _token = self.endpoint_context.idtoken.make(session_id=session_id)
        assert _token
        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(_token)
        assert "address" in res
        assert "nickname" not in res

    def test_client_claims_with_default(self):
        session_id = self._create_session(AREQ)
        grant = self.session_manager[session_id]

        # self.endpoint_context.cdb["client_1"]["id_token_claims"] = {"address": None}
        # self.endpoint_context.idtoken.enable_claims_per_client = True

        _claims = self.endpoint_context.claims_interface.get_claims(
            session_id=session_id, scopes=AREQ["scope"], usage="id_token")
        grant.claims = {"id_token": _claims}

        _token = self.endpoint_context.idtoken.make(session_id=session_id)
        assert _token
        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(_token)

        # No user info claims should be there
        assert "address" not in res
        assert "nickname" not in res

    def test_client_claims_scopes(self):
        session_id = self._create_session(AREQS)
        grant = self.session_manager[session_id]

        self.endpoint_context.idtoken.kwargs["add_claims_by_scope"] = True
        _claims = self.endpoint_context.claims_interface.get_claims(
            session_id=session_id, scopes=AREQS["scope"], usage="id_token")
        grant.claims = {"id_token": _claims}

        _token = self.endpoint_context.idtoken.make(session_id=session_id)
        assert _token
        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(_token)
        assert "address" in res
        assert "email" in res
        assert "nickname" not in res

    def test_client_claims_scopes_and_request_claims_no_match(self):
        session_id = self._create_session(AREQRC)
        grant = self.session_manager[session_id]

        self.endpoint_context.idtoken.kwargs["add_claims_by_scope"] = True
        _claims = self.endpoint_context.claims_interface.get_claims(
            session_id=session_id, scopes=AREQRC["scope"], usage="id_token")
        grant.claims = {"id_token": _claims}

        _token = self.endpoint_context.idtoken.make(session_id=session_id)
        assert _token
        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(_token)
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

        self.endpoint_context.idtoken.kwargs["add_claims_by_scope"] = True
        _claims = self.endpoint_context.claims_interface.get_claims(
            session_id=session_id, scopes=_req["scope"], usage="id_token")
        grant.claims = {"id_token": _claims}

        _token = self.endpoint_context.idtoken.make(session_id=session_id)
        assert _token
        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(_token)
        # Email didn't match
        assert "email" not in res
        # Scope -> claims
        assert "address" in res
