import json
import os

from cryptojwt.key_jar import build_keyjar
from oidcmsg.oidc import AuthorizationRequest
import pytest

from oidcop.authn_event import create_authn_event
from oidcop.cookie import CookieDealer
from oidcop.oidc import userinfo
from oidcop.oidc.authorization import Authorization
from oidcop.oidc.provider_config import ProviderConfiguration
from oidcop.oidc.registration import Registration
from oidcop.oidc.session import Session
from oidcop.oidc.token import Token
from oidcop.server import Server
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcop.user_info import UserInfo

ISS = "https://example.com/"

CLI1 = "https://client1.example.com/"
CLI2 = "https://client2.example.com/"

KEYDEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

KEYJAR = build_keyjar(KEYDEFS)
KEYJAR.import_jwks(KEYJAR.export_jwks(private=True), ISS)

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
    redirect_uri="{}cb".format(ISS),
    scope=["openid"],
    state="STATE",
    response_type="code",
    client_secret="hemligt",
)

AUTH_REQ_DICT = AUTH_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_db = json.loads(open(full_path("users.json")).read())

CDB = {
    "client_1": {
        "client_secret": "hemligt",
        "redirect_uris": [("{}cb".format(CLI1), None)],
        "client_salt": "salted",
        "token_endpoint_auth_method": "client_secret_post",
        "response_types": ["code", "token", "code id_token", "id_token"],
        "post_logout_redirect_uris": [("{}logout_cb".format(CLI1), "")],
    },
    "client_2": {
        "client_secret": "hemligare",
        "redirect_uris": [("{}cb".format(CLI2), None)],
        "client_salt": "saltare",
        "token_endpoint_auth_method": "client_secret_post",
        "response_types": ["code", "token", "code id_token", "id_token"],
        "post_logout_redirect_uris": [("{}logout_cb".format(CLI2), "")],
    },
}

CONF = {
    "issuer": ISS,
    "password": "mycket hemlig zebra",
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "verify_ssl": False,
    "capabilities": CAPABILITIES,
    "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
    "endpoint": {
        "provider_config": {
            "path": "{}/.well-known/openid-configuration",
            "class": ProviderConfiguration,
            "kwargs": {"client_authn_method": None},
        },
        "registration": {
            "path": "{}/registration",
            "class": Registration,
            "kwargs": {"client_authn_method": None},
        },
        "authorization": {
            "path": "{}/authorization",
            "class": Authorization,
            "kwargs": {"client_authn_method": None},
        },
        "token": {"path": "{}/token", "class": Token, "kwargs": {}},
        "userinfo": {
            "path": "{}/userinfo",
            "class": userinfo.UserInfo,
            "kwargs": {"db_file": "users.json"},
        },
        "session": {
            "path": "{}/end_session",
            "class": Session,
            "kwargs": {
                "post_logout_uri_path": "post_logout",
                "signing_alg": "ES256",
                "logout_verify_url": "{}/verify_logout".format(ISS),
                "client_authn_method": None,
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
    "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_db}},
    "template_dir": "template",
}

COOKIE_CONF = {
    "sign_key": "ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch",
    "default_values": {
        "name": "oidcop",
        "domain": "127.0.0.1",
        "path": "/",
        "max_age": 3600,
    },
}


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):

        self.cd = CookieDealer(**COOKIE_CONF)

        server = Server(CONF, cookie_dealer=self.cd, keyjar=KEYJAR)
        endpoint_context = server.endpoint_context
        endpoint_context.cdb = CDB

        self.session_manager = endpoint_context.session_manager
        self.authn_endpoint = server.server_get("endpoint", "authorization")
        self.session_endpoint = server.server_get("endpoint", "session")
        self.token_endpoint = server.server_get("endpoint", "token")
        self.user_id = "diana"

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
        return grant.mint_token(
            session_id=session_id,
            endpoint_context=self.authn_endpoint.server_get("endpoint_context"),
            token_type='authorization_code',
            token_handler=self.session_manager.token_handler["code"]
        )

    def _mint_access_token(self, grant, session_id, token_ref=None, resources=None):
        return grant.mint_token(
            session_id=session_id,
            endpoint_context=self.authn_endpoint.server_get("endpoint_context"),
            token_type='access_token',
            token_handler=self.session_manager.token_handler["access_token"],
            based_on=token_ref,
            resources=resources
        )

    def test_to(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        access_token = self._mint_access_token(grant, session_id, code)

        _store = self.session_manager.dump()
        assert _store
        _store_str = json.dumps(_store)

        server = Server(CONF, cookie_dealer=self.cd, keyjar=KEYJAR)
        server.endpoint_context.cdb = CDB
        _mngr = server.endpoint_context.session_manager

        _mngr.load(_store)

        _session_info = _mngr.get_session_info_by_token(access_token.value)
        assert _session_info
        code = _mngr.find_token(_session_info["session_id"], code.value)
        assert code.is_active()
