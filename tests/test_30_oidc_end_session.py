import copy
import json
import os
from urllib.parse import parse_qs
from urllib.parse import urlparse

from cryptojwt.key_jar import build_keyjar
from oidcmsg.exception import InvalidRequest
from oidcmsg.message import Message
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import verified_claim_name
from oidcmsg.oidc import verify_id_token
from oidcmsg.time_util import utc_time_sans_frac
import pytest
import responses

from oidcop.configure import OPConfiguration
from oidcop.cookie_handler import CookieHandler
from oidcop.exception import RedirectURIError
from oidcop.oauth2.authorization import join_query
from oidcop.oidc import userinfo
from oidcop.oidc.authorization import Authorization
from oidcop.oidc.provider_config import ProviderConfiguration
from oidcop.oidc.registration import Registration
from oidcop.oidc.session import Session
from oidcop.oidc.session import do_front_channel_logout_iframe
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


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": ISS,
            "password": "mycket hemlig zebra",
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
                    "kwargs": {"lifetime": 3600, "aud": ["https://example.org/appl"], },
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
        }

        cookie_conf = {
            "sign_key": "ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch",
            "name": {
                "session": "oidc_op",
                "register": "oidc_op_reg",
                "session_management": "oidc_op_sman",
            },
        }
        self.cd = CookieHandler(**cookie_conf)
        server = Server(
            OPConfiguration(conf=conf, base_path=BASEDIR),
            cwd=BASEDIR,
            cookie_handler=self.cd,
            keyjar=KEYJAR,
        )
        endpoint_context = server.endpoint_context
        endpoint_context.cdb = {
            "client_1": {
                "client_secret": "hemligt",
                "redirect_uris": [("{}cb".format(CLI1), None)],
                "client_salt": "salted",
                "token_endpoint_auth_method": "client_secret_post",
                "response_types": ["code", "token", "code id_token", "id_token"],
                "post_logout_redirect_uri": [f"{CLI1}logout_cb", ""],
            },
            "client_2": {
                "client_secret": "hemligare",
                "redirect_uris": [("{}cb".format(CLI2), None)],
                "client_salt": "saltare",
                "token_endpoint_auth_method": "client_secret_post",
                "response_types": ["code", "token", "code id_token", "id_token"],
                "post_logout_redirect_uri": [f"{CLI2}logout_cb", ""],
            },
        }
        self.endpoint_context = endpoint_context
        self.session_manager = endpoint_context.session_manager
        self.authn_endpoint = server.server_get("endpoint", "authorization")
        self.session_endpoint = server.server_get("endpoint", "session")
        self.token_endpoint = server.server_get("endpoint", "token")
        self.user_id = "diana"

    def test_end_session_endpoint(self):
        # End session not allowed if no cookie and no id_token_hint is sent
        # (can't determine session)
        http_info = {"headers": {"cookie": ["FAIL"]}}
        with pytest.raises(ValueError):
            _ = self.session_endpoint.process_request("", http_info=http_info)

    def _create_cookie(self, session_id):
        ec = self.session_endpoint.server_get("endpoint_context")
        return ec.new_cookie(name=ec.cookie_handler.name["session"], sid=session_id, )

    def _code_auth(self, state):
        req = AuthorizationRequest(
            state=state,
            response_type="code",
            redirect_uri="{}cb".format(CLI1),
            scope=["openid"],
            client_id="client_1",
        )
        _pr_resp = self.authn_endpoint.parse_request(req.to_dict())
        return self.authn_endpoint.process_request(_pr_resp)

    def _code_auth2(self, state):
        req = AuthorizationRequest(
            state=state,
            response_type="code",
            redirect_uri="{}cb".format(CLI2),
            scope=["openid"],
            client_id="client_2",
        )
        _pr_resp = self.authn_endpoint.parse_request(req.to_dict())
        return self.authn_endpoint.process_request(_pr_resp)

    def _auth_with_id_token(self, state):
        req = AuthorizationRequest(
            state=state,
            response_type="id_token",
            redirect_uri="{}cb".format(CLI1),
            scope=["openid"],
            client_id="client_1",
            nonce="_nonce_",
        )
        _pr_resp = self.authn_endpoint.parse_request(req.to_dict())
        _resp = self.authn_endpoint.process_request(_pr_resp)

        _info = self.session_endpoint.server_get("endpoint_context").cookie_handler.parse_cookie(
            "oidc_op", _resp["cookie"]
        )
        # value is a JSON document
        _cookie_info = json.loads(_info[0]["value"])

        return _resp["response_args"], _cookie_info["sid"]

    def _mint_token(self, token_class, grant, session_id, token_ref=None):
        return grant.mint_token(
            session_id=session_id,
            endpoint_context=self.endpoint_context,
            token_class=token_class,
            token_handler=self.session_manager.token_handler[token_class],
            expires_at=utc_time_sans_frac() + 900,  # 15 minutes from now
            based_on=token_ref,  # Means the token (tok) was used to mint this token
        )

    def test_end_session_endpoint_with_cookie(self):
        _resp = self._code_auth("1234567")
        _code = _resp["response_args"]["code"]
        _session_info = self.session_manager.get_session_info_by_token(_code)
        cookie = self._create_cookie(_session_info["session_id"])
        http_info = {"cookie": [cookie]}
        _req_args = self.session_endpoint.parse_request({"state": "1234567"}, http_info=http_info)
        resp = self.session_endpoint.process_request(_req_args, http_info=http_info)

        # returns a signed JWT to be put in a verification web page shown to
        # the user

        p = urlparse(resp["redirect_location"])
        qs = parse_qs(p.query)
        jwt_info = self.session_endpoint.unpack_signed_jwt(qs["sjwt"][0])

        assert jwt_info["sid"] == _session_info["session_id"]
        assert jwt_info["redirect_uri"] == "https://example.com/post_logout"

    def test_end_session_endpoint_with_cookie_and_unknown_sid(self):
        # Need cookie and ID Token to figure this out
        resp_args, _session_id = self._auth_with_id_token("1234567")
        id_token = resp_args["id_token"]

        _uid, _cid, _gid = self.session_manager.decrypt_session_id(_session_id)
        cookie = self._create_cookie(self.session_manager.session_key(_uid, "client_66", _gid))
        http_info = {"cookie": [cookie]}

        with pytest.raises(ValueError):
            self.session_endpoint.process_request({"state": "foo"}, http_info=http_info)

    def test_end_session_endpoint_with_cookie_id_token_and_unknown_sid(self):
        # Need cookie and ID Token to figure this out
        resp_args, _session_id = self._auth_with_id_token("1234567")
        id_token = resp_args["id_token"]

        _uid, _cid, _gid = self.session_manager.decrypt_session_id(_session_id)
        cookie = self._create_cookie(self.session_manager.session_key(_uid, "client_66", _gid))
        http_info = {"cookie": [cookie]}

        msg = Message(id_token=id_token)
        verify_id_token(msg, keyjar=self.session_endpoint.server_get("endpoint_context").keyjar)

        msg2 = Message(id_token_hint=id_token)
        msg2[verified_claim_name("id_token_hint")] = msg[verified_claim_name("id_token")]
        with pytest.raises(ValueError):
            self.session_endpoint.process_request(msg2, http_info=http_info)

    def test_end_session_endpoint_with_cookie_dual_login(self):
        _resp = self._code_auth("1234567")
        self._code_auth2("abcdefg")
        _code = _resp["response_args"]["code"]
        _session_info = self.session_manager.get_session_info_by_token(_code)
        cookie = self._create_cookie(_session_info["session_id"])
        http_info = {"cookie": [cookie]}

        resp = self.session_endpoint.process_request({"state": "abcde"}, http_info=http_info)

        # returns a signed JWT to be put in a verification web page shown to
        # the user

        p = urlparse(resp["redirect_location"])
        qs = parse_qs(p.query)
        jwt_info = self.session_endpoint.unpack_signed_jwt(qs["sjwt"][0])

        assert jwt_info["sid"] == _session_info["session_id"]
        assert jwt_info["redirect_uri"] == "https://example.com/post_logout"

    def test_end_session_endpoint_with_post_logout_redirect_uri(self):
        _resp = self._code_auth("1234567")
        self._code_auth2("abcdefg")
        _code = _resp["response_args"]["code"]
        _session_info = self.session_manager.get_session_info_by_token(_code)
        cookie = self._create_cookie(_session_info["session_id"])
        http_info = {"cookie": [cookie]}

        post_logout_redirect_uri = join_query(
            *self.session_endpoint.server_get("endpoint_context").cdb["client_1"][
                "post_logout_redirect_uri"]
        )

        with pytest.raises(InvalidRequest):
            self.session_endpoint.process_request(
                {"post_logout_redirect_uri": post_logout_redirect_uri, "state": "abcde", },
                http_info=http_info,
            )

    def test_end_session_endpoint_with_wrong_post_logout_redirect_uri(self):
        _resp = self._code_auth("1234567")
        self._code_auth2("abcdefg")

        resp_args, _session_id = self._auth_with_id_token("1234567")
        id_token = resp_args["id_token"]

        cookie = self._create_cookie(_session_id)
        http_info = {"cookie": [cookie]}

        post_logout_redirect_uri = "https://demo.example.com/log_out"

        msg = Message(id_token=id_token)
        verify_id_token(msg, keyjar=self.session_endpoint.server_get("endpoint_context").keyjar)

        with pytest.raises(RedirectURIError):
            self.session_endpoint.process_request(
                {
                    "post_logout_redirect_uri": post_logout_redirect_uri,
                    "state": "abcde",
                    "id_token_hint": id_token,
                    verified_claim_name("id_token_hint"): msg[verified_claim_name("id_token")],
                },
                http_info=http_info,
            )

    def test_back_channel_logout_no_backchannel_logout_uri(self):
        info = self._code_auth("1234567")

        res = self.session_endpoint.do_back_channel_logout(
            self.session_endpoint.server_get("endpoint_context").cdb["client_1"],
            info["session_id"]
        )
        assert res is None

    def test_back_channel_logout(self):
        info = self._code_auth("1234567")

        _cdb = copy.copy(self.session_endpoint.server_get("endpoint_context").cdb["client_1"])
        _cdb["backchannel_logout_uri"] = "https://example.com/bc_logout"
        _cdb["client_id"] = "client_1"
        res = self.session_endpoint.do_back_channel_logout(_cdb, info["session_id"])
        assert isinstance(res, tuple)
        assert res[0] == "https://example.com/bc_logout"
        _jwt = self.session_endpoint.unpack_signed_jwt(res[1], "RS256")
        assert _jwt
        assert _jwt["iss"] == ISS
        assert _jwt["aud"] == ["client_1"]
        assert "sid" in _jwt

    def test_front_channel_logout(self):
        self._code_auth("1234567")

        _cdb = copy.copy(self.session_endpoint.server_get("endpoint_context").cdb["client_1"])
        _cdb["frontchannel_logout_uri"] = "https://example.com/fc_logout"
        _cdb["client_id"] = "client_1"
        res = do_front_channel_logout_iframe(_cdb, ISS, "_sid_")
        assert res == '<iframe src="https://example.com/fc_logout">'

    def test_front_channel_logout_session_required(self):
        self._code_auth("1234567")

        _cdb = copy.copy(self.session_endpoint.server_get("endpoint_context").cdb["client_1"])
        _cdb["frontchannel_logout_uri"] = "https://example.com/fc_logout"
        _cdb["frontchannel_logout_session_required"] = True
        _cdb["client_id"] = "client_1"
        res = do_front_channel_logout_iframe(_cdb, ISS, "_sid_")
        test_res = (
            '<iframe src="https://example.com/fc_logout?',
            "iss=https%3A%2F%2Fexample.com%2F",
            "sid=_sid_",
        )
        for i in test_res:
            assert i in res

    def test_front_channel_logout_with_query(self):
        self._code_auth("1234567")

        _cdb = copy.copy(self.session_endpoint.server_get("endpoint_context").cdb["client_1"])
        _cdb["frontchannel_logout_uri"] = "https://example.com/fc_logout?entity_id=foo"
        _cdb["frontchannel_logout_session_required"] = True
        _cdb["client_id"] = "client_1"
        res = do_front_channel_logout_iframe(_cdb, ISS, "_sid_")
        test_res = (
            "<iframe",
            'src="https://example.com/fc_logout?',
            "entity_id=foo",
            "iss=https%3A%2F%2Fexample.com%2F",
            "sid=_sid_",
        )
        for i in test_res:
            assert i in res

    def test_logout_from_client_bc(self):
        _resp = self._code_auth("1234567")
        _code = _resp["response_args"]["code"]
        _session_info = self.session_manager.get_session_info_by_token(
            _code, client_session_info=True
        )

        self.session_endpoint.server_get("endpoint_context").cdb["client_1"][
            "backchannel_logout_uri"
        ] = "https://example.com/bc_logout"
        self.session_endpoint.server_get("endpoint_context").cdb["client_1"][
            "client_id"
        ] = "client_1"

        res = self.session_endpoint.logout_from_client(_session_info["session_id"])
        assert set(res.keys()) == {"blu"}
        assert set(res["blu"].keys()) == {"client_1"}
        _spec = res["blu"]["client_1"]
        assert _spec[0] == "https://example.com/bc_logout"
        _jwt = self.session_endpoint.unpack_signed_jwt(_spec[1], "RS256")
        assert _jwt
        assert _jwt["iss"] == ISS
        assert _jwt["aud"] == ["client_1"]
        assert "sid" in _jwt  # This session ID is not the same as the session_id mentioned above

        assert _jwt["sid"] == _session_info["session_id"]
        assert _session_info["client_session_info"].is_revoked()

    def test_logout_from_client_fc(self):
        _resp = self._code_auth("1234567")
        _code = _resp["response_args"]["code"]
        _session_info = self.session_manager.get_session_info_by_token(
            _code, client_session_info=True
        )

        # del self.session_endpoint.server_get("endpoint_context").cdb['client_1'][
        # 'backchannel_logout_uri']
        self.session_endpoint.server_get("endpoint_context").cdb["client_1"][
            "frontchannel_logout_uri"
        ] = "https://example.com/fc_logout"
        self.session_endpoint.server_get("endpoint_context").cdb["client_1"][
            "client_id"
        ] = "client_1"

        res = self.session_endpoint.logout_from_client(_session_info["session_id"])
        assert set(res.keys()) == {"flu"}
        assert set(res["flu"].keys()) == {"client_1"}
        _spec = res["flu"]["client_1"]
        assert _spec == '<iframe src="https://example.com/fc_logout">'

        assert _session_info["client_session_info"].is_revoked()

    def test_logout_from_client(self):
        _resp = self._code_auth("1234567")
        _code = _resp["response_args"]["code"]
        _session_info = self.session_manager.get_session_info_by_token(
            _code, client_session_info=True, grant=True
        )
        _grant_code = self.session_manager.find_token(_session_info["session_id"], _code)
        id_token1 = self._mint_token("id_token", _session_info["grant"],
                                     _session_info["session_id"], _grant_code)

        _resp2 = self._code_auth2("abcdefg")
        _code2 = _resp2["response_args"]["code"]
        _session_info2 = self.session_manager.get_session_info_by_token(
            _code2, client_session_info=True, grant=True
        )
        _grant_code2 = self.session_manager.find_token(_session_info2["session_id"], _code2)
        id_token2 = self._mint_token("id_token", _session_info2["grant"],
                                     _session_info2["session_id"], _grant_code2)

        # client0
        self.session_endpoint.server_get("endpoint_context").cdb["client_1"][
            "backchannel_logout_uri"
        ] = "https://example.com/bc_logout"
        self.session_endpoint.server_get("endpoint_context").cdb["client_1"][
            "client_id"
        ] = "client_1"
        self.session_endpoint.server_get("endpoint_context").cdb["client_2"][
            "frontchannel_logout_uri"
        ] = "https://example.com/fc_logout"
        self.session_endpoint.server_get("endpoint_context").cdb["client_2"][
            "client_id"
        ] = "client_2"

        res = self.session_endpoint.logout_all_clients(_session_info["session_id"])

        assert res
        assert set(res.keys()) == {"blu", "flu"}
        # Front channel logout
        assert set(res["flu"].keys()) == {"client_2"}
        _spec = res["flu"]["client_2"]
        assert _spec == '<iframe src="https://example.com/fc_logout">'
        # Back channel logout
        assert set(res["blu"].keys()) == {"client_1"}
        logout_url, logout_token = res["blu"]["client_1"]
        assert logout_url == "https://example.com/bc_logout"
        _jwt = self.session_endpoint.unpack_signed_jwt(logout_token, "RS256")
        assert _jwt
        assert _jwt["iss"] == ISS
        assert _jwt["aud"] == ["client_1"]
        assert _jwt["sid"] == id_token1.session_id
        _id_token = self.session_endpoint.unpack_signed_jwt(id_token1.value, "RS256")
        assert _id_token["sid"] == _jwt["sid"]

        # both should be revoked
        assert _session_info["client_session_info"].is_revoked()
        _cinfo = self.session_manager[
            self.session_manager.encrypted_session_id(self.user_id, "client_2")
        ]
        assert _cinfo.is_revoked()

    def test_do_verified_logout(self):
        with responses.RequestsMock() as rsps:
            rsps.add("POST", "https://example.com/bc_logout", body="OK", status=200)

            _resp = self._code_auth("1234567")
            _code = _resp["response_args"]["code"]
            _session_info = self.session_manager.get_session_info_by_token(_code)
            _cdb = self.session_endpoint.server_get("endpoint_context").cdb
            _cdb["client_1"]["backchannel_logout_uri"] = "https://example.com/bc_logout"
            _cdb["client_1"]["client_id"] = "client_1"

            res = self.session_endpoint.do_verified_logout(_session_info["session_id"])
            assert res == []

    def test_logout_from_client_unknow_sid(self):
        _resp = self._code_auth("1234567")
        _code = _resp["response_args"]["code"]
        _session_info = self.session_manager.get_session_info_by_token(_code)
        self._code_auth2("abcdefg")

        _uid, _cid, _gid = self.session_manager.decrypt_session_id(_session_info["session_id"])
        _sid = self.session_manager.encrypted_session_id("babs", _cid, _gid)
        with pytest.raises(KeyError):
            res = self.session_endpoint.logout_all_clients(_sid)

    def test_logout_from_client_no_session(self):
        _resp = self._code_auth("1234567")
        _code = _resp["response_args"]["code"]
        _session_info = self.session_manager.get_session_info_by_token(_code)
        self._code_auth2("abcdefg")

        # client0
        self.session_endpoint.server_get("endpoint_context").cdb["client_1"][
            "backchannel_logout_uri"
        ] = "https://example.com/bc_logout"
        self.session_endpoint.server_get("endpoint_context").cdb["client_1"][
            "client_id"
        ] = "client_1"
        self.session_endpoint.server_get("endpoint_context").cdb["client_2"][
            "frontchannel_logout_uri"
        ] = "https://example.com/fc_logout"
        self.session_endpoint.server_get("endpoint_context").cdb["client_2"][
            "client_id"
        ] = "client_2"

        _uid, _cid, _gid = self.session_manager.decrypt_session_id(_session_info["session_id"])
        self.session_endpoint.server_get("endpoint_context").session_manager.delete([_uid, _cid])

        with pytest.raises(ValueError):
            self.session_endpoint.logout_all_clients(_session_info["session_id"])

    def test_kill_cookies(self):
        _info = self.session_endpoint.kill_cookies()
        assert len(_info) == 2
        _names = [ci["name"] for ci in _info]
        assert set(_names) == {"oidc_op_sman", "oidc_op"}
        _values = [ci["value"] for ci in _info]
        assert set(_values) == {"", ""}
        _exps = [ci["expires"] for ci in _info]
        assert set(_exps) == {
            "Thu, 01 Jan 1970 00:00:00 GMT;",
            "Thu, 01 Jan 1970 00:00:00 GMT;",
        }
