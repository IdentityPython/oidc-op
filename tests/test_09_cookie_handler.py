import pytest
from cryptojwt.jwk.hmac import SYMKey

from oidcop.cookie_handler import CookieHandler
from oidcop.cookie_handler import compute_session_state

KEYDEFS = [
    {"type": "OCT", "kid": "sig", "use": ["sig"]},
    {"type": "OCT", "kid": "enc", "use": ["enc"]},
]


class TestCookieSign(object):
    @pytest.fixture(autouse=True)
    def make_cookie_content_handler(self):
        cookie_conf = {
            "sign_key": SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch"),
        }

        self.cookie_handler = CookieHandler(**cookie_conf)

    def test_init(self):
        assert self.cookie_handler

    def test_make_cookie_content(self):
        _cookie_info = self.cookie_handler.make_cookie_content("oidcop", "value", "sso")
        assert _cookie_info
        assert set(_cookie_info.keys()) == {"name", "value"}
        assert len(_cookie_info["value"].split("|")) == 3

    def test_make_cookie_content_max_age(self):
        _cookie_info = self.cookie_handler.make_cookie_content(
            "oidcop", "value", "sso", max_age=3600
        )
        assert _cookie_info
        assert set(_cookie_info.keys()) == {"name", "value", "Max-Age"}
        assert len(_cookie_info["value"].split("|")) == 3

    def test_read_cookie_info(self):
        _cookie_info = [self.cookie_handler.make_cookie_content("oidcop", "value", "sso")]
        returned = [{"name": c["name"], "value": c["value"]} for c in _cookie_info]
        _info = self.cookie_handler.parse_cookie("oidcop", returned)
        assert len(_info) == 1
        assert set(_info[0].keys()) == {"value", "type", "timestamp"}
        assert _info[0]["value"] == "value"
        assert _info[0]["type"] == "sso"

    def test_mult_cookie(self):
        _cookie = [
            self.cookie_handler.make_cookie_content("oidcop", "value", "sso"),
            self.cookie_handler.make_cookie_content("oidcop", "session_state", "session"),
        ]
        assert len(_cookie) == 2
        _c_info = self.cookie_handler.parse_cookie("oidcop", _cookie)
        assert len(_c_info) == 2
        assert _c_info[0]["value"] == "value"
        assert _c_info[0]["type"] == "sso"
        assert _c_info[1]["value"] == "session_state"
        assert _c_info[1]["type"] == "session"


class TestCookieHandlerSignEnc(object):
    @pytest.fixture(autouse=True)
    def make_cookie_handler(self):
        cookie_conf = {
            "sign_key": SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch"),
            "enc_key": SYMKey(k="NXi6HD473d_YS4exVRn7z9z23mGmvU641MuvKqH0o7Y"),
        }

        self.cookie_handler = CookieHandler(**cookie_conf)

    def test_make_cookie_content(self):
        _cookie_info = self.cookie_handler.make_cookie_content("oidcop", "value", "sso")
        assert _cookie_info
        assert set(_cookie_info.keys()) == {"name", "value"}
        assert len(_cookie_info["value"].split("|")) == 4

    def test_make_cookie_content_max_age(self):
        _cookie_info = self.cookie_handler.make_cookie_content(
            "oidcop", "value", "sso", max_age=3600
        )
        assert _cookie_info
        assert set(_cookie_info.keys()) == {"name", "value", "Max-Age"}
        assert len(_cookie_info["value"].split("|")) == 4

    def test_read_cookie_info(self):
        _cookie_info = [self.cookie_handler.make_cookie_content("oidcop", "value", "sso")]
        returned = [{"name": c["name"], "value": c["value"]} for c in _cookie_info]
        _info = self.cookie_handler.parse_cookie("oidcop", returned)
        assert len(_info) == 1
        assert set(_info[0].keys()) == {"value", "type", "timestamp"}
        assert _info[0]["value"] == "value"
        assert _info[0]["type"] == "sso"

    def test_mult_cookie(self):
        _cookie = [
            self.cookie_handler.make_cookie_content("oidcop", "value", "sso"),
            self.cookie_handler.make_cookie_content("oidcop", "session_state", "session"),
        ]
        assert len(_cookie) == 2
        _c_info = self.cookie_handler.parse_cookie("oidcop", _cookie)
        assert len(_c_info) == 2
        assert _c_info[0]["value"] == "value"
        assert _c_info[0]["type"] == "sso"
        assert _c_info[1]["value"] == "session_state"
        assert _c_info[1]["type"] == "session"


class TestCookieHandlerEnc(object):
    @pytest.fixture(autouse=True)
    def make_cookie_content_handler(self):
        cookie_conf = {
            "enc_key": SYMKey(k="NXi6HD473d_YS4exVRn7z9z23mGmvU641MuvKqH0o7Y"),
        }

        self.cookie_handler = CookieHandler(**cookie_conf)

    def test_make_cookie_content(self):
        _cookie_info = self.cookie_handler.make_cookie_content("oidcop", "value", "sso")
        assert _cookie_info
        assert set(_cookie_info.keys()) == {"name", "value"}
        assert len(_cookie_info["value"].split("|")) == 4

    def test_make_cookie_content_max_age(self):
        _cookie_info = self.cookie_handler.make_cookie_content(
            "oidcop", "value", "sso", max_age=3600
        )
        assert _cookie_info
        assert set(_cookie_info.keys()) == {"name", "value", "Max-Age"}
        assert len(_cookie_info["value"].split("|")) == 4

    def test_read_cookie_info(self):
        _cookie_info = [self.cookie_handler.make_cookie_content("oidcop", "value", "sso")]
        returned = [{"name": c["name"], "value": c["value"]} for c in _cookie_info]
        _info = self.cookie_handler.parse_cookie("oidcop", returned)
        assert len(_info) == 1
        assert set(_info[0].keys()) == {"value", "type", "timestamp"}
        assert _info[0]["value"] == "value"
        assert _info[0]["type"] == "sso"

    def test_mult_cookie(self):
        _cookie = [
            self.cookie_handler.make_cookie_content("oidcop", "value", "sso"),
            self.cookie_handler.make_cookie_content("oidcop", "session_state", "session"),
        ]
        assert len(_cookie) == 2
        _c_info = self.cookie_handler.parse_cookie("oidcop", _cookie)
        assert len(_c_info) == 2
        assert _c_info[0]["value"] == "value"
        assert _c_info[0]["type"] == "sso"
        assert _c_info[1]["value"] == "session_state"
        assert _c_info[1]["type"] == "session"


class TestCookieHandlerSignEncKeys(object):
    @pytest.fixture(autouse=True)
    def make_cookie_handler(self):
        cookie_conf = {
            "keys": {
                "private_path": "private/cookie_jwks.json",
                "key_defs": KEYDEFS,
                "read_only": False,
            }
        }

        self.cookie_handler = CookieHandler(**cookie_conf)

    def test_make_cookie_content(self):
        _cookie_info = self.cookie_handler.make_cookie_content("oidcop", "value", "sso")
        assert _cookie_info
        assert set(_cookie_info.keys()) == {"name", "value"}
        assert len(_cookie_info["value"].split("|")) == 4

    def test_make_cookie_content_max_age(self):
        _cookie_info = self.cookie_handler.make_cookie_content(
            "oidcop", "value", "sso", max_age=3600
        )
        assert _cookie_info
        assert set(_cookie_info.keys()) == {"name", "value", "Max-Age"}
        assert len(_cookie_info["value"].split("|")) == 4

    def test_read_cookie_info(self):
        _cookie_info = [self.cookie_handler.make_cookie_content("oidcop", "value", "sso")]
        returned = [{"name": c["name"], "value": c["value"]} for c in _cookie_info]
        _info = self.cookie_handler.parse_cookie("oidcop", returned)
        assert len(_info) == 1
        assert set(_info[0].keys()) == {"value", "type", "timestamp"}
        assert _info[0]["value"] == "value"
        assert _info[0]["type"] == "sso"

    def test_mult_cookie(self):
        _cookie = [
            self.cookie_handler.make_cookie_content("oidcop", "value", "sso"),
            self.cookie_handler.make_cookie_content("oidcop", "session_state", "session"),
        ]
        assert len(_cookie) == 2
        _c_info = self.cookie_handler.parse_cookie("oidcop", _cookie)
        assert len(_c_info) == 2
        assert _c_info[0]["value"] == "value"
        assert _c_info[0]["type"] == "sso"
        assert _c_info[1]["value"] == "session_state"
        assert _c_info[1]["type"] == "session"


def test_compute_session_state():
    hv = compute_session_state("state", "salt", "client_id", "https://example.com/redirect")
    assert hv == "d21113fbe4b54661ae45f3a3233b0f865ccc646af248274b6fa5664267540e29.salt"


#
# def test_create_session_cookie():
#     kaka = create_session_cookie(
#         "sess_man", "session_state", domain="example.com", path="/"
#     )
#
#     assert isinstance(kaka, SimpleCookie)
#     assert {"sess_man"} == set(kaka.keys())
#     morsel = kaka["sess_man"]
#     assert morsel.value == "session_state"
#     assert morsel["path"] == "/"
#     assert morsel["domain"] == "example.com"
#
#
# def test_append_cookie():
#     kaka1 = create_session_cookie(
#         "sess_man", "session_state", domain="example.com", path="/"
#     )
#     kaka2 = create_session_cookie("foobar", "value", domain="example.com", path="/")
#
#     kakor = append_cookie(kaka1, kaka2)
#     assert {"sess_man", "foobar"} == set(kakor.keys())
#
#
# conf = {
#     "issuer": "https://example.com/",
#     "password": "mycket hemligt",
#     "token_expires_in": 600,
#     "grant_expires_in": 300,
#     "refresh_token_expires_in": 86400,
#     "verify_ssl": False,
#     "endpoint": {"token": {"path": "token", "class": Token, "kwargs": {}}},
#     "template_dir": "template",
#     "keys": {
#         "private_path": "own/jwks.json",
#         "key_defs": KEYDEFS,
#         "uri_path": "static/jwks.json",
#     },
# }
#
# cookie_conf = {
#     "sign_key": SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch"),
#     "default_values": {
#         "name": "oidc_op",
#         "domain": "example.com",
#         "path": "/",
#         "max_age": 3600,
#     },
# }
#
# client_id = "client_id"
# client_secret = "a_longer_client_secret"
# # Need to add the client_secret as a symmetric key bound to the client_id
# KEYJAR.add_symmetric(client_id, client_secret, ["sig"])
#
# endpoint_context = EndpointContext(conf, keyjar=KEYJAR)
# endpoint_context.cdb[client_id] = {"client_secret": client_secret}
# endpoint_context.cookie_handler = CookieHandler(**cookie_conf)
#
# enc_key = rndstr(32)
#
#
# def test_new_cookie():
#     kaka = new_cookie(
#         endpoint_context, "foobar", client_id="client_id", sid="sessionID"
#     )
#     assert isinstance(kaka, SimpleCookie)
#     assert {"foobar"} == set(kaka.keys())
#
#     val = endpoint_context.cookie_handler.get_cookie_value(kaka, "foobar")
#     assert isinstance(val, tuple)
#     b64val, ts, typ = val
#     info = cookie_value(b64val)
#     assert set(info.keys()) == {"client_id", "sid"}
#
#
# def test_cookie_default():
#     _key = SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch")
#     kaka = make_cookie("test", "data", sign_key=_key)
#     assert kaka["test"]["secure"] is True
#     assert kaka["test"]["httponly"] is True
#     assert kaka["test"]["samesite"] is ""
#
#
# def test_cookie_http_only_false():
#     _key = SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch")
#     kaka = make_cookie("test", "data", sign_key=_key, http_only=False)
#     assert kaka["test"]["secure"] is True
#     assert kaka["test"]["httponly"] is False
#     assert kaka["test"]["samesite"] is ""
#
#
# def test_cookie_not_secure():
#     _key = SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch")
#     kaka = make_cookie("test", "data", _key, secure=False)
#     assert kaka["test"]["secure"] is False
#     assert kaka["test"]["httponly"] is True
#     assert kaka["test"]["samesite"] is ""
#
#
# def test_cookie_same_site_none():
#     _key = SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch")
#     kaka = make_cookie("test", "data", sign_key=_key, same_site="None")
#     assert kaka["test"]["secure"] is True
#     assert kaka["test"]["httponly"] is True
#     assert kaka["test"]["samesite"] is "None"
#
#
# def test_cookie_enc():
#     _key = SYMKey(k=enc_key)
#     _enc_data = sign_enc_payload(json.dumps({"test": "data"}), timestamp=time.time(),
#     enc_key=_key)
#     _data, _timestamp = ver_dec_content(_enc_data.split('|'), enc_key=_key)
#     assert json.loads(_data) == {"test": "data"}
