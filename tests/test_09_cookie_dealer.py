import json
import time
from http.cookies import SimpleCookie

import pytest
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.key_jar import init_key_jar

from oidcop import rndstr
from oidcop.cookie import CookieDealer
from oidcop.cookie import append_cookie
from oidcop.cookie import compute_session_state
from oidcop.cookie import cookie_value
from oidcop.cookie import create_session_cookie
from oidcop.cookie import make_cookie
from oidcop.cookie import new_cookie
from oidcop.cookie import sign_enc_payload
from oidcop.cookie import ver_dec_content
from oidcop.endpoint_context import EndpointContext
from oidcop.oidc.token import Token

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

KEYJAR = init_key_jar("public.jwks", "private.jwks", KEYDEFS)


class TestCookieDealerSign(object):
    @pytest.fixture(autouse=True)
    def create_cookie_dealer(self):
        cookie_conf = {
            "sign_key": SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch"),
            "default_values": {
                "name": "oidc_op",
                "domain": "127.0.0.1",
                "path": "/",
                "max_age": 3600,
            },
        }

        self.cookie_dealer = CookieDealer(**cookie_conf)

    def test_init(self):
        assert self.cookie_dealer

    def test_create_cookie(self):
        _cookie = self.cookie_dealer.create_cookie("value", "sso")
        assert _cookie

    def test_read_created_cookie(self):
        _cookie = self.cookie_dealer.create_cookie("value", "sso")
        _value = self.cookie_dealer.get_cookie_value(_cookie)
        assert len(_value) == 3
        assert _value[0] == "value"
        assert _value[2] == "sso"

    def test_delete_cookie(self):
        _cookie = self.cookie_dealer.delete_cookie("openid")
        _morsel = _cookie["openid"]
        assert _morsel["expires"]
        _value = self.cookie_dealer.get_cookie_value(_cookie, "openid")
        assert _value[0] == ""
        assert _value[2] == ""

    def test_mult_cookie(self):
        _cookie = self.cookie_dealer.create_cookie("value", "sso")
        _cookie = self.cookie_dealer.append_cookie(
            _cookie, "session", "session_state", "session"
        )
        assert len(_cookie) == 2
        _value = self.cookie_dealer.get_cookie_value(_cookie, "session")
        assert _value[0] == "session_state"
        assert _value[2] == "session"
        _value = self.cookie_dealer.get_cookie_value(_cookie, "oidc_op")
        assert _value[0] == "value"
        assert _value[2] == "sso"


class TestCookieDealerSignEnc(object):
    @pytest.fixture(autouse=True)
    def create_cookie_dealer(self):
        cookie_conf = {
            "sign_key": SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch"),
            "enc_key": SYMKey(k="NXi6HD473d_YS4exVRn7z9z23mGmvU641MuvKqH0o7Y"),
            "default_values": {
                "name": "oidc_op",
                "domain": "127.0.0.1",
                "path": "/",
                "max_age": 3600,
            },
        }

        self.cookie_dealer = CookieDealer(**cookie_conf)

    def test_init(self):
        assert self.cookie_dealer

    def test_create_cookie(self):
        _cookie = self.cookie_dealer.create_cookie("value", "sso")
        assert _cookie

    def test_read_created_cookie(self):
        _cookie = self.cookie_dealer.create_cookie("value", "sso")
        _value = self.cookie_dealer.get_cookie_value(_cookie)
        assert len(_value) == 3
        assert _value[0] == "value"
        assert _value[2] == "sso"

    def test_delete_cookie(self):
        _cookie = self.cookie_dealer.delete_cookie("openid")
        _morsel = _cookie["openid"]
        assert _morsel["expires"]
        _value = self.cookie_dealer.get_cookie_value(_cookie, "openid")
        assert _value[0] == ""
        assert _value[2] == ""

    def test_mult_cookie(self):
        _cookie = self.cookie_dealer.create_cookie("value", "sso")
        _cookie = self.cookie_dealer.append_cookie(
            _cookie, "session", "session_state", "session"
        )
        assert len(_cookie) == 2
        _value = self.cookie_dealer.get_cookie_value(_cookie, "session")
        assert _value[0] == "session_state"
        assert _value[2] == "session"
        _value = self.cookie_dealer.get_cookie_value(_cookie, "oidc_op")
        assert _value[0] == "value"
        assert _value[2] == "sso"


class TestCookieDealerEnc(object):
    @pytest.fixture(autouse=True)
    def create_cookie_dealer(self):
        cookie_conf = {
            "enc_key": SYMKey(k="NXi6HD473d_YS4exVRn7z9z23mGmvU641MuvKqH0o7Y"),
            "default_values": {
                "name": "oidc_op",
                "domain": "127.0.0.1",
                "path": "/",
                "max_age": 3600,
            },
        }

        self.cookie_dealer = CookieDealer(**cookie_conf)

    def test_init(self):
        assert self.cookie_dealer

    def test_create_cookie(self):
        _cookie = self.cookie_dealer.create_cookie("value", "sso")
        assert _cookie

    def test_read_created_cookie(self):
        _cookie = self.cookie_dealer.create_cookie("value", "sso")
        _value = self.cookie_dealer.get_cookie_value(_cookie)
        assert len(_value) == 3
        assert _value[0] == "value"
        assert _value[2] == "sso"

    def test_delete_cookie(self):
        _cookie = self.cookie_dealer.delete_cookie("openid")
        _morsel = _cookie["openid"]
        assert _morsel["expires"]
        _value = self.cookie_dealer.get_cookie_value(_cookie, "openid")
        assert _value[0] == ""
        assert _value[2] == ""

    def test_mult_cookie(self):
        _cookie = self.cookie_dealer.create_cookie("value", "sso")
        _cookie = self.cookie_dealer.append_cookie(
            _cookie, "session", "session_state", "session"
        )
        assert len(_cookie) == 2
        _value = self.cookie_dealer.get_cookie_value(_cookie, "session")
        assert _value[0] == "session_state"
        assert _value[2] == "session"
        _value = self.cookie_dealer.get_cookie_value(_cookie, "oidc_op")
        assert _value[0] == "value"
        assert _value[2] == "sso"

    def test_mult_cookie_same_site(self):
        _cookie1 = self.cookie_dealer.create_cookie(
            "value", "sso", same_site="None", http_only=False
        )
        _cookie = self.cookie_dealer.append_cookie(
            _cookie1, "session", "session_state", "session",
        )
        assert len(_cookie) == 2
        _value = self.cookie_dealer.get_cookie_value(_cookie, "session")
        assert _value[0] == "session_state"
        assert _value[2] == "session"
        _value = self.cookie_dealer.get_cookie_value(_cookie, "oidc_op")
        assert _value[0] == "value"
        assert _value[2] == "sso"


def test_compute_session_state():
    hv = compute_session_state(
        "state", "salt", "client_id", "https://example.com/redirect"
    )
    assert hv == "d21113fbe4b54661ae45f3a3233b0f865ccc646af248274b6fa5664267540e29.salt"


def test_create_session_cookie():
    kaka = create_session_cookie(
        "sess_man", "session_state", domain="example.com", path="/"
    )

    assert isinstance(kaka, SimpleCookie)
    assert {"sess_man"} == set(kaka.keys())
    morsel = kaka["sess_man"]
    assert morsel.value == "session_state"
    assert morsel["path"] == "/"
    assert morsel["domain"] == "example.com"


def test_append_cookie():
    kaka1 = create_session_cookie(
        "sess_man", "session_state", domain="example.com", path="/"
    )
    kaka2 = create_session_cookie("foobar", "value", domain="example.com", path="/")

    kakor = append_cookie(kaka1, kaka2)
    assert {"sess_man", "foobar"} == set(kakor.keys())


conf = {
    "issuer": "https://example.com/",
    "password": "mycket hemligt",
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "verify_ssl": False,
    "endpoint": {"token": {"path": "token", "class": Token, "kwargs": {}}},
    "template_dir": "template",
    "keys": {
        "private_path": "own/jwks.json",
        "key_defs": KEYDEFS,
        "uri_path": "static/jwks.json",
    },
}

cookie_conf = {
    "sign_key": SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch"),
    "default_values": {
        "name": "oidc_op",
        "domain": "example.com",
        "path": "/",
        "max_age": 3600,
    },
}

client_id = "client_id"
client_secret = "a_longer_client_secret"
# Need to add the client_secret as a symmetric key bound to the client_id
KEYJAR.add_symmetric(client_id, client_secret, ["sig"])

endpoint_context = EndpointContext(conf, keyjar=KEYJAR)
endpoint_context.cdb[client_id] = {"client_secret": client_secret}
endpoint_context.cookie_dealer = CookieDealer(**cookie_conf)

enc_key = rndstr(32)


def test_new_cookie():
    kaka = new_cookie(
        endpoint_context, "foobar", client_id="client_id", sid="sessionID"
    )
    assert isinstance(kaka, SimpleCookie)
    assert {"foobar"} == set(kaka.keys())

    val = endpoint_context.cookie_dealer.get_cookie_value(kaka, "foobar")
    assert isinstance(val, tuple)
    b64val, ts, typ = val
    info = cookie_value(b64val)
    assert set(info.keys()) == {"client_id", "sid"}


def test_cookie_default():
    _key = SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch")
    kaka = make_cookie("test", "data", sign_key=_key)
    assert kaka["test"]["secure"] is True
    assert kaka["test"]["httponly"] is True
    assert kaka["test"]["samesite"] is ""


def test_cookie_http_only_false():
    _key = SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch")
    kaka = make_cookie("test", "data", sign_key=_key, http_only=False)
    assert kaka["test"]["secure"] is True
    assert kaka["test"]["httponly"] is False
    assert kaka["test"]["samesite"] is ""


def test_cookie_not_secure():
    _key = SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch")
    kaka = make_cookie("test", "data", _key, secure=False)
    assert kaka["test"]["secure"] is False
    assert kaka["test"]["httponly"] is True
    assert kaka["test"]["samesite"] is ""


def test_cookie_same_site_none():
    _key = SYMKey(k="ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch")
    kaka = make_cookie("test", "data", sign_key=_key, same_site="None")
    assert kaka["test"]["secure"] is True
    assert kaka["test"]["httponly"] is True
    assert kaka["test"]["samesite"] is "None"


def test_cookie_enc():
    _key = SYMKey(k=enc_key)
    _enc_data = sign_enc_payload(json.dumps({"test": "data"}), timestamp=time.time(), enc_key=_key)
    _data, _timestamp = ver_dec_content(_enc_data.split('|'), enc_key=_key)
    assert json.loads(_data) == {"test": "data"}
