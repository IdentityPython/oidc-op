from cryptojwt.key_jar import build_keyjar
import pytest

from oidcop.endpoint_context import EndpointContext
from oidcop.server import Server
from oidcop.session import session_key
from oidcop.session.grant import Grant
from oidcop.session.grant import TOKEN_MAP
from oidcop.session.grant import find_token
from oidcop.session.grant import get_usage_rules
from oidcop.session.token import AuthorizationCode
from oidcop.session.token import SessionToken
from oidcop.token import DefaultToken
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

KEYJAR = build_keyjar(KEYDEFS)

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
        "token_endpoint": {
            "path": "token",
            "class": "oidcop.oidc.token.Token",
            "kwargs": {}
        },
    },
    "authentication": {
        "anon": {
            "acr": INTERNETPROTOCOLPASSWORD,
            "class": "oidcop.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
}

SERVER = Server(conf=conf)
ENDPOINT_CONTEXT = SERVER.server_get("endpoint_context")


def test_access_code():
    token = AuthorizationCode('authorization_code', value="ABCD")
    assert token.issued_at
    assert token.type == "authorization_code"
    assert token.value == "ABCD"

    token.register_usage()
    #  max_usage == 1
    assert token.max_usage_reached() is True


def test_access_token():
    code = AuthorizationCode('authorization_code', value="ABCD")
    token = SessionToken('access_token', value="1234", based_on=code.id, usage_rules={"max_usage": 2})
    assert token.issued_at
    assert token.type == "access_token"
    assert token.value == "1234"

    token.register_usage()
    #  max_usage - undefined
    assert token.max_usage_reached() is False

    token.register_usage()
    assert token.max_usage_reached() is True

    t = find_token([code, token], token.based_on)
    assert t.value == "ABCD"

    token.revoked = True
    assert token.revoked is True


TOKEN_HANDLER = {
    "authorization_code": DefaultToken("authorization_code", typ="A"),
    "access_token": DefaultToken("access_token", typ="T"),
    "refresh_token": DefaultToken("refresh_token", typ="R")
}


def test_mint_token():
    grant = Grant()

    code = grant.mint_token("user_id;;client_id;;grant_id",
                            endpoint_context=ENDPOINT_CONTEXT,
                            token_type="authorization_code",
                            token_handler=TOKEN_HANDLER["authorization_code"])

    access_token = grant.mint_token(
        "user_id;;client_id;;grant_id",
        endpoint_context=ENDPOINT_CONTEXT,
        token_type="access_token",
        token_handler=TOKEN_HANDLER["access_token"],
        based_on=code,
        scope=["openid", "foo", "bar"]
    )

    assert access_token.scope == ["openid", "foo", "bar"]


SESSION_ID = session_key('user_id', 'client_id', 'grant.id')


def test_grant():
    grant = Grant()
    code = grant.mint_token(SESSION_ID, endpoint_context=ENDPOINT_CONTEXT,
                            token_type="authorization_code",
                            token_handler=TOKEN_HANDLER["authorization_code"])

    access_token = grant.mint_token(
        SESSION_ID,
        endpoint_context=ENDPOINT_CONTEXT,
        token_type="access_token",
        token_handler=TOKEN_HANDLER["access_token"],
        based_on=code)

    refresh_token = grant.mint_token(
        SESSION_ID,
        endpoint_context=ENDPOINT_CONTEXT,
        token_type="refresh_token",
        token_handler=TOKEN_HANDLER["refresh_token"],
        based_on=code)

    grant.revoke_token()
    assert code.revoked is True
    assert access_token.revoked is True
    assert refresh_token.revoked is True


def test_get_token():
    grant = Grant()
    code = grant.mint_token(SESSION_ID, endpoint_context=ENDPOINT_CONTEXT,
                            token_type="authorization_code",
                            token_handler=TOKEN_HANDLER["authorization_code"])

    access_token = grant.mint_token(
        SESSION_ID,
        endpoint_context=ENDPOINT_CONTEXT,
        token_type="access_token",
        token_handler=TOKEN_HANDLER["access_token"],
        based_on=code,
        scope=["openid", "foo", "bar"]
    )

    _code = grant.get_token(code.value)
    assert _code.id == code.id

    _token = grant.get_token(access_token.value)
    assert _token.id == access_token.id
    assert set(_token.scope) == {"openid", "foo", "bar"}


def test_grant_revoked_based_on():
    grant = Grant()
    code = grant.mint_token(SESSION_ID,
                            endpoint_context=ENDPOINT_CONTEXT,
                            token_type="authorization_code",
                            token_handler=TOKEN_HANDLER["authorization_code"])

    access_token = grant.mint_token(
        SESSION_ID,
        endpoint_context=ENDPOINT_CONTEXT,
        token_type="access_token",
        token_handler=TOKEN_HANDLER["access_token"],
        based_on=code)

    refresh_token = grant.mint_token(
        SESSION_ID,
        endpoint_context=ENDPOINT_CONTEXT,
        token_type="refresh_token",
        token_handler=TOKEN_HANDLER["refresh_token"],
        based_on=code)

    code.register_usage()
    if code.max_usage_reached():
        grant.revoke_token(based_on=code.value)

    assert code.is_active() is False
    assert access_token.is_active() is False
    assert refresh_token.is_active() is False


def test_revoke():
    grant = Grant()
    code = grant.mint_token(SESSION_ID,
                            endpoint_context=ENDPOINT_CONTEXT,
                            token_type="authorization_code",
                            token_handler=TOKEN_HANDLER["authorization_code"])

    access_token = grant.mint_token(
        SESSION_ID,
        endpoint_context=ENDPOINT_CONTEXT,
        token_type="access_token",
        token_handler=TOKEN_HANDLER["access_token"],
        based_on=code)

    grant.revoke_token(based_on=code.value)

    assert code.is_active() is True
    assert access_token.is_active() is False

    access_token_2 = grant.mint_token(
        SESSION_ID,
        endpoint_context=ENDPOINT_CONTEXT,
        token_type="access_token",
        token_handler=TOKEN_HANDLER["access_token"],
        based_on=code)

    grant.revoke_token(value=code.value, recursive=True)

    assert code.is_active() is False
    assert access_token_2.is_active() is False


def test_json_conversion():
    grant = Grant()
    code = grant.mint_token(SESSION_ID,
                            endpoint_context=ENDPOINT_CONTEXT,
                            token_type="authorization_code",
                            token_handler=TOKEN_HANDLER["authorization_code"])

    grant.mint_token(
        SESSION_ID,
        endpoint_context=ENDPOINT_CONTEXT,
        token_type="access_token",
        token_handler=TOKEN_HANDLER["access_token"],
        based_on=code)

    _item = grant.dump()

    _grant_copy = Grant().load(_item)

    assert len(_grant_copy.issued_token) == 2

    tt = {"code": 0, "access_token": 0}
    for token in _grant_copy.issued_token:
        if token.type == "authorization_code":
            tt["code"] += 1
        if token.type == "access_token":
            tt["access_token"] += 1

    assert tt == {"code": 1, "access_token": 1}


def test_json_no_token_map():
    grant = Grant(token_map={})
    with pytest.raises(ValueError):
        grant.mint_token(SESSION_ID,
                         endpoint_context=ENDPOINT_CONTEXT,
                         token_type="authorization_code",
                         token_handler=TOKEN_HANDLER["authorization_code"])


class MyToken(SessionToken):
    pass


TOKEN_HANDLER["my_token"] = DefaultToken("my_token", typ="M")


def test_json_custom_token_map():
    token_map = TOKEN_MAP.copy()
    token_map["my_token"] = MyToken

    grant = Grant(token_map=token_map)
    code = grant.mint_token(SESSION_ID,
                            endpoint_context=ENDPOINT_CONTEXT,
                            token_type="authorization_code",
                            token_handler=TOKEN_HANDLER["authorization_code"])

    grant.mint_token(
        SESSION_ID,
        endpoint_context=ENDPOINT_CONTEXT,
        token_type="access_token",
        token_handler=TOKEN_HANDLER["access_token"],
        based_on=code)

    grant.mint_token(
        SESSION_ID,
        endpoint_context=ENDPOINT_CONTEXT,
        token_type="my_token",
        token_handler=TOKEN_HANDLER["my_token"])

    _jstr = grant.dump()

    _grant_copy = Grant().load(_jstr)

    assert len(_grant_copy.issued_token) == 3

    tt = {k: 0 for k, v in grant.token_map.items()}

    for token in _grant_copy.issued_token:
        for _type in tt.keys():
            if token.type == _type:
                tt[_type] += 1

    assert tt == {
        'access_token': 1, 'authorization_code': 1,
        'my_token': 1, 'refresh_token': 0
    }


def test_get_spec():
    grant = Grant(scope=["openid", "email", "address"],
                  claims={"userinfo": {"given_name": None, "email": None}},
                  resources=["https://api.example.com"]
                  )

    code = grant.mint_token(SESSION_ID,
                            endpoint_context=ENDPOINT_CONTEXT,
                            token_type="authorization_code",
                            token_handler=TOKEN_HANDLER["authorization_code"])

    access_token = grant.mint_token(
        SESSION_ID,
        endpoint_context=ENDPOINT_CONTEXT,
        token_type="access_token",
        token_handler=TOKEN_HANDLER["access_token"],
        based_on=code,
        scope=["openid", "email", "eduperson"],
        claims={
            "userinfo": {
                "given_name": None,
                "eduperson_affiliation": None
            }
        }
    )

    spec = grant.get_spec(access_token)
    assert set(spec.keys()) == {"scope", "claims", "resources"}
    assert spec["scope"] == ["openid", "email", "eduperson"]
    assert spec["claims"] == {
        "userinfo": {
            "given_name": None,
            "eduperson_affiliation": None
        }
    }
    assert spec["resources"] == ["https://api.example.com"]


def test_get_usage_rules():
    grant = Grant(scope=["openid", "email", "address"],
                  claims={"userinfo": {"given_name": None, "email": None}},
                  resources=["https://api.example.com"]
                  )

    # Default usage rules
    ENDPOINT_CONTEXT.cdb["client_id"] = {}
    rules = get_usage_rules("access_token", ENDPOINT_CONTEXT, grant, "client_id")
    assert rules == {'supports_minting': [], 'expires_in': 3600}

    # client specific usage rules
    ENDPOINT_CONTEXT.cdb["client_id"] = {"access_token": {"expires_in": 600}}