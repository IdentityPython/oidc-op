from oidcmsg.time_util import utc_time_sans_frac

from oidcop.session.token import AccessToken
from oidcop.session.token import AuthorizationCode
from oidcop.session.token import IDToken


def test_authorization_code_default():
    code = AuthorizationCode(value="ABCD")
    assert code.usage_rules["max_usage"] == 1
    assert code.usage_rules["supports_minting"] == [
        "access_token",
        "refresh_token",
        "id_token",
    ]


def test_authorization_code_usage():
    code = AuthorizationCode(
        value="ABCD", usage_rules={"supports_minting": ["access_token"], "max_usage": 1}
    )

    assert code.usage_rules["max_usage"] == 1
    assert code.usage_rules["supports_minting"] == ["access_token"]


def test_authorization_code_extras():
    code = AuthorizationCode(
        value="ABCD",
        scope=["openid", "foo", "bar"],
        claims={"userinfo": {"given_name": None}},
        resources=["https://api.example.com"],
    )

    assert code.scope == ["openid", "foo", "bar"]
    assert code.claims == {"userinfo": {"given_name": None}}
    assert code.resources == ["https://api.example.com"]


def test_dump_load(
    cls=AuthorizationCode,
    kwargs=dict(
        value="ABCD",
        scope=["openid", "foo", "bar"],
        claims={"userinfo": {"given_name": None}},
        resources=["https://api.example.com"],
    ),
):
    code = cls(**kwargs)

    _item = code.dump()
    _new_code = cls().load(_item)
    for attr in cls.parameter.keys():
        val = getattr(code, attr)
        if val:
            assert val == getattr(_new_code, attr)


def test_dump_load_access_token():
    test_dump_load(cls=AccessToken, kwargs={})


def test_dump_load_idtoken():
    test_dump_load(cls=IDToken, kwargs={})


def test_supports_minting():
    code = AuthorizationCode(value="ABCD")
    assert code.supports_minting("access_token")
    assert code.supports_minting("refresh_token")
    assert code.supports_minting("authorization_code") is False


def test_usage():
    token = AccessToken(usage_rules={"max_usage": 2})

    token.register_usage()
    assert token.has_been_used()
    assert token.used == 1
    assert token.max_usage_reached() is False

    token.register_usage()
    assert token.max_usage_reached()

    token.register_usage()
    assert token.used == 3
    assert token.max_usage_reached()


def test_is_active_usage():
    token = AccessToken(usage_rules={"max_usage": 2})

    token.register_usage()
    token.register_usage()
    assert token.is_active() is False


def test_is_active_revoke():
    token = AccessToken(usage_rules={"max_usage": 2})
    token.revoke()
    assert token.is_active() is False


def test_is_active_expired():
    token = AccessToken(usage_rules={"max_usage": 2})
    token.expires_at = utc_time_sans_frac() - 60
    assert token.is_active() is False
