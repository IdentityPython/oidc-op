import os

from oidcop.endpoint_context import init_service
from oidcop.endpoint_context import init_user_info
from oidcop.login_hint import LoginHint2Acrs

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


def test_login_hint():
    userinfo = init_user_info(
        {
            "class": "oidcop.user_info.UserInfo",
            "kwargs": {"db_file": full_path("users.json")},
        },
        "",
    )
    login_hint_lookup = init_service(
        {"class": "oidcop.login_hint.LoginHintLookup"}, None
    )
    login_hint_lookup.userinfo = userinfo

    assert login_hint_lookup("tel:0907865000") == "diana"


def test_login_hint2acrs():
    l2a = LoginHint2Acrs({"tel": ["http://www.swamid.se/policy/assurance/al1"]})

    assert l2a("tel:+467865000") == ["http://www.swamid.se/policy/assurance/al1"]
