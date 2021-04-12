import os

import pytest

from oidcop.cookie import cookie_value
from oidcop.cookie import new_cookie
from oidcop.endpoint_context import EndpointContext
from oidcop.server import Server
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcop.user_authn.authn_context import UNSPECIFIED
from oidcop.user_authn.user import NoAuthn
from oidcop.user_authn.user import UserPassJinja2
from oidcop.util import JSONDictDB

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


class TestUserAuthn(object):
    @pytest.fixture(autouse=True)
    def create_endpoint_context(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "grant_expires_in": 300,
            "verify_ssl": False,
            "endpoint": {},
            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
            "authentication": {
                "user": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": UserPassJinja2,
                    "verify_endpoint": "verify/user",
                    "kwargs": {
                        "template": "user_pass.jinja2",
                        "sym_key": "24AA/LR6HighEnergy",
                        "db": {
                            "class": JSONDictDB,
                            "kwargs": {"json_path": full_path("passwd.json")},
                        },
                        "page_header": "Testing log in",
                        "submit_btn": "Get me in!",
                        "user_label": "Nickname",
                        "passwd_label": "Secret sauce",
                    },
                },
                "anon": {
                    "acr": UNSPECIFIED,
                    "class": NoAuthn,
                    "kwargs": {"user": "diana"},
                },
            },
            "cookie_dealer": {
                "class": "oidcop.cookie.CookieDealer",
                "kwargs": {
                    "sign_key": "ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch",
                    "default_values": {
                        "name": "oidc_xx",
                        "domain": "example.com",
                        "path": "/",
                        "max_age": 3600,
                    },
                },
            },
            "template_dir": "template",
        }
        server = Server(conf)
        self.endpoint_context = server.endpoint_context

    def test_authenticated_as_without_cookie(self):
        authn_item = self.endpoint_context.authn_broker.pick(INTERNETPROTOCOLPASSWORD)
        method = authn_item[0]["method"]

        _info, _time_stamp = method.authenticated_as(None)
        assert _info is None

    def test_authenticated_as_with_cookie(self):
        authn_item = self.endpoint_context.authn_broker.pick(INTERNETPROTOCOLPASSWORD)
        method = authn_item[0]["method"]

        authn_req = {"state": "state_identifier", "client_id": "client 12345"}
        _cookie = new_cookie(
            self.endpoint_context,
            sub="diana",
            sid="session_identifier",
            state=authn_req["state"],
            client_id=authn_req["client_id"],
            cookie_name=self.endpoint_context.cookie_name["session"],
        )

        _info, _time_stamp = method.authenticated_as(_cookie)
        _info = cookie_value(_info["uid"])
        assert _info["sub"] == "diana"
