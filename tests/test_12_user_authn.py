import base64
import os

import pytest

from oidcop.configure import OPConfiguration
from oidcop.server import Server
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcop.user_authn.authn_context import UNSPECIFIED
from oidcop.user_authn.user import BasicAuthn
from oidcop.user_authn.user import NoAuthn
from oidcop.user_authn.user import SymKeyAuthn
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
            "httpc_params": {"verify": False, "timeout": 1},
            "grant_expires_in": 300,
            "endpoint": {
                "authorization": {
                    "path": "{}/authorization",
                    "class": 'oidcop.oidc.authorization.Authorization',
                    "kwargs": {},
                }
            },
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
                            "kwargs": {"filename": full_path("passwd.json")},
                        },
                        "page_header": "Testing log in",
                        "submit_btn": "Get me in!",
                        "user_label": "Nickname",
                        "passwd_label": "Secret sauce",
                    },
                },
                "anon": {"acr": UNSPECIFIED, "class": NoAuthn, "kwargs": {"user": "diana"}, },
            },
            "template_dir": "templates",
            "cookie_handler": {
                "class": "oidcop.cookie_handler.CookieHandler",
                "kwargs": {
                    "sign_key": "ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch",
                    "name": {
                        "session": "oidc_op",
                        "register": "oidc_op_reg",
                        "session_management": "oidc_op_sman",
                    },
                },
            },
        }
        self.server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
        self.endpoint_context = self.server.endpoint_context

    def test_authenticated_as_without_cookie(self):
        authn_item = self.endpoint_context.authn_broker.pick(INTERNETPROTOCOLPASSWORD)
        method = authn_item[0]["method"]

        _info, _time_stamp = method.authenticated_as(None)
        assert _info is None

    def test_authenticated_as_with_cookie(self):
        authn_item = self.endpoint_context.authn_broker.pick(INTERNETPROTOCOLPASSWORD)
        method = authn_item[0]["method"]

        authn_req = {"state": "state_identifier", "client_id": "client 12345"}
        _cookie = self.endpoint_context.new_cookie(
            name=self.endpoint_context.cookie_handler.name["session"],
            sub="diana",
            sid=self.endpoint_context.session_manager.encrypted_session_id(
                "diana", "client 12345", "abcdefgh"
            ),
            state=authn_req["state"],
            client_id=authn_req["client_id"],
        )

        _info, _time_stamp = method.authenticated_as("client 12345", [_cookie])
        assert set(_info.keys()) == {'sub', 'uid', 'state', 'grant_id', 'timestamp', 'sid',
                                     'client_id'}
        assert _info["sub"] == "diana"

    def test_userpassjinja2(self):
        db = {
            "class": JSONDictDB,
            "kwargs": {"filename": full_path("passwd.json")},
        }
        template_handler = self.endpoint_context.template_handler
        res = UserPassJinja2(db, template_handler,
                             server_get=self.server.server_get)
        res()
        assert "page_header" in res.kwargs

    def test_basic_auth(self):
        basic_auth = base64.b64encode(b"diana:krall").decode()
        ba = BasicAuthn(pwd={"diana": "krall"}, server_get=self.server.server_get)
        ba.authenticated_as(client_id="", authorization=f"Basic {basic_auth}")

    def test_no_auth(self):
        basic_auth = base64.b64encode(
            b"D\xfd\x8a\x85\xa6\xd1\x16\xe4\\6\x1e\x9ds~\xc3\t\x95\x99\x83\x91\x1f\xfb:iviviviv"
        )
        ba = SymKeyAuthn(symkey=b"0" * 32, ttl=600, server_get=self.server.server_get)
        ba.authenticated_as(client_id="", authorization=basic_auth)
