import json

import pytest

from oidcop.oidc.discovery import Discovery
from oidcop.server import Server
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "endpoint": {
                "webfinger": {
                    "path": ".well-known/webfinger",
                    "class": Discovery,
                    "kwargs": {"client_authn_method": None},
                }
            },
            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "oidcop.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
        }
        server = Server(conf)
        self.endpoint = server.server_get("endpoint", "discovery")

    def test_do_response(self):
        args = self.endpoint.process_request({"resource": "acct:foo@example.com"})
        msg = self.endpoint.do_response(**args)
        _resp = json.loads(msg["response"])
        assert _resp == {
            "subject": "acct:foo@example.com",
            "links": [
                {
                    "href": "https://example.com/",
                    "rel": "http://openid.net/specs/connect/1.0/issuer",
                }
            ],
        }
