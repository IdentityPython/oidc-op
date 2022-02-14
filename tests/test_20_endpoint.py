import json
import os
from urllib.parse import urlparse

from oidcop.configure import OPConfiguration
import pytest
from oidcmsg.message import Message

from oidcop.endpoint import Endpoint
from oidcop.server import Server
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD

BASEDIR = os.path.abspath(os.path.dirname(__file__))

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

REQ = Message(foo="bar", hej="hopp", client_id="client_id")

EXAMPLE_MSG = {
    "name": "Jane Doe",
    "given_name": "Jane",
    "family_name": "Doe",
    # "email": "janedoe@example.com",
    # "picture": "http://example.com/janedoe/me.jpg",
}


def pre(args, request, endpoint_context):
    args.update({"name": "{}, {}".format(args["family_name"], args["given_name"])})
    return args


def post(cis, request, endpoint_context):
    cis["request"] = request
    return cis


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": "https://example.com/",
            "httpc_params": {"verify": False, "timeout": 1},
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "endpoint": {"endpoint": {"path": "endpoint", "class": Endpoint, "kwargs": {}},},
            "keys": {
                "public_path": "jwks.json",
                "key_defs": KEYDEFS,
                "private_path": "own/jwks.json",
                "uri_path": "static/jwks.json",
            },
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "oidcop.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
        }
        server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)

        server.endpoint_context.cdb["client_id"] = {}
        self.endpoint_context = server.endpoint_context
        self.endpoint = server.server_get("endpoint", "")

    def test_parse_urlencoded(self):
        self.endpoint.request_format = "urlencoded"
        request = REQ.to_urlencoded()
        req = self.endpoint.parse_request(request, http_info={})
        assert req == REQ

    def test_parse_url(self):
        self.endpoint.request_format = "url"
        request = "{}?{}".format(self.endpoint_context.issuer, REQ.to_urlencoded())
        req = self.endpoint.parse_request(request, http_info={})
        assert req == REQ

    def test_parse_json(self):
        self.endpoint.request_format = "json"
        request = REQ.to_json()
        req = self.endpoint.parse_request(request)
        assert req == REQ

    def test_parse_dict(self):
        # Doesn't matter what request_format is defined
        self.endpoint.request_format = "json"
        request = REQ.to_dict()
        req = self.endpoint.parse_request(request)
        assert req == REQ

    def test_parse_jwt(self):
        self.endpoint.request_format = "jwt"
        kj = self.endpoint_context.keyjar
        request = REQ.to_jwt(kj.get_signing_key("RSA"), "RS256")
        req = self.endpoint.parse_request(request)
        assert req == REQ

    def test_construct(self):
        msg = self.endpoint.construct(EXAMPLE_MSG, {})
        assert set(msg.keys()) == set(EXAMPLE_MSG.keys())

    def test_pre_construct(self):
        self.endpoint.pre_construct.append(pre)
        msg = self.endpoint.construct(EXAMPLE_MSG, {})
        assert msg["name"] == "Doe, Jane"

    def test_post_construct(self):
        self.endpoint.post_construct.append(post)
        msg = self.endpoint.construct(EXAMPLE_MSG, {})
        assert "request" in msg

    def test_do_response_body_json(self):
        self.endpoint.response_placement = "body"
        self.endpoint.response_format = "json"
        msg = self.endpoint.do_response(EXAMPLE_MSG)

        assert isinstance(msg, dict)
        jmsg = json.loads(msg["response"])
        assert set(jmsg.keys()) == set(EXAMPLE_MSG.keys())

    def test_do_response_body_urlencoded(self):
        self.endpoint.response_placement = "body"
        self.endpoint.response_format = "urlencoded"
        msg = self.endpoint.do_response(EXAMPLE_MSG)

        assert isinstance(msg, dict)
        umsg = Message().from_urlencoded(msg["response"])
        assert set(umsg.keys()) == set(EXAMPLE_MSG.keys())

    def test_do_response_url_query(self):
        self.endpoint.response_placement = "url"
        self.endpoint.response_format = "urlencoded"
        msg = self.endpoint.do_response(
            EXAMPLE_MSG, fragment_enc=False, return_uri="https://example.org/cb"
        )

        assert isinstance(msg, dict)
        parse_res = urlparse(msg["response"])
        assert parse_res.scheme == "https"
        assert parse_res.netloc == "example.org"
        assert parse_res.path == "/cb"
        umsg = Message().from_urlencoded(parse_res.query)
        assert set(umsg.keys()) == set(EXAMPLE_MSG.keys())

    def test_do_response_url_fragment(self):
        self.endpoint.response_placement = "url"
        self.endpoint.response_format = "urlencoded"
        msg = self.endpoint.do_response(
            EXAMPLE_MSG, fragment_enc=True, return_uri="https://example.org/cb_i"
        )

        assert isinstance(msg, dict)
        parse_res = urlparse(msg["response"])
        assert parse_res.scheme == "https"
        assert parse_res.netloc == "example.org"
        assert parse_res.path == "/cb_i"
        umsg = Message().from_urlencoded(parse_res.fragment)
        assert set(umsg.keys()) == set(EXAMPLE_MSG.keys())

    def test_do_response_response_msg_1(self):
        info = self.endpoint.do_response(EXAMPLE_MSG, response_msg="{foo=bar}")
        assert info["response"] == "{foo=bar}"
        assert ("Content-type", "application/json") in info["http_headers"]

        self.endpoint.response_format = "jws"
        info = self.endpoint.do_response(EXAMPLE_MSG, response_msg="header.payload.sign")

        assert info["response"] == "header.payload.sign"
        assert ("Content-type", "application/jose") in info["http_headers"]

        self.endpoint.response_format = ""
        info = self.endpoint.do_response(EXAMPLE_MSG, response_msg="foo=bar")

        assert info["response"] == "foo=bar"
        assert ("Content-type", "application/x-www-form-urlencoded") in info["http_headers"]

        info = self.endpoint.do_response(
            EXAMPLE_MSG, response_msg="{foo=bar}", content_type="application/json"
        )
        assert info["response"] == "{foo=bar}"
        assert ("Content-type", "application/json") in info["http_headers"]

        info = self.endpoint.do_response(
            EXAMPLE_MSG, response_msg="header.payload.sign", content_type="application/jose",
        )
        assert info["response"] == "header.payload.sign"
        assert ("Content-type", "application/jose") in info["http_headers"]

    def test_do_response_placement_body(self):
        self.endpoint.response_placement = "body"
        info = self.endpoint.do_response(EXAMPLE_MSG)
        assert ("Content-type", "application/json; charset=utf-8") in info["http_headers"]
        assert (
            info["response"] == '{"name": "Doe, Jane", "given_name": "Jane", "family_name": "Doe"}'
        )

    def test_do_response_placement_url(self):
        self.endpoint.response_placement = "url"
        info = self.endpoint.do_response(EXAMPLE_MSG, return_uri="https://example.org/cb")
        assert ("Content-type", "application/x-www-form-urlencoded") in info["http_headers"]
        assert (
            info["response"]
            == "https://example.org/cb?name=Doe%2C+Jane&given_name=Jane&family_name=Doe"
        )

        info = self.endpoint.do_response(
            EXAMPLE_MSG, return_uri="https://example.org/cb", fragment_enc=True
        )
        assert ("Content-type", "application/x-www-form-urlencoded") in info["http_headers"]
        assert (
            info["response"]
            == "https://example.org/cb#name=Doe%2C+Jane&given_name=Jane&family_name=Doe"
        )

    def test_do_response_error(self):
        info = self.endpoint.do_response(
            error="invalid_request", error_description="Missing required attribute"
        )

        assert (
            info["response"]
            == '{"error": "invalid_request", "error_description": "Missing required attribute"}'
        )
