# -*- coding: latin-1 -*-
import json
import os

from oidcop.configure import OPConfiguration
import pytest
from oidcmsg.oidc import RegistrationRequest

from oidcop.cookie_handler import CookieHandler
from oidcop.oidc.authorization import Authorization
from oidcop.oidc.read_registration import RegistrationRead
from oidcop.oidc.registration import Registration
from oidcop.oidc.token import Token
from oidcop.oidc.userinfo import UserInfo
from oidcop.server import Server

BASEDIR = os.path.abspath(os.path.dirname(__file__))

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

COOKIE_KEY_DEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]},
]

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
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ],
}

msg = {
    "application_type": "web",
    "redirect_uris": [
        "https://client.example.org/callback",
        "https://client.example.org/callback2",
    ],
    "client_name": "My Example",
    "client_name#ja-Jpan-JP": "クライアント名",
    "subject_type": "pairwise",
    "token_endpoint_auth_method": "client_secret_basic",
    "jwks_uri": "https://client.example.org/my_public_keys.jwks",
    "userinfo_encrypted_response_alg": "RSA-OAEP",
    "userinfo_encrypted_response_enc": "A128CBC-HS256",
    "contacts": ["ve7jtb@example.org", "mary@example.org"],
    "request_uris": [
        "https://client.example.org/rf.txt#qpXaRLh_n93TT",
        "https://client.example.org/rf.txt",
    ],
    "post_logout_redirect_uris": [
        "https://rp.example.com/pl?foo=bar",
        "https://rp.example.com/pl",
    ],
}

CLI_REQ = RegistrationRequest(**msg)


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": "https://example.com/",
            "httpc_params": {"verify": False, "timeout": 1},
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "capabilities": CAPABILITIES,
            "keys": {"key_defs": KEYDEFS, "uri_path": "static/jwks.json"},
            "cookie_handler": {
                "class": CookieHandler,
                "kwargs": {"keys": {"key_defs": COOKIE_KEY_DEFS}},
            },
            "endpoint": {
                "registration": {
                    "path": "registration",
                    "class": Registration,
                    "kwargs": {"client_auth_method": None},
                },
                "registration_api": {
                    "path": "registration_api",
                    "class": RegistrationRead,
                    "kwargs": {"client_authn_method": ["bearer_header"]},
                },
                "authorization": {"path": "authorization", "class": Authorization, "kwargs": {},},
                "token": {
                    "path": "token",
                    "class": Token,
                    "kwargs": {
                        "client_authn_method": [
                            "client_secret_post",
                            "client_secret_basic",
                            "client_secret_jwt",
                            "private_key_jwt",
                        ]
                    },
                },
                "userinfo": {"path": "userinfo", "class": UserInfo, "kwargs": {}},
            },
            "template_dir": "template",
        }
        server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
        self.registration_endpoint = server.server_get("endpoint", "registration")
        self.registration_api_endpoint = server.server_get("endpoint", "registration_read")

    def test_do_response(self):
        _req = self.registration_endpoint.parse_request(CLI_REQ.to_json())
        _resp = self.registration_endpoint.process_request(request=_req)
        msg = self.registration_endpoint.do_response(**_resp)
        assert isinstance(msg, dict)
        _msg = json.loads(msg["response"])
        assert _msg

        http_info = {
            "headers": {
                "authorization": "Bearer {}".format(
                    _resp["response_args"]["registration_access_token"]
                )
            }
        }

        _api_req = self.registration_api_endpoint.parse_request(
            "client_id={}".format(_resp["response_args"]["client_id"]), http_info=http_info,
        )
        assert set(_api_req.keys()) == {"client_id"}

        _info = self.registration_api_endpoint.process_request(request=_api_req)
        assert set(_info.keys()) == {"response_args"}
        assert _info["response_args"] == _resp["response_args"]

        _endp_response = self.registration_api_endpoint.do_response(_info)
        assert set(_endp_response.keys()) == {"response", "http_headers"}
        assert ("Content-type", "application/json; charset=utf-8") in _endp_response["http_headers"]
