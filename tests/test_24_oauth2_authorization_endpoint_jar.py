import io
import json
import os
from http.cookies import SimpleCookie

import pytest
import responses
import yaml
from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jwt import utc_time_sans_frac
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import JWTSecuredAuthorizationRequest
from oidcmsg.server.configure import ASConfiguration
from oidcmsg.server.user_info import UserInfo
from oidcmsg.time_util import in_a_while

from oidcop.cookie_handler import CookieHandler
from oidcop.oauth2.authorization import Authorization
from oidcop.server import Server

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]}
    # {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

RESPONSE_TYPES_SUPPORTED = [["code"], ["token"], ["code", "token"], ["none"]]

CAPABILITIES = {
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ]
}

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

AUTH_REQ_DICT = AUTH_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_db = json.loads(open(full_path("users.json")).read())


class SimpleCookieDealer(object):
    def __init__(self, name=""):
        self.name = name

    def create_cookie(self, value, typ, **kwargs):
        cookie = SimpleCookie()
        timestamp = str(utc_time_sans_frac())

        _payload = "::".join([value, timestamp, typ])

        bytes_load = _payload.encode("utf-8")
        bytes_timestamp = timestamp.encode("utf-8")

        cookie_payload = [bytes_load, bytes_timestamp]
        cookie[self.name] = (b"|".join(cookie_payload)).decode("utf-8")
        try:
            ttl = kwargs["ttl"]
        except KeyError:
            pass
        else:
            cookie[self.name]["expires"] = in_a_while(seconds=ttl)

        return cookie

    @staticmethod
    def get_cookie_value(cookie=None, name=None):
        if cookie is None or name is None:
            return None
        else:
            try:
                info, timestamp = cookie[name].split("|")
            except (TypeError, AssertionError):
                return None
            else:
                value = info.split("::")
                if timestamp == value[1]:
                    return value
        return None


client_yaml = """
clients:
  client_1:
    "client_secret": 'hemligtkodord'
    "redirect_uris": 
        - ['https://example.com/cb', '']
    "client_salt": "salted"
    'token_endpoint_auth_method': 'client_secret_post'
    'response_types': 
        - 'code'
        - 'token'
  client2:
    client_secret: "spraket"
    redirect_uris:
      - ['https://app1.example.net/foo', '']
      - ['https://app2.example.net/bar', '']
    response_types:
      - code
"""


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt zebra",
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
            "endpoint": {
                "authorization": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {
                        "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
                        "response_modes_supported": ["query", "fragment", "form_post"],
                        "claims_parameter_supported": True,
                        "request_parameter_supported": True,
                        "request_uri_parameter_supported": True,
                        "request_cls": JWTSecuredAuthorizationRequest,
                    },
                }
            },
            "authentication": {
                "anon": {
                    "acr": "http://www.swamid.se/policy/assurance/al1",
                    "class": "oidcmsg.server.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_db}},
            "template_dir": "template",
            "cookie_handler": {
                "class": CookieHandler,
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
        server = Server(ASConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
        endpoint_context = server.endpoint_context
        _clients = yaml.safe_load(io.StringIO(client_yaml))
        endpoint_context.cdb = _clients["clients"]
        endpoint_context.keyjar.import_jwks(
            endpoint_context.keyjar.export_jwks(True, ""), conf["issuer"]
        )
        self.endpoint = server.server_get("endpoint", "authorization")
        self.session_manager = endpoint_context.session_manager
        self.user_id = "diana"

        self.rp_keyjar = KeyJar()
        self.rp_keyjar.add_symmetric("client_1", "hemligtkodord1234567890")
        endpoint_context.keyjar.add_symmetric("client_1", "hemligtkodord1234567890")

    def test_parse_request_parameter(self):
        _jwt = JWT(key_jar=self.rp_keyjar, iss="client_1", sign_alg="HS256")
        _jws = _jwt.pack(
            AUTH_REQ_DICT, aud=self.endpoint.server_get("endpoint_context").provider_info["issuer"],
        )
        # -----------------
        _req = self.endpoint.parse_request(
            {
                "request": _jws,
                "redirect_uri": AUTH_REQ.get("redirect_uri"),
                "response_type": AUTH_REQ.get("response_type"),
                "client_id": AUTH_REQ.get("client_id"),
                "scope": AUTH_REQ.get("scope"),
            }
        )
        assert "__verified_request" in _req

    def test_parse_request_uri(self):
        _jwt = JWT(key_jar=self.rp_keyjar, iss="client_1", sign_alg="HS256")
        _jws = _jwt.pack(
            AUTH_REQ_DICT, aud=self.endpoint.server_get("endpoint_context").provider_info["issuer"],
        )

        request_uri = "https://client.example.com/req"
        # -----------------
        with responses.RequestsMock() as rsps:
            rsps.add("GET", request_uri, body=_jws, status=200)
            _req = self.endpoint.parse_request(
                {
                    "request_uri": request_uri,
                    "redirect_uri": AUTH_REQ.get("redirect_uri"),
                    "response_type": AUTH_REQ.get("response_type"),
                    "client_id": AUTH_REQ.get("client_id"),
                    "scope": AUTH_REQ.get("scope"),
                }
            )

        assert "__verified_request" in _req
