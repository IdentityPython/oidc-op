import io
import json
import os

from oidcop.configure import ASConfiguration
import pytest
import responses
import yaml
from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jwt import utc_time_sans_frac
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import JWTSecuredAuthorizationRequest
from oidcmsg.time_util import in_a_while

from oidcop.oauth2.authorization import Authorization
from oidcop.server import Server
from oidcop.user_info import UserInfo

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
                    "class": "oidcop.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_db}},
            "template_dir": "template",
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
