import io
import json
import os

from oidcop.configure import OPConfiguration
import pytest
import yaml
from cryptojwt import KeyJar
from oidcmsg.oidc import AuthorizationRequest

from oidcop.oidc.authorization import Authorization
from oidcop.server import Server
from oidcop.user_authn.authn_context import UNSPECIFIED
from oidcop.user_authn.user import NoAuthn

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]}
    # {"type": "EC", "crv": "P-256", "use": ["sig"]}
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

CLAIMS = {"id_token": {"given_name": {"essential": True}, "nickname": None}}

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

AUTH_REQ_DICT = AUTH_REQ.to_dict()

AUTH_REQ_2 = AuthorizationRequest(
    client_id="client_3",
    redirect_uri="https://127.0.0.1:8090/authz_cb/bobcat",
    scope=["openid"],
    state="STATE2",
    response_type="code",
)

AUTH_REQ_3 = AuthorizationRequest(
    client_id="client_2",
    redirect_uri="https://app1.example.net/foo",
    scope=["openid"],
    state="STATE3",
    response_type="code",
)

AUTH_REQ_4 = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid", "email"],
    state="STATE",
    response_type="code",
)

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_db = json.loads(open(full_path("users.json")).read())

client_yaml = """
oidc_clients:
  client_1:
    client_secret: hemligtkodord,
    client_id: client_1,
    "redirect_uris":
        - ['https://example.com/cb', '']
    "client_salt": "salted"
    'token_endpoint_auth_method': 'client_secret_post'
    'response_types':
        - 'code'
        - 'token'
        - 'code id_token'
        - 'id_token'
        - 'code id_token token'
  client_2:
    client_secret: "spraket_sr.se"
    client_id: client_2,
    redirect_uris:
      - ['https://app1.example.net/foo', '']
      - ['https://app2.example.net/bar', '']
    response_types:
      - code
  client_3:
    client_id: client_3,
    client_secret: '2222222222222222222222222222222222222222'
    redirect_uris:
      - ['https://127.0.0.1:8090/authz_cb/bobcat', '']
    post_logout_redirect_uris:
      - ['https://openidconnect.net/', '']
    response_types:
      - code
"""


class TestUserAuthn(object):
    @pytest.fixture(autouse=True)
    def create_endpoint_context(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
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
                    },
                }
            },
            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
            "authentication": {
                "anon": {"acr": UNSPECIFIED, "class": NoAuthn, "kwargs": {"user": "diana"},},
            },
            "template_dir": "template"
        }
        server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)

        endpoint_context = server.endpoint_context
        _clients = yaml.safe_load(io.StringIO(client_yaml))
        endpoint_context.cdb = _clients["oidc_clients"]
        endpoint_context.keyjar.import_jwks(
            endpoint_context.keyjar.export_jwks(True, ""), conf["issuer"]
        )
        self.endpoint = server.server_get("endpoint", "authorization")

        self.rp_keyjar = KeyJar()
        self.rp_keyjar.add_symmetric("client_1", "hemligtkodord1234567890")
        endpoint_context.keyjar.add_symmetric("client_1", "hemligtkodord1234567890")
