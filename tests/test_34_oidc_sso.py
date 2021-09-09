import io
import json
import os

from . import full_path
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
            "httpc_params": {"verify": False, "timeout": 1},
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
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
            "template_dir": "template",
            "userinfo": {
                "class": "oidcop.user_info.UserInfo",
                "kwargs": {"db_file": full_path("users.json")},
            },
        }
        server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)

        endpoint_context = server.endpoint_context
        _clients = yaml.safe_load(io.StringIO(client_yaml))
        endpoint_context.cdb = _clients["oidc_clients"]
        endpoint_context.keyjar.import_jwks(
            endpoint_context.keyjar.export_jwks(True, ""), conf["issuer"]
        )
        self.endpoint = server.server_get("endpoint", "authorization")
        self.endpoint_context = endpoint_context
        self.rp_keyjar = KeyJar()
        self.rp_keyjar.add_symmetric("client_1", "hemligtkodord1234567890")
        endpoint_context.keyjar.add_symmetric("client_1", "hemligtkodord1234567890")

    def test_sso(self):
        request = self.endpoint.parse_request(AUTH_REQ_DICT)
        redirect_uri = request["redirect_uri"]
        cinfo = self.endpoint.server_get("endpoint_context").cdb[request["client_id"]]
        info = self.endpoint.setup_auth(request, redirect_uri, cinfo, cookie=None)
        # info = self.endpoint.process_request(request)

        assert "user" in info

        res = self.endpoint.authz_part2(request, info["session_id"], cookie="")
        assert res
        cookies_1 = res["cookie"]

        # second login - from 2nd client
        request = self.endpoint.parse_request(AUTH_REQ_2.to_dict())
        redirect_uri = request["redirect_uri"]
        cinfo = self.endpoint.server_get("endpoint_context").cdb[request["client_id"]]
        info = self.endpoint.setup_auth(request, redirect_uri, cinfo, cookie=None)
        sid2 = info["session_id"]

        assert set(info.keys()) == {"session_id", "identity", "user"}
        assert info["user"] == "diana"

        res = self.endpoint.authz_part2(request, info["session_id"], cookie="")
        cookies_2 = res["cookie"]

        # third login - from 3rd client
        request = self.endpoint.parse_request(AUTH_REQ_3.to_dict())
        redirect_uri = request["redirect_uri"]
        cinfo = self.endpoint.server_get("endpoint_context").cdb[request["client_id"]]
        info = self.endpoint.setup_auth(request, redirect_uri, cinfo, cookie=None)

        assert set(info.keys()) == {"session_id", "identity", "user"}
        assert info["user"] == "diana"

        res = self.endpoint.authz_part2(request, info["session_id"], cookie="")
        cookies_3 = res["cookie"]

        # fourth login - from 1st client

        request = self.endpoint.parse_request(AUTH_REQ_4.to_dict())
        redirect_uri = request["redirect_uri"]
        cinfo = self.endpoint.server_get("endpoint_context").cdb[request["client_id"]]

        # Parse cookies once before setup_auth
        kakor = self.endpoint_context.cookie_handler.parse_cookie(
            cookies=cookies_1, name=self.endpoint_context.cookie_handler.name["session"])

        info = self.endpoint.setup_auth(request, redirect_uri, cinfo, cookie=kakor)

        assert set(info.keys()) == {"session_id", "identity", "user"}
        assert info["user"] == "diana"

        self.endpoint.authz_part2(request, info["session_id"], cookie="")

        # Fifth login - from 2nd client - wrong cookie
        request = self.endpoint.parse_request(AUTH_REQ_2.to_dict())
        redirect_uri = request["redirect_uri"]
        cinfo = self.endpoint.server_get("endpoint_context").cdb[request["client_id"]]
        info = self.endpoint.setup_auth(request, redirect_uri, cinfo, cookie=kakor)
        # No valid login cookie so new session
        assert info["session_id"] != sid2

        user_session_info = self.endpoint.server_get("endpoint_context").session_manager.get(
            ["diana"]
        )
        assert len(user_session_info.subordinate) == 3
        assert set(user_session_info.subordinate) == {
            "client_1",
            "client_2",
            "client_3",
        }

        # Should be one grant for each of client_2 and client_3 and
        # 2 grants for client_1

        csi1 = self.endpoint.server_get("endpoint_context").session_manager.get(
            ["diana", "client_1"]
        )
        csi2 = self.endpoint.server_get("endpoint_context").session_manager.get(
            ["diana", "client_2"]
        )
        csi3 = self.endpoint.server_get("endpoint_context").session_manager.get(
            ["diana", "client_3"]
        )

        assert len(csi1.subordinate) == 2
        assert len(csi2.subordinate) == 1
        assert len(csi3.subordinate) == 2
