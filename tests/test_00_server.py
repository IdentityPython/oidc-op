from copy import copy
from copy import deepcopy
import io
import json
import os

from cryptojwt.key_jar import build_keyjar
from oidcmsg.storage.abfile import AbstractFileSystem
import yaml

from oidcop.configure import OPConfiguration
import oidcop.login_hint
from oidcop.oidc.add_on.pkce import add_pkce_support
from oidcop.oidc.authorization import Authorization
from oidcop.oidc.provider_config import ProviderConfiguration
from oidcop.oidc.registration import Registration
from oidcop.oidc.session import Session
from oidcop.oidc.token import Token
from oidcop.oidc.userinfo import UserInfo
from oidcop.server import Server
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

KEYJAR = build_keyjar(KEYDEFS)

CONF = {
    "issuer": "https://example.com/",
    "httpc_params": {"verify": False, "timeout": 1},
    "capabilities": {},
    "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS, "read_only": True},
    "endpoint": {
        "provider_config": {
            "path": ".well-known/openid-configuration",
            "class": ProviderConfiguration,
            "kwargs": {},
        },
        "registration_endpoint": {"path": "registration", "class": Registration, "kwargs": {}, },
        "authorization_endpoint": {"path": "authorization", "class": Authorization, "kwargs": {}, },
        "token_endpoint": {"path": "token", "class": Token, "kwargs": {}},
        "userinfo_endpoint": {
            "path": "userinfo",
            "class": UserInfo,
            "kwargs": {"db_file": "users.json"},
        },
        "session": {"path": "end_session", "class": Session, "kwargs": {}},
    },
    "authentication": {
        "anon": {
            "acr": INTERNETPROTOCOLPASSWORD,
            "class": "oidcop.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
    "claims_interface": {"class": "oidcop.session.claims.ClaimsInterface", "kwargs": {}},
    "add_on": {"pkce": {"function": add_pkce_support, "kwargs": {"essential": True}}},
    "template_dir": "template",
    "login_hint_lookup": {"class": oidcop.login_hint.LoginHintLookup, "kwargs": {}},
}

client_yaml = """
oidc_clients:
  client1:
    # client secret is "password"
    client_secret: "Namnam"
    redirect_uris:
      - ['https://openidconnect.net/callback', '']
    response_types:
      - code
  client2:
    client_secret: "spraket"
    redirect_uris:
      - ['https://app1.example.net/foo', '']
      - ['https://app2.example.net/bar', '']
    response_types:
      - code
  client3:
    client_secret: '2222222222222222222222222222222222222222'
    redirect_uris:
      - ['https://127.0.0.1:8090/authz_cb/bobcat', '']
    post_logout_redirect_uri: ['https://openidconnect.net/', '']
    response_types:
      - code
"""


def test_capabilities_default():
    _str = open(full_path("op_config.json")).read()
    _conf = json.loads(_str)

    configuration = OPConfiguration(conf=_conf, base_path=BASEDIR, domain="127.0.0.1", port=443)

    server = Server(configuration)
    assert set(server.endpoint_context.provider_info["response_types_supported"]) == {
        "code",
        "token",
        "id_token",
        "code token",
        "code id_token",
        "id_token token",
        "code id_token token",
    }
    assert server.endpoint_context.provider_info["request_uri_parameter_supported"] is True
    assert server.endpoint_context.jwks_uri == 'https://127.0.0.1:80/static/jwks.json'


def test_capabilities_subset1():
    _cnf = deepcopy(CONF)
    _cnf["capabilities"] = {"response_types_supported": ["code"]}
    server = Server(_cnf)
    assert server.endpoint_context.provider_info["response_types_supported"] == ["code"]


def test_capabilities_subset2():
    _cnf = deepcopy(CONF)
    _cnf["capabilities"] = {"response_types_supported": ["code", "id_token"]}
    server = Server(_cnf)
    assert set(server.endpoint_context.provider_info["response_types_supported"]) == {
        "code",
        "id_token",
    }


def test_capabilities_bool():
    _cnf = deepcopy(CONF)
    _cnf["capabilities"] = {"request_uri_parameter_supported": False}
    server = Server(_cnf)
    assert server.endpoint_context.provider_info["request_uri_parameter_supported"] is False


def test_cdb():
    _cnf = deepcopy(CONF)
    server = Server(_cnf)
    _clients = yaml.safe_load(io.StringIO(client_yaml))
    server.endpoint_context.cdb = _clients["oidc_clients"]

    assert set(server.endpoint_context.cdb.keys()) == {"client1", "client2", "client3"}


def test_cdb_afs():
    _cnf = copy(CONF)
    _cnf["client_db"] = {
        "class": 'oidcmsg.storage.abfile.AbstractFileSystem',
        "kwargs": {
            'fdir': full_path("afs"),
            'value_conv': 'oidcmsg.util.JSON'
        }
    }
    server = Server(_cnf)
    assert isinstance(server.endpoint_context.cdb, AbstractFileSystem)
