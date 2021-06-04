import io
import json
import os
from urllib.parse import parse_qs
from urllib.parse import urlparse

from oidcop.configure import OPConfiguration
import pytest
import responses
import yaml
from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.utils import as_bytes
from cryptojwt.utils import b64e
from oidcmsg.exception import ParameterError
from oidcmsg.exception import URIError
from oidcmsg.oauth2 import AuthorizationErrorResponse
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import AuthorizationResponse
from oidcmsg.oidc import verified_claim_name
from oidcmsg.oidc import verify_id_token

from oidcop.authn_event import create_authn_event
from oidcop.authz import AuthzHandling
from oidcop.endpoint_context import init_service
from oidcop.endpoint_context import init_user_info
from oidcop.exception import NoSuchAuthentication
from oidcop.exception import RedirectURIError
from oidcop.exception import ServiceError
from oidcop.exception import ToOld
from oidcop.exception import UnknownClient
from oidcop.login_hint import LoginHint2Acrs
from oidcop.oauth2.authorization import authn_args_gather
from oidcop.oauth2.authorization import get_uri
from oidcop.oauth2.authorization import inputs
from oidcop.oauth2.authorization import join_query
from oidcop.oauth2.authorization import verify_uri
from oidcop.oidc import userinfo
from oidcop.oidc.authorization import Authorization
from oidcop.oidc.authorization import acr_claims
from oidcop.oidc.authorization import re_authenticate
from oidcop.oidc.provider_config import ProviderConfiguration
from oidcop.oidc.registration import Registration
from oidcop.oidc.token import Token
from oidcop.server import Server
from oidcop.session.grant import Grant
from oidcop.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcop.user_authn.authn_context import UNSPECIFIED
from oidcop.user_authn.authn_context import init_method
from oidcop.user_authn.user import NoAuthn
from oidcop.user_authn.user import UserAuthnMethod
from oidcop.user_authn.user import UserPassJinja2
from oidcop.user_info import UserInfo
from oidcop.util import JSONDictDB

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
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
    client_id="client3",
    redirect_uri="https://127.0.0.1:8090/authz_cb/bobcat",
    scope=["openid"],
    state="STATE2",
    response_type="code",
)

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_db = json.loads(open(full_path("users.json")).read())

client_yaml = """
oidc_clients:
  client_1:
    "client_secret": 'hemligtkodord'
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
  client2:
    client_secret: "spraket_sr.se"
    redirect_uris:
      - ['https://app1.example.net/foo', '']
      - ['https://app2.example.net/bar', '']
    response_types:
      - code
  client3:
    client_secret: '2222222222222222222222222222222222222222'
    redirect_uris:
      - ['https://127.0.0.1:8090/authz_cb/bobcat', '']
    post_logout_redirect_uris:
      - ['https://openidconnect.net/', '']
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
            "token_handler_args": {
                "jwks_file": "private/token_jwks.json",
                "code": {"kwargs": {"lifetime": 600}},
                "token": {
                    "class": "oidcop.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "add_claims_by_scope": True,
                        "aud": ["https://example.org/appl"],
                    },
                },
                "refresh": {
                    "class": "oidcop.token.jwt_token.JWTToken",
                    "kwargs": {"lifetime": 3600, "aud": ["https://example.org/appl"],},
                },
                "id_token": {
                    "class": "oidcop.token.id_token.IDToken",
                    "kwargs": {
                        "base_claims": {
                            "email": {"essential": True},
                            "email_verified": {"essential": True},
                            "given_name": {"essential": True},
                            "nickname": None,
                        }
                    },
                },
            },
            "endpoint": {
                "provider_config": {
                    "path": "{}/.well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "registration": {"path": "{}/registration", "class": Registration, "kwargs": {},},
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
                },
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
                "userinfo": {
                    "path": "userinfo",
                    "class": userinfo.UserInfo,
                    "kwargs": {
                        "db_file": "users.json",
                        "claim_types_supported": ["normal", "aggregated", "distributed",],
                    },
                },
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
            "authz": {
                "class": AuthzHandling,
                "kwargs": {
                    "grant_config": {
                        "usage_rules": {
                            "authorization_code": {
                                "supports_minting": ["access_token", "refresh_token", "id_token",],
                                "max_usage": 1,
                            },
                            "access_token": {},
                            "refresh_token": {
                                "supports_minting": ["access_token", "refresh_token"],
                            },
                        },
                        "expires_in": 43200,
                    }
                },
            },
            "login_hint2acrs": {
                "class": LoginHint2Acrs,
                "kwargs": {"scheme_map": {"email": [INTERNETPROTOCOLPASSWORD]}},
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
        self.session_manager = endpoint_context.session_manager
        self.user_id = "diana"

        self.rp_keyjar = KeyJar()
        self.rp_keyjar.add_symmetric("client_1", "hemligtkodord1234567890")
        endpoint_context.keyjar.add_symmetric("client_1", "hemligtkodord1234567890")

    def test_init(self):
        assert self.endpoint

    def _create_session(self, auth_req, sub_type="public", sector_identifier=""):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req
        client_id = authz_req["client_id"]
        ae = create_authn_event(self.user_id)
        return self.session_manager.create_session(
            ae, authz_req, self.user_id, client_id=client_id, sub_type=sub_type
        )

    def test_parse(self):
        _req = self.endpoint.parse_request(AUTH_REQ_DICT)

        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == set(AUTH_REQ.keys())

    # def test_process_request(self):
        # _pr_resp = self.endpoint.parse_request(AUTH_REQ_DICT)
        # breakpoi
        # _resp = self.endpoint.process_request(_pr_resp)

        # assert set(_resp.keys()) == {
            # "response_args",
            # "fragment_enc",
            # "return_uri",
            # "session_id",
        # }

    # def test_do_response_code(self):
        # _pr_resp = self.endpoint.parse_request(AUTH_REQ_DICT)
        # _resp = self.endpoint.process_request(_pr_resp)
        # msg = self.endpoint.do_response(**_resp)
        # assert isinstance(msg, dict)
        # _msg = parse_qs(msg["response"])
        # assert _msg
        # part = urlparse(msg["response"])
        # assert part.fragment == ""
        # assert part.query
        # _query = parse_qs(part.query)
        # assert _query
        # assert "code" in _query

    def test_do_response_id_token_no_nonce(self):
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req["response_type"] = "id_token"
        _pr_resp = self.endpoint.parse_request(_orig_req)
        assert isinstance(_pr_resp, ResponseMessage)

    # def test_do_response_id_token(self):
        # _orig_req = AUTH_REQ_DICT.copy()
        # _orig_req["response_type"] = "id_token"
        # _orig_req["nonce"] = "rnd_nonce"
        # _pr_resp = self.endpoint.parse_request(_orig_req)
        # _resp = self.endpoint.process_request(_pr_resp)
        # msg = self.endpoint.do_response(**_resp)
        # assert isinstance(msg, dict)
        # part = urlparse(msg["response"])
        # assert part.query == ""
        # assert part.fragment
        # _frag_msg = parse_qs(part.fragment)
        # assert _frag_msg
        # assert "id_token" in _frag_msg
        # assert "code" not in _frag_msg
        # assert "token" not in _frag_msg

    def test_do_response_id_token_token(self):
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req["response_type"] = "id_token token"
        _orig_req["nonce"] = "rnd_nonce"
        _pr_resp = self.endpoint.parse_request(_orig_req)
        assert isinstance(_pr_resp, AuthorizationErrorResponse)
        assert _pr_resp["error"] == "invalid_request"

    def test_do_response_code_token(self):
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req["response_type"] = "code token"
        _pr_resp = self.endpoint.parse_request(_orig_req)
        assert isinstance(_pr_resp, AuthorizationErrorResponse)
        assert _pr_resp["error"] == "invalid_request"

    # def test_do_response_code_id_token(self):
        # _orig_req = AUTH_REQ_DICT.copy()
        # _orig_req["response_type"] = "code id_token"
        # _orig_req["nonce"] = "rnd_nonce"
        # _pr_resp = self.endpoint.parse_request(_orig_req)
        # _resp = self.endpoint.process_request(_pr_resp)
        # msg = self.endpoint.do_response(**_resp)
        # assert isinstance(msg, dict)
        # part = urlparse(msg["response"])
        # assert part.query == ""
        # assert part.fragment
        # _frag_msg = parse_qs(part.fragment)
        # assert _frag_msg
        # assert "id_token" in _frag_msg
        # assert "code" in _frag_msg
        # assert "access_token" not in _frag_msg

    # def test_do_response_code_id_token_token(self):
        # _orig_req = AUTH_REQ_DICT.copy()
        # _orig_req["response_type"] = "code id_token token"
        # _orig_req["nonce"] = "rnd_nonce"
        # _pr_resp = self.endpoint.parse_request(_orig_req)
        # _resp = self.endpoint.process_request(_pr_resp)
        # msg = self.endpoint.do_response(**_resp)
        # assert isinstance(msg, dict)
        # part = urlparse(msg["response"])
        # assert part.query == ""
        # assert part.fragment
        # _frag_msg = parse_qs(part.fragment)
        # assert _frag_msg
        # assert "id_token" in _frag_msg
        # assert "code" in _frag_msg
        # assert "access_token" in _frag_msg

    # def test_id_token_claims(self):
        # _req = AUTH_REQ_DICT.copy()
        # _req["claims"] = CLAIMS
        # _req["response_type"] = "code id_token token"
        # _req["nonce"] = "rnd_nonce"
        # _pr_resp = self.endpoint.parse_request(_req)
        # _resp = self.endpoint.process_request(_pr_resp)
        # idt = verify_id_token(
            # _resp["response_args"], keyjar=self.endpoint.server_get("endpoint_context").keyjar,
        # )
        # assert idt
        # assert "given_name" in _resp["response_args"]["__verified_id_token"]
        # assert "nickname" in _resp["response_args"]["__verified_id_token"]
        # assert "email" in _resp["response_args"]["__verified_id_token"]

    def test_re_authenticate(self):
        request = {"prompt": "login"}
        authn = UserAuthnMethod(self.endpoint.server_get("endpoint_context"))
        assert re_authenticate(request, authn)

    # def test_id_token_acr(self):
        # _req = AUTH_REQ_DICT.copy()
        # _req["claims"] = {
            # "id_token": {"acr": {"value": "http://www.swamid.se/policy/assurance/al1"}}
        # }
        # _req["response_type"] = "code id_token token"
        # _req["nonce"] = "rnd_nonce"
        # _pr_resp = self.endpoint.parse_request(_req)
        # _resp = self.endpoint.process_request(_pr_resp)
        # res = verify_id_token(
            # _resp["response_args"], keyjar=self.endpoint.server_get("endpoint_context").keyjar,
        # )
        # assert res
        # res = _resp["response_args"][verified_claim_name("id_token")]
        # assert res["acr"] == "http://www.swamid.se/policy/assurance/al1"

    def test_verify_uri_unknown_client(self):
        request = {"redirect_uri": "https://rp.example.com/cb"}
        with pytest.raises(UnknownClient):
            verify_uri(self.endpoint.server_get("endpoint_context"), request, "redirect_uri")

    def test_verify_uri_fragment(self):
        _ec = self.endpoint.server_get("endpoint_context")
        _ec.cdb["client_id"] = {"redirect_uri": ["https://rp.example.com/auth_cb"]}
        request = {"redirect_uri": "https://rp.example.com/cb#foobar"}
        with pytest.raises(URIError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_verify_uri_noregistered(self):
        _ec = self.endpoint.server_get("endpoint_context")
        request = {"redirect_uri": "https://rp.example.com/cb"}

        with pytest.raises(KeyError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_verify_uri_unregistered(self):
        _ec = self.endpoint.server_get("endpoint_context")
        _ec.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/auth_cb", {})]}

        request = {"redirect_uri": "https://rp.example.com/cb"}

        with pytest.raises(RedirectURIError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_verify_uri_qp_match(self):
        _ec = self.endpoint.server_get("endpoint_context")
        _ec.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/cb", {"foo": ["bar"]})]}

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bar"}

        verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_verify_uri_qp_mismatch(self):
        _ec = self.endpoint.server_get("endpoint_context")
        _ec.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/cb", {"foo": ["bar"]})]}

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bob"}
        with pytest.raises(ValueError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bar&foo=kex"}
        with pytest.raises(ValueError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

        request = {"redirect_uri": "https://rp.example.com/cb"}
        with pytest.raises(ValueError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bar&level=low"}
        with pytest.raises(ValueError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_verify_uri_qp_missing(self):
        _ec = self.endpoint.server_get("endpoint_context")
        _ec.cdb["client_id"] = {
            "redirect_uris": [("https://rp.example.com/cb", {"foo": ["bar"], "state": ["low"]})]
        }

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bar"}
        with pytest.raises(ValueError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_verify_uri_qp_missing_val(self):
        _ec = self.endpoint.server_get("endpoint_context")
        _ec.cdb["client_id"] = {
            "redirect_uris": [("https://rp.example.com/cb", {"foo": ["bar", "low"]})]
        }

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bar"}
        with pytest.raises(ValueError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_verify_uri_no_registered_qp(self):
        _ec = self.endpoint.server_get("endpoint_context")
        _ec.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/cb", {})]}

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bob"}
        with pytest.raises(ValueError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_get_uri(self):
        _ec = self.endpoint.server_get("endpoint_context")
        _ec.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/cb", {})]}

        request = {
            "redirect_uri": "https://rp.example.com/cb",
            "client_id": "client_id",
        }

        assert get_uri(_ec, request, "redirect_uri") == "https://rp.example.com/cb"

    def test_get_uri_no_redirect_uri(self):
        _ec = self.endpoint.server_get("endpoint_context")
        _ec.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/cb", {})]}

        request = {"client_id": "client_id"}

        assert get_uri(_ec, request, "redirect_uri") == "https://rp.example.com/cb"

    def test_get_uri_no_registered(self):
        _ec = self.endpoint.server_get("endpoint_context")
        _ec.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/cb", {})]}

        request = {"client_id": "client_id"}

        with pytest.raises(ParameterError):
            get_uri(_ec, request, "post_logout_redirect_uri")

    def test_get_uri_more_then_one_registered(self):
        _ec = self.endpoint.server_get("endpoint_context")
        _ec.cdb["client_id"] = {
            "redirect_uris": [
                ("https://rp.example.com/cb", {}),
                ("https://rp.example.org/authz_cb", {"foo": "bar"}),
            ]
        }

        request = {"client_id": "client_id"}

        with pytest.raises(ParameterError):
            get_uri(_ec, request, "redirect_uri")

    def test_create_authn_response(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token"],
            state="state",
            nonce="nonce",
            scope="openid",
        )

        _ec = self.endpoint.server_get("endpoint_context")
        _ec.cdb["client_id"] = {
            "client_id": "client_id",
            "redirect_uris": [("https://rp.example.com/cb", {})],
            "id_token_signed_response_alg": "ES256",
        }

        session_id = self._create_session(request)

        resp = self.endpoint.create_authn_response(request, session_id)
        assert isinstance(resp["response_args"], AuthorizationResponse)

    # def test_setup_auth(self):
        # request = AuthorizationRequest(
            # client_id="client_id",
            # redirect_uri="https://rp.example.com/cb",
            # response_type=["id_token"],
            # state="state",
            # nonce="nonce",
            # scope="openid",
        # )
        # redirect_uri = request["redirect_uri"]
        # cinfo = {
            # "client_id": "client_id",
            # "redirect_uris": [("https://rp.example.com/cb", {})],
            # "id_token_signed_response_alg": "RS256",
        # }

        # res = self.endpoint.setup_auth(request, redirect_uri, cinfo, [])
        # assert set(res.keys()) == {"session_id", "identity", "user"}

    def test_setup_auth_error(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token"],
            state="state",
            nonce="nonce",
            scope="openid",
        )
        redirect_uri = request["redirect_uri"]
        cinfo = {
            "client_id": "client_id",
            "redirect_uris": [("https://rp.example.com/cb", {})],
            "id_token_signed_response_alg": "RS256",
        }

        item = self.endpoint.server_get("endpoint_context").authn_broker.db["anon"]
        item["method"].fail = NoSuchAuthentication

        res = self.endpoint.setup_auth(request, redirect_uri, cinfo, None)
        assert set(res.keys()) == {"function", "args"}

        item["method"].fail = ToOld

        res = self.endpoint.setup_auth(request, redirect_uri, cinfo, None)
        assert set(res.keys()) == {"function", "args"}

        item["method"].file = ""

    # def test_setup_auth_user(self):
        # request = AuthorizationRequest(
            # client_id="client_id",
            # redirect_uri="https://rp.example.com/cb",
            # response_type=["id_token"],
            # state="state",
            # nonce="nonce",
            # scope="openid",
        # )
        # redirect_uri = request["redirect_uri"]
        # cinfo = {
            # "client_id": "client_id",
            # "redirect_uris": [("https://rp.example.com/cb", {})],
            # "id_token_signed_response_alg": "RS256",
        # }
        # _ec = self.endpoint.server_get("endpoint_context")

        # session_id = self._create_session(request)

        # item = _ec.authn_broker.db["anon"]
        # item["method"].user = b64e(as_bytes(json.dumps({"uid": "krall", "sid": session_id})))

        # res = self.endpoint.setup_auth(request, redirect_uri, cinfo, None)
        # assert set(res.keys()) == {"session_id", "identity", "user"}
        # assert res["identity"]["uid"] == "krall"

    # def test_setup_auth_session_revoked(self):
        # request = AuthorizationRequest(
            # client_id="client_id",
            # redirect_uri="https://rp.example.com/cb",
            # response_type=["id_token"],
            # state="state",
            # nonce="nonce",
            # scope="openid",
        # )
        # redirect_uri = request["redirect_uri"]
        # cinfo = {
            # "client_id": "client_id",
            # "redirect_uris": [("https://rp.example.com/cb", {})],
            # "id_token_signed_response_alg": "RS256",
        # }
        # _ec = self.endpoint.server_get("endpoint_context")

        # session_id = self._create_session(request)

        # item = _ec.authn_broker.db["anon"]
        # item["method"].user = b64e(as_bytes(json.dumps({"uid": "krall", "sid": session_id})))

        # grant = _ec.session_manager[session_id]
        # grant.revoked = True

        # res = self.endpoint.setup_auth(request, redirect_uri, cinfo, None)
        # assert set(res.keys()) == {"args", "function"}

    # def test_check_session_iframe(self):
        # self.endpoint.server_get("endpoint_context").provider_info[
            # "check_session_iframe"
        # ] = "https://example.com/csi"
        # _pr_resp = self.endpoint.parse_request(AUTH_REQ_DICT)
        # _resp = self.endpoint.process_request(_pr_resp)
        # assert "session_state" in _resp["response_args"]

    def test_setup_auth_login_hint(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token"],
            state="state",
            nonce="nonce",
            scope="openid",
            login_hint="tel:0907865204",
        )
        redirect_uri = request["redirect_uri"]
        cinfo = {
            "client_id": "client_id",
            "redirect_uris": [("https://rp.example.com/cb", {})],
            "id_token_signed_response_alg": "RS256",
        }

        item = self.endpoint.server_get("endpoint_context").authn_broker.db["anon"]
        item["method"].fail = NoSuchAuthentication

        res = self.endpoint.setup_auth(request, redirect_uri, cinfo, None)
        assert set(res.keys()) == {"function", "args"}
        assert "login_hint" in res["args"]

    def test_setup_auth_login_hint2acrs(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token"],
            state="state",
            nonce="nonce",
            scope="openid",
            login_hint="email:foo@bar",
        )
        redirect_uri = request["redirect_uri"]

        method_spec = {
            "acr": INTERNETPROTOCOLPASSWORD,
            "kwargs": {"user": "knoll"},
            "class": NoAuthn,
        }
        self.endpoint.server_get("endpoint_context").authn_broker["foo"] = init_method(
            method_spec, None
        )

        item = self.endpoint.server_get("endpoint_context").authn_broker.db["anon"]
        item["method"].fail = NoSuchAuthentication
        item = self.endpoint.server_get("endpoint_context").authn_broker.db["foo"]
        item["method"].fail = NoSuchAuthentication

        res = self.endpoint.pick_authn_method(request, redirect_uri)
        assert set(res.keys()) == {"method", "acr"}
        assert res["acr"] == INTERNETPROTOCOLPASSWORD
        assert isinstance(res["method"], NoAuthn)
        assert res["method"].user == "knoll"

    def test_post_logout_uri(self):
        pass

    def test_parse_request(self):
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

    def test_verify_response_type(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token token"],
            state="state",
            nonce="nonce",
            scope="openid",
        )
        client_info = {
            "client_id": "client_id",
            "redirect_uris": [("https://rp.example.com/cb", {})],
            "id_token_signed_response_alg": "RS256",
            "policy_uri": "https://example.com/policy.html",
        }

        assert self.endpoint.verify_response_type(request, client_info) is False

        client_info["response_types"] = [
            "code",
            "code id_token",
            "id_token",
            "id_token token",
        ]

        assert self.endpoint.verify_response_type(request, client_info) is True

    @pytest.mark.parametrize("exp_in", [360, "360", 0])
    def test_mint_token_exp_at(self, exp_in):
        grant = Grant()
        grant.usage_rules = {"authorization_code": {"expires_in": exp_in}}

        DUMMY_SESSION_ID = self.session_manager.encrypted_session_id(
            "user_id", "client_id", "grant.id"
        )

        code = self.endpoint.mint_token("authorization_code", grant, DUMMY_SESSION_ID)
        if exp_in in [360, "360"]:
            assert code.expires_at
        else:
            assert code.expires_at == 0

    def test_do_request_uri(self):
        request = AuthorizationRequest(
            redirect_uri="https://rp.example.com/cb", request_uri="https://example.com/request",
        )

        orig_request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token token"],
            state="state",
            nonce="nonce",
            scope="openid",
        )
        _jwt = JWT(key_jar=self.rp_keyjar, iss="client_1", sign_alg="HS256")
        _jws = _jwt.pack(
            orig_request.to_dict(),
            aud=self.endpoint.server_get("endpoint_context").provider_info["issuer"],
        )

        endpoint_context = self.endpoint.server_get("endpoint_context")
        endpoint_context.cdb["client_1"]["request_uris"] = [("https://example.com/request", {})]

        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                request["request_uri"],
                body=_jws,
                adding_headers={"Content-Type": "application/jose"},
                status=200,
            )

            self.endpoint._do_request_uri(request, "client_1", endpoint_context)

        request["request_uri"] = "https://example.com/request#1"

        with responses.RequestsMock() as rsps:
            rsps.add(
                "GET",
                request["request_uri"],
                body=_jws,
                adding_headers={"Content-Type": "application/jose"},
                status=200,
            )

            self.endpoint._do_request_uri(request, "client_1", endpoint_context)

        request["request_uri"] = "https://example.com/another"
        with pytest.raises(ValueError):
            self.endpoint._do_request_uri(request, "client_1", endpoint_context)

        endpoint_context.provider_info["request_uri_parameter_supported"] = False
        with pytest.raises(ServiceError):
            self.endpoint._do_request_uri(request, "client_1", endpoint_context)

    def test_post_parse_request(self):
        endpoint_context = self.endpoint.server_get("endpoint_context")
        msg = self.endpoint._post_parse_request(None, "client_1", endpoint_context)
        assert "error" in msg

        request = AuthorizationRequest(
            client_id="client_X",
            response_type=["code"],
            state="state",
            nonce="nonce",
            scope="openid",
        )

        msg = self.endpoint._post_parse_request(request, "client_X", endpoint_context)
        assert "error" in msg
        assert msg["error_description"] == "unknown client"

        request["client_id"] = "client_1"
        endpoint_context.cdb["client_1"]["redirect_uris"] = [
            ("https://example.com/cb", ""),
            ("https://example.com/2nd_cb", ""),
        ]

        msg = self.endpoint._post_parse_request(request, "client_1", endpoint_context)
        assert "error" in msg
        assert msg["error"] == "invalid_request"

    @pytest.mark.parametrize("response_mode", ["form_post", "fragment", "query"])
    def test_response_mode(self, response_mode):
        request = AuthorizationRequest(
            client_id="client_1",
            response_type=["code"],
            redirect_uri="https://example.com/cb",
            state="state",
            scope="openid",
            response_mode=response_mode,
        )

        response_args = AuthorizationResponse(scope="openid", code="abcdefghijklmnop")

        if response_mode == "fragment":
            info = self.endpoint.response_mode(
                request, response_args, request["redirect_uri"], fragment_enc=True
            )
        else:
            info = self.endpoint.response_mode(request, response_args, request["redirect_uri"])

        if response_mode == "form_post":
            assert set(info.keys()) == {
                "response_msg",
                "content_type",
                "response_placement",
            }
        elif response_mode == "fragment":
            assert set(info.keys()) == {"response_args", "return_uri", "fragment_enc"}
        elif response_mode == "query":
            assert set(info.keys()) == {"response_args", "return_uri"}

    def test_post_authentication(self):
        request = AuthorizationRequest(
            client_id="client_1",
            response_type=["code"],
            redirect_uri="https://example.com/cb",
            state="state",
            scope="openid",
        )
        session_id = self._create_session(request)
        resp = self.endpoint.post_authentication(request, session_id)
        assert resp

    def test_do_request_user(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token"],
            state="state",
            nonce="nonce",
            scope="openid",
        )
        assert self.endpoint.do_request_user(request) == {}

        # With login_hint
        request["login_hint"] = "mail:diana@example.org"
        assert self.endpoint.do_request_user(request) == {}

        endpoint_context = self.endpoint.server_get("endpoint_context")
        # userinfo
        _userinfo = init_user_info(
            {"class": "oidcop.user_info.UserInfo", "kwargs": {"db_file": full_path("users.json")},},
            "",
        )
        # login_hint
        endpoint_context.login_hint_lookup = init_service(
            {"class": "oidcop.login_hint.LoginHintLookup"}, None
        )
        endpoint_context.login_hint_lookup.userinfo = _userinfo

        # With login_hint and login_hint_lookup
        assert self.endpoint.do_request_user(request) == {"req_user": "diana"}


def test_authn_args_gather_message():
    request = AuthorizationRequest(
        client_id="client_id",
        redirect_uri="https://rp.example.com/cb",
        response_type=["id_token"],
        state="state",
        nonce="nonce",
        scope="openid",
    )
    client_info = {
        "client_id": "client_id",
        "redirect_uris": [("https://rp.example.com/cb", {})],
        "id_token_signed_response_alg": "RS256",
        "policy_uri": "https://example.com/policy.html",
    }

    args = authn_args_gather(request, INTERNETPROTOCOLPASSWORD, client_info)
    assert set(args.keys()) == {"query", "authn_class_ref", "return_uri", "policy_uri"}

    args = authn_args_gather(request.to_dict(), INTERNETPROTOCOLPASSWORD, client_info)
    assert set(args.keys()) == {"query", "authn_class_ref", "return_uri", "policy_uri"}

    with pytest.raises(ValueError):
        authn_args_gather(request.to_urlencoded(), INTERNETPROTOCOLPASSWORD, client_info)


def test_inputs():
    elems = inputs(dict(foo="bar", home="stead"))
    test_elems = (
        '<input type="hidden" name="foo" value="bar"/>',
        '<input type="hidden" name="home" value="stead"/>',
    )
    assert test_elems[0] in elems and test_elems[1] in elems


def test_acr_claims():
    assert acr_claims({"claims": {"id_token": {"acr": {"value": "foo"}}}}) == ["foo"]
    assert acr_claims({"claims": {"id_token": {"acr": {"values": ["foo", "bar"]}}}}) == [
        "foo",
        "bar",
    ]
    assert acr_claims({"claims": {"id_token": {"acr": {"values": ["foo"]}}}}) == ["foo"]
    assert acr_claims({"claims": {"id_token": {"acr": {"essential": True}}}}) is None


def test_join_query():
    redirect_uris = [("https://rp.example.com/cb", {"foo": ["bar"], "state": ["low"]})]
    uri = join_query(*redirect_uris[0])
    test_uri = ("https://rp.example.com/cb?", "foo=bar", "state=low")
    for i in test_uri:
        assert i in uri


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
                            "kwargs": {"filename": full_path("passwd.json")},
                        },
                        "page_header": "Testing log in",
                        "submit_btn": "Get me in!",
                        "user_label": "Nickname",
                        "passwd_label": "Secret sauce",
                    },
                },
                "anon": {"acr": UNSPECIFIED, "class": NoAuthn, "kwargs": {"user": "diana"},},
            },
            "template_dir": "template",
        }
        server = Server(OPConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
        self.endpoint_context = server.endpoint_context
