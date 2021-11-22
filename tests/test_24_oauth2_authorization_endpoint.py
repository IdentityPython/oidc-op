import io
import json
import os
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
from urllib.parse import urlparse

from oidcop.configure import ASConfiguration
import pytest
import yaml
from cryptojwt import KeyJar
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.utils import as_bytes
from cryptojwt.utils import b64e
from oidcmsg.exception import ParameterError
from oidcmsg.exception import URIError
from oidcmsg.oauth2 import AuthorizationErrorResponse
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.time_util import in_a_while

from oidcop.authn_event import create_authn_event
from oidcop.authz import AuthzHandling
from oidcop.cookie_handler import CookieHandler
from oidcop.exception import InvalidRequest
from oidcop.exception import NoSuchAuthentication
from oidcop.exception import RedirectURIError
from oidcop.exception import ToOld
from oidcop.exception import UnAuthorizedClientScope
from oidcop.exception import UnknownClient
from oidcop.oauth2.authorization import FORM_POST
from oidcop.oauth2.authorization import Authorization
from oidcop.oauth2.authorization import get_uri
from oidcop.oauth2.authorization import inputs
from oidcop.oauth2.authorization import join_query
from oidcop.oauth2.authorization import verify_uri
from oidcop.server import Server
from oidcop.user_info import UserInfo

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]}
    # {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

COOKIE_KEYDEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]},
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
            "token_handler_args": {
                "jwks_def": {
                    "private_path": "private/token_jwks.json",
                    "read_only": False,
                    "key_defs": [{"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
                },
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
                        }
                    },
                },
            },
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
            "authentication": {
                "anon": {
                    "acr": "http://www.swamid.se/policy/assurance/al1",
                    "class": "oidcop.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_db}},
            "template_dir": "template",
            "cookie_handler": {
                "class": CookieHandler,
                "kwargs": {
                    "keys": {"key_defs": COOKIE_KEYDEFS},
                    "name": {
                        "session": "oidc_op",
                        "register": "oidc_op_reg",
                        "session_management": "oidc_op_sman",
                    },
                },
            },
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
                                "supports_minting": ["access_token", "refresh_token", "id_token",],
                            },
                        },
                        "expires_in": 43200,
                    }
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
        self.endpoint_context = endpoint_context
        self.endpoint = server.server_get("endpoint", "authorization")
        self.session_manager = endpoint_context.session_manager
        self.user_id = "diana"

        self.rp_keyjar = KeyJar()
        self.rp_keyjar.add_symmetric("client_1", "hemligtkodord1234567890")
        self.endpoint.server_get("endpoint_context").keyjar.add_symmetric(
            "client_1", "hemligtkodord1234567890"
        )

    def _create_session(self, auth_req, sub_type="public", sector_identifier=""):
        if sector_identifier:
            areq = auth_req.copy()
            areq["sector_identifier_uri"] = sector_identifier
        else:
            areq = auth_req

        client_id = areq["client_id"]
        ae = create_authn_event(self.user_id)
        return self.session_manager.create_session(
            ae, areq, self.user_id, client_id=client_id, sub_type=sub_type
        )

    def test_init(self):
        assert self.endpoint

    def test_parse(self):
        _req = self.endpoint.parse_request(AUTH_REQ_DICT)
        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == set(AUTH_REQ.keys())

    def test_process_request(self):
        _pr_resp = self.endpoint.parse_request(AUTH_REQ_DICT)
        _resp = self.endpoint.process_request(_pr_resp)
        assert set(_resp.keys()) == {
            "response_args",
            "fragment_enc",
            "return_uri",
            "cookie",
            "session_id",
        }

    def test_do_response_code(self):
        _pr_resp = self.endpoint.parse_request(AUTH_REQ_DICT)
        _resp = self.endpoint.process_request(_pr_resp)
        msg = self.endpoint.do_response(**_resp)
        assert isinstance(msg, dict)
        _msg = parse_qs(msg["response"])
        assert _msg
        part = urlparse(msg["response"])
        assert part.fragment == ""
        assert part.query
        _query = parse_qs(part.query)
        assert _query
        assert "code" in _query

    def test_do_response_code_token(self):
        """UnAuthorized Client
        """
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req["response_type"] = "code token"
        msg = ""
        _pr_resp = self.endpoint.parse_request(_orig_req)
        assert isinstance(_pr_resp, AuthorizationErrorResponse)
        assert _pr_resp["error"] == "invalid_request"

    def test_verify_uri_unknown_client(self):
        request = {"redirect_uri": "https://rp.example.com/cb"}
        with pytest.raises(UnknownClient):
            verify_uri(self.endpoint.server_get("endpoint_context"), request, "redirect_uri")

    def test_verify_uri_fragment(self):
        _context = self.endpoint.server_get("endpoint_context")
        _context.cdb["client_id"] = {"redirect_uri": ["https://rp.example.com/auth_cb"]}
        request = {"redirect_uri": "https://rp.example.com/cb#foobar"}
        with pytest.raises(URIError):
            verify_uri(_context, request, "redirect_uri", "client_id")

    def test_verify_uri_noregistered(self):
        _context = self.endpoint.server_get("endpoint_context")
        request = {"redirect_uri": "https://rp.example.com/cb"}

        with pytest.raises(KeyError):
            verify_uri(_context, request, "redirect_uri", "client_id")

    def test_verify_uri_unregistered(self):
        _context = self.endpoint.server_get("endpoint_context")
        _context.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/auth_cb", {})]}

        request = {"redirect_uri": "https://rp.example.com/cb"}

        with pytest.raises(RedirectURIError):
            verify_uri(_context, request, "redirect_uri", "client_id")

    def test_verify_uri_qp_match(self):
        _context = self.endpoint.server_get("endpoint_context")
        _context.cdb["client_id"] = {
            "redirect_uris": [("https://rp.example.com/cb", {"foo": ["bar"]})]
        }

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bar"}

        verify_uri(_context, request, "redirect_uri", "client_id")

    def test_verify_uri_qp_mismatch(self):
        _context = self.endpoint.server_get("endpoint_context")
        _context.cdb["client_id"] = {
            "redirect_uris": [("https://rp.example.com/cb", {"foo": ["bar"]})]
        }

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bob"}
        with pytest.raises(ValueError):
            verify_uri(_context, request, "redirect_uri", "client_id")

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bar&foo=kex"}
        with pytest.raises(ValueError):
            verify_uri(_context, request, "redirect_uri", "client_id")

        request = {"redirect_uri": "https://rp.example.com/cb"}
        with pytest.raises(ValueError):
            verify_uri(_context, request, "redirect_uri", "client_id")

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bar&level=low"}
        with pytest.raises(ValueError):
            verify_uri(_context, request, "redirect_uri", "client_id")

    def test_verify_uri_qp_missing(self):
        _context = self.endpoint.server_get("endpoint_context")
        _context.cdb["client_id"] = {
            "redirect_uris": [("https://rp.example.com/cb", {"foo": ["bar"], "state": ["low"]})]
        }

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bar"}
        with pytest.raises(ValueError):
            verify_uri(_context, request, "redirect_uri", "client_id")

    def test_verify_uri_qp_missing_val(self):
        _context = self.endpoint.server_get("endpoint_context")
        _context.cdb["client_id"] = {
            "redirect_uris": [("https://rp.example.com/cb", {"foo": ["bar", "low"]})]
        }

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bar"}
        with pytest.raises(ValueError):
            verify_uri(_context, request, "redirect_uri", "client_id")

    def test_verify_uri_no_registered_qp(self):
        _context = self.endpoint.server_get("endpoint_context")
        _context.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/cb", {})]}

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bob"}
        with pytest.raises(ValueError):
            verify_uri(_context, request, "redirect_uri", "client_id")

    def test_verify_uri_wrong_uri_type(self):
        _context = self.endpoint.server_get("endpoint_context")
        _context.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/cb", {})]}

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bob"}
        with pytest.raises(ValueError):
            verify_uri(_context, request, "post_logout_redirect_uri", "client_id")

    def test_verify_uri_none_registered(self):
        _context = self.endpoint.server_get("endpoint_context")
        _context.cdb["client_id"] = {
            "post_logout_redirect_uri": [("https://rp.example.com/plrc", {})]
        }

        request = {"redirect_uri": "https://rp.example.com/cb"}
        with pytest.raises(RedirectURIError):
            verify_uri(_context, request, "redirect_uri", "client_id")

    def test_get_uri(self):
        _context = self.endpoint.server_get("endpoint_context")
        _context.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/cb", {})]}

        request = {
            "redirect_uri": "https://rp.example.com/cb",
            "client_id": "client_id",
        }

        assert get_uri(_context, request, "redirect_uri") == "https://rp.example.com/cb"

    def test_get_uri_no_redirect_uri(self):
        _context = self.endpoint.server_get("endpoint_context")
        _context.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/cb", {})]}

        request = {"client_id": "client_id"}

        assert get_uri(_context, request, "redirect_uri") == "https://rp.example.com/cb"

    def test_get_uri_no_registered(self):
        _context = self.endpoint.server_get("endpoint_context")
        _context.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/cb", {})]}

        request = {"client_id": "client_id"}

        with pytest.raises(ParameterError):
            get_uri(_context, request, "post_logout_redirect_uri")

    def test_get_uri_more_then_one_registered(self):
        _context = self.endpoint.server_get("endpoint_context")
        _context.cdb["client_id"] = {
            "redirect_uris": [
                ("https://rp.example.com/cb", {}),
                ("https://rp.example.org/authz_cb", {"foo": "bar"}),
            ]
        }

        request = {"client_id": "client_id"}

        with pytest.raises(ParameterError):
            get_uri(_context, request, "redirect_uri")

    def test_create_authn_response(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token"],
            state="state",
            nonce="nonce",
            scope="openid",
        )

        self.endpoint.server_get("endpoint_context").cdb["client_id"] = {
            "client_id": "client_id",
            "redirect_uris": [("https://rp.example.com/cb", {})],
            "id_token_signed_response_alg": "ES256",
        }

        session_id = self._create_session(request)

        resp = self.endpoint.create_authn_response(request, session_id)
        assert isinstance(resp["response_args"], AuthorizationErrorResponse)

    def test_setup_auth(self):
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

        kaka = self.endpoint.server_get("endpoint_context").cookie_handler.make_cookie_content(
            "value", "sso"
        )

        # Parsed once before setup_auth
        kakor = self.endpoint_context.cookie_handler.parse_cookie(
            cookies=[kaka], name=self.endpoint_context.cookie_handler.name["session"])

        res = self.endpoint.setup_auth(request, redirect_uri, cinfo, kakor)
        assert set(res.keys()) == {"session_id", "identity", "user"}

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

    def test_setup_auth_invalid_scope(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token"],
            state="state",
            nonce="nonce",
            scope="openid THAT-BLOODY_SCOPE",
        )
        redirect_uri = request["redirect_uri"]
        cinfo = {
            "client_id": "client_id",
            "redirect_uris": [("https://rp.example.com/cb", {})],
            "id_token_signed_response_alg": "RS256",
        }

        _context = self.endpoint.server_get("endpoint_context")
        _context.cdb["client_id"] = cinfo

        kaka = _context.cookie_handler.make_cookie_content("value", "sso")

        # force to 400 Http Error message if the release scope policy is heavy!
        _context.conf["capabilities"]["deny_unknown_scopes"] = True
        excp = None
        try:
            res = self.endpoint.process_request(request, http_info={"headers": {"cookie": [kaka]}})
        except UnAuthorizedClientScope as e:
            excp = e
        assert excp
        assert isinstance(excp, UnAuthorizedClientScope)

    def test_setup_auth_user(self):
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

        session_id = self._create_session(request)

        item = self.endpoint.server_get("endpoint_context").authn_broker.db["anon"]
        item["method"].user = b64e(as_bytes(json.dumps({"uid": "krall", "sid": session_id})))

        res = self.endpoint.setup_auth(request, redirect_uri, cinfo, None)
        assert set(res.keys()) == {"session_id", "identity", "user"}
        assert res["identity"]["uid"] == "krall"

    def test_setup_auth_session_revoked(self):
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

        session_id = self._create_session(request)

        _context = self.endpoint.server_get("endpoint_context")
        _mngr = _context.session_manager
        _csi = _mngr[session_id]
        _csi.revoked = True

        item = _context.authn_broker.db["anon"]
        item["method"].user = b64e(as_bytes(json.dumps({"uid": "krall", "sid": session_id})))

        res = self.endpoint.setup_auth(request, redirect_uri, cinfo, None)
        assert set(res.keys()) == {"args", "function"}

    def test_response_mode_form_post(self):
        request = {"response_mode": "form_post"}
        info = {
            "response_args": AuthorizationResponse(foo="bar"),
            "return_uri": "https://example.com/cb",
        }
        info = self.endpoint.response_mode(request, **info)
        assert set(info.keys()) == {
            "response_msg",
            "content_type",
            "response_placement",
        }
        assert info["response_msg"] == FORM_POST.format(
            action="https://example.com/cb", inputs='<input type="hidden" name="foo" value="bar"/>',
        )

    def test_response_mode_fragment(self):
        request = {"response_mode": "fragment"}
        self.endpoint.response_mode(request, fragment_enc=True)

        with pytest.raises(InvalidRequest):
            self.endpoint.response_mode(request, fragment_enc=False)

        info = self.endpoint.response_mode(request)
        assert set(info.keys()) == {"return_uri", "response_args", "fragment_enc"}

    def test_req_user(self):
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
        res = self.endpoint.setup_auth(request, redirect_uri, cinfo, None, req_user="adam")
        assert "function" in res

    def test_req_user_no_prompt(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token"],
            state="state",
            nonce="nonce",
            scope="openid",
            prompt="none",
        )
        redirect_uri = request["redirect_uri"]
        cinfo = {
            "client_id": "client_id",
            "redirect_uris": [("https://rp.example.com/cb", {})],
            "id_token_signed_response_alg": "RS256",
        }
        res = self.endpoint.setup_auth(request, redirect_uri, cinfo, None, req_user="adam")
        assert "error" in res

    # def test_sso(self):
    #     _pr_resp = self.endpoint.parse_request(AUTH_REQ_DICT)
    #     _resp = self.endpoint.process_request(_pr_resp)
    #     msg = self.endpoint.do_response(**_resp)
    #
    #     request = AuthorizationRequest(
    #         client_id="client_2",
    #         redirect_uri="https://rp.example.org/cb",
    #         response_type=["code"],
    #         state="state",
    #         scope="openid",
    #     )
    #
    #     cinfo = {
    #         "client_id": "client_2",
    #         "redirect_uris": [(request["redirect_uri"], {})]
    #     }
    #
    #     _pr_resp = self.endpoint.parse_request(AUTH_REQ_DICT, cookie="kaka")
    #     _resp = self.endpoint.process_request(_pr_resp)
    #     msg = self.endpoint.do_response(**_resp)
    #
    #     assert set(res.keys()) == {"authn_event", "identity", "user"}


def test_inputs():
    elems = inputs(dict(foo="bar", home="stead"))
    test_elems = (
        '<input type="hidden" name="foo" value="bar"/>',
        '<input type="hidden" name="home" value="stead"/>',
    )
    assert test_elems[0] in elems and test_elems[1] in elems


def test_join_query():
    redirect_uris = [("https://rp.example.com/cb", {"foo": ["bar"], "state": ["low"]})]
    uri = join_query(*redirect_uris[0])
    test_uri = ("https://rp.example.com/cb?", "foo=bar", "state=low")
    for i in test_uri:
        assert i in uri
