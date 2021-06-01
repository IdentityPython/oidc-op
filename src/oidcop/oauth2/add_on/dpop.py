from typing import Optional

from cryptojwt import JWS
from cryptojwt import as_unicode
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import factory
from oidcmsg.message import SINGLE_REQUIRED_INT
from oidcmsg.message import SINGLE_REQUIRED_JSON
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.message import Message

from oidcop.client_authn import AuthnFailure
from oidcop.client_authn import ClientAuthnMethod
from oidcop.client_authn import basic_authn


class DPoPProof(Message):
    c_param = {
        # header
        "typ": SINGLE_REQUIRED_STRING,
        "alg": SINGLE_REQUIRED_STRING,
        "jwk": SINGLE_REQUIRED_JSON,
        # body
        "jti": SINGLE_REQUIRED_STRING,
        "htm": SINGLE_REQUIRED_STRING,
        "htu": SINGLE_REQUIRED_STRING,
        "iat": SINGLE_REQUIRED_INT,
    }
    header_params = {"typ", "alg", "jwk"}
    body_params = {"jti", "htm", "htu", "iat"}

    def __init__(self, set_defaults=True, **kwargs):
        self.key = None
        Message.__init__(self, set_defaults=set_defaults, **kwargs)

        if self.key:
            pass
        elif "jwk" in self:
            self.key = key_from_jwk_dict(self["jwk"])
            self.key.deserialize()

    def from_dict(self, dictionary, **kwargs):
        Message.from_dict(self, dictionary, **kwargs)

        if "jwk" in self:
            self.key = key_from_jwk_dict(self["jwk"])
            self.key.deserialize()

        return self

    def verify(self, **kwargs):
        Message.verify(self, **kwargs)
        if self["typ"] != "dpop+jwt":
            raise ValueError("Wrong type")
        if self["alg"] == "none":
            raise ValueError("'none' is not allowed as signing algorithm")

    def create_header(self) -> str:
        payload = {k: self[k] for k in self.body_params}
        _jws = JWS(payload, alg=self["alg"])
        _headers = {k: self[k] for k in self.header_params}
        self.key.kid = ""
        _sjwt = _jws.sign_compact(keys=[self.key], **_headers)
        return _sjwt

    def verify_header(self, dpop_header) -> Optional["DPoPProof"]:
        _jws = factory(dpop_header)
        if _jws:
            _jwt = _jws.jwt
            if "jwk" in _jwt.headers:
                _pub_key = key_from_jwk_dict(_jwt.headers["jwk"])
                _pub_key.deserialize()
                _info = _jws.verify_compact(keys=[_pub_key], sigalg=_jwt.headers["alg"])
                for k, v in _jwt.headers.items():
                    self[k] = v

                for k, v in _info.items():
                    self[k] = v
            else:
                raise Exception()

            return self
        else:
            return None


def post_parse_request(request, client_id, endpoint_context, **kwargs):
    """
    Expect http_info attribute in kwargs. http_info should be a dictionary
    containing HTTP information.

    :param request:
    :param client_id:
    :param endpoint_context:
    :param kwargs:
    :return:
    """

    _http_info = kwargs.get("http_info")
    if not _http_info:
        return request

    _dpop = DPoPProof().verify_header(_http_info["headers"]["dpop"])

    # The signature of the JWS is verified, now for checking the
    # content

    if _dpop["htu"] != _http_info["url"]:
        raise ValueError("htu in DPoP does not match the HTTP URI")

    if _dpop["htm"] != _http_info["method"]:
        raise ValueError("htm in DPoP does not match the HTTP method")

    if not _dpop.key:
        _dpop.key = key_from_jwk_dict(_dpop["jwk"])

    # Need something I can add as a reference when minting tokens
    request["dpop_jkt"] = as_unicode(_dpop.key.thumbprint("SHA-256"))
    return request


def token_args(endpoint_context, client_id, token_args: Optional[dict] = None):
    dpop_jkt = endpoint_context.cdb[client_id]["dpop_jkt"]
    _jkt = list(dpop_jkt.keys())[0]
    if "dpop_jkt" in endpoint_context.cdb[client_id]:
        if token_args is None:
            token_args = {"cnf": {"jkt": _jkt}}
        else:
            token_args.update({"cnf": {"jkt": endpoint_context.cdb[client_id]["dpop_jkt"]}})

    return token_args


def add_support(endpoint, **kwargs):
    #
    _token_endp = endpoint["token"]
    _token_endp.post_parse_request.append(post_parse_request)

    # Endpoint Context stuff
    # _endp.endpoint_context.token_args_methods.append(token_args)
    _algs_supported = kwargs.get("dpop_signing_alg_values_supported")
    if not _algs_supported:
        _algs_supported = ["RS256"]

    _token_endp.server_get("endpoint_context").provider_info[
        "dpop_signing_alg_values_supported"
    ] = _algs_supported

    _endpoint_context = _token_endp.server_get("endpoint_context")
    _endpoint_context.dpop_enabled = True


# DPoP-bound access token in the "Authorization" header and the DPoP proof in the "DPoP" header


class DPoPClientAuth(ClientAuthnMethod):
    tag = "dpop_client_auth"

    def is_usable(self, request=None, authorization_info=None, http_headers=None):
        if authorization_info is not None and authorization_info.startswith("DPoP "):
            return True
        return False

    def verify(self, authorization_info, **kwargs):
        client_info = basic_authn(authorization_info)
        _context = self.server_get("endpoint_context")
        if _context.cdb[client_info["id"]]["client_secret"] == client_info["secret"]:
            return {"client_id": client_info["id"]}
        else:
            raise AuthnFailure()
