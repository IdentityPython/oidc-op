import base64
import logging
from typing import Callable
from typing import Optional
from typing import Union
from urllib.parse import unquote_plus

from cryptojwt.exception import BadSignature
from cryptojwt.exception import Invalid
from cryptojwt.exception import MissingKey
from cryptojwt.jwt import JWT
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode
from oidcmsg.message import Message
from oidcmsg.oidc import JsonWebToken
from oidcmsg.oidc import verified_claim_name

from oidcop import JWT_BEARER
from oidcop import sanitize
from oidcop.endpoint_context import EndpointContext
from oidcop.exception import BearerTokenAuthenticationError
from oidcop.exception import InvalidClient
from oidcop.exception import MultipleUsage
from oidcop.exception import NotForMe
from oidcop.exception import ToOld
from oidcop.exception import UnknownClient
from oidcop.util import importer

logger = logging.getLogger(__name__)

__author__ = "roland hedberg"


class AuthnFailure(Exception):
    pass


class NoMatchingKey(Exception):
    pass


class UnknownOrNoAuthnMethod(Exception):
    pass


class WrongAuthnMethod(Exception):
    pass


class ClientAuthnMethod(object):
    def __init__(self, server_get):
        """
        :param server_get: A method that can be used to get general server information.
        """
        self.server_get = server_get

    def verify(self, **kwargs):
        """
        Verify authentication information in a request
        :param kwargs:
        :return:
        """
        raise NotImplementedError()

    def is_usable(self, request=None, authorization_info=None):
        """
        Verify that this authentication method is applicable.

        :param request: The request
        :param authorization_info: Other authorization information
        :return: True/False
        """
        raise NotImplementedError()


def basic_authn(authorization_token):
    if not authorization_token.startswith("Basic "):
        raise AuthnFailure("Wrong type of authorization token")

    _tok = as_bytes(authorization_token[6:])
    # Will raise ValueError type exception if not base64 encoded
    _tok = base64.b64decode(_tok)
    part = [unquote_plus(p) for p in as_unicode(_tok).split(":")]
    if len(part) == 2:
        return dict(zip(["id", "secret"], part))
    else:
        raise ValueError("Illegal token")


class ClientSecretBasic(ClientAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] using HTTP Basic authentication scheme.
    """

    tag = "client_secret_basic"

    def is_usable(self, request=None, authorization_token=None):
        if authorization_token is not None and authorization_token.startswith("Basic "):
            return True
        return False

    def verify(self, authorization_token, **kwargs):
        client_info = basic_authn(authorization_token)

        if (
            self.server_get("endpoint_context").cdb[client_info["id"]]["client_secret"]
            == client_info["secret"]
        ):
            return {"client_id": client_info["id"]}
        else:
            raise AuthnFailure()


class ClientSecretPost(ClientSecretBasic):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] by including the Client Credentials in
    the request body.
    """

    tag = "client_secret_post"

    def is_usable(self, request=None, authorization_token=None):
        if request is None:
            return False
        if "client_id" in request and "client_secret" in request:
            return True
        return False

    def verify(self, request, **kwargs):
        if (
            self.server_get("endpoint_context").cdb[request["client_id"]]["client_secret"]
            == request["client_secret"]
        ):
            return {"client_id": request["client_id"]}
        else:
            raise AuthnFailure("secrets doesn't match")


class BearerHeader(ClientSecretBasic):
    """"""

    tag = "bearer_header"

    def is_usable(self, request=None, authorization_token=None):
        if authorization_token is not None and authorization_token.startswith("Bearer "):
            return True
        return False

    def verify(self, authorization_token, **kwargs):
        return {"token": authorization_token.split(" ", 1)[1]}


class BearerBody(ClientSecretPost):
    """
    Same as Client Secret Post
    """

    tag = "bearer_body"

    def is_usable(self, request=None, authorization_token=None):
        if request is not None and "access_token" in request:
            return True
        return False

    def verify(self, request, **kwargs):
        _token = request.get("access_token")
        if _token is None:
            raise AuthnFailure("No access token")

        res = {"token": _token}
        _client_id = request.get("client_id")
        if _client_id:
            res["client_id"] = _client_id
        return res


class JWSAuthnMethod(ClientAuthnMethod):
    def is_usable(self, request=None, authorization_token=None):
        if request is None:
            return False
        if "client_assertion" in request:
            return True
        return False

    def verify(self, request, key_type, **kwargs):
        _context = self.server_get("endpoint_context")
        _jwt = JWT(_context.keyjar, msg_cls=JsonWebToken)
        try:
            ca_jwt = _jwt.unpack(request["client_assertion"])
        except (Invalid, MissingKey, BadSignature) as err:
            logger.info("%s" % sanitize(err))
            raise AuthnFailure("Could not verify client_assertion.")

        _sign_alg = ca_jwt.jws_header.get("alg")
        if _sign_alg and _sign_alg.startswith("HS"):
            if key_type == "private_key":
                raise AttributeError("Wrong key type")
            keys = _context.keyjar.get("sig", "oct", ca_jwt["iss"], ca_jwt.jws_header.get("kid"))
            _secret = _context.cdb[ca_jwt["iss"]].get("client_secret")
            if _secret and keys[0].key != as_bytes(_secret):
                raise AttributeError("Oct key used for signing not client_secret")
        else:
            if key_type == "client_secret":
                raise AttributeError("Wrong key type")

        authtoken = sanitize(ca_jwt.to_dict())
        logger.debug("authntoken: {}".format(authtoken))

        _endpoint = kwargs.get("endpoint")
        if _endpoint is None or not _endpoint:
            if _context.issuer in ca_jwt["aud"]:
                pass
            else:
                raise NotForMe("Not for me!")
        else:
            if set(ca_jwt["aud"]).intersection(_endpoint.allowed_target_uris()):
                pass
            else:
                raise NotForMe("Not for me!")

        # If there is a jti use it to make sure one-time usage is true
        _jti = ca_jwt.get("jti")
        if _jti:
            _key = "{}:{}".format(ca_jwt["iss"], _jti)
            if _key in _context.jti_db:
                raise MultipleUsage("Have seen this token once before")
            else:
                _context.jti_db[_key] = utc_time_sans_frac()

        request[verified_claim_name("client_assertion")] = ca_jwt
        client_id = kwargs.get("client_id") or ca_jwt["iss"]

        return {"client_id": client_id, "jwt": ca_jwt}


class ClientSecretJWT(JWSAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server create a JWT using an HMAC SHA algorithm, such as HMAC SHA-256.
    The HMAC (Hash-based Message Authentication Code) is calculated using the
    bytes of the UTF-8 representation of the client_secret as the shared key.
    """

    tag = "client_secret_jwt"

    def verify(self, request=None, **kwargs):
        res = JWSAuthnMethod.verify(self, request, key_type="client_secret", **kwargs)
        # Verify that a HS alg was used
        res["method"] = self.tag
        return res


class PrivateKeyJWT(JWSAuthnMethod):
    """
    Clients that have registered a public key sign a JWT using that key.
    """

    tag = "private_key_jwt"

    def verify(self, request=None, **kwargs):
        res = JWSAuthnMethod.verify(self, request, key_type="private_key", **kwargs)
        # Verify that an RS or ES alg was used ?
        res["method"] = self.tag
        return res


class RequestParam(ClientAuthnMethod):
    tag = "request_param"

    def is_usable(self, request=None, authorization_info=None):
        if request and "request" in request:
            return True

    def verify(self, request=None, **kwargs):
        _context = self.server_get("endpoint_context")
        _jwt = JWT(_context.keyjar, msg_cls=JsonWebToken)
        try:
            _jwt = _jwt.unpack(request["request"])
        except (Invalid, MissingKey, BadSignature) as err:
            logger.info("%s" % sanitize(err))
            raise AuthnFailure("Could not verify client_assertion.")

        # If there is a jti use it to make sure one-time usage is true
        _jti = _jwt.get("jti")
        if _jti:
            _key = "{}:{}".format(_jwt["iss"], _jti)
            if _key in _context.jti_db:
                raise MultipleUsage("Have seen this token once before")
            else:
                _context.jti_db[_key] = utc_time_sans_frac()

        request[verified_claim_name("client_assertion")] = _jwt
        client_id = kwargs.get("client_id") or _jwt["iss"]

        return {"client_id": client_id, "jwt": _jwt}


CLIENT_AUTHN_METHOD = {
    "client_secret_basic": ClientSecretBasic,
    "client_secret_post": ClientSecretPost,
    "bearer_header": BearerHeader,
    "bearer_body": BearerBody,
    "client_secret_jwt": ClientSecretJWT,
    "private_key_jwt": PrivateKeyJWT,
    "request_param": RequestParam,
    "none": None,
}

TYPE_METHOD = [(JWT_BEARER, JWSAuthnMethod)]


def valid_client_info(cinfo):
    eta = cinfo.get("client_secret_expires_at", 0)
    if eta != 0 and eta < utc_time_sans_frac():
        return False
    return True


def verify_client(
    endpoint_context: EndpointContext,
    request: Union[dict, Message],
    http_info: Optional[dict] = None,
    get_client_id_from_token: Optional[Callable] = None,
    endpoint=None,  # Optional[Endpoint]
    also_known_as: Optional[str] = None,
):
    """
    Initiated Guessing !

    :param also_known_as:
    :param endpoint: Endpoint instance
    :param endpoint_context: EndpointContext instance
    :param request: The request
    :param http_info: Client authentication information
    :param get_client_id_from_token: Function that based on a token returns a client id.
    :return: dictionary containing client id, client authentication method and
        possibly access token.
    """

    if http_info and "headers" in http_info:
        authorization_token = http_info["headers"].get("authorization")
    else:
        authorization_token = None

    auth_info = {}
    _methods = getattr(endpoint, "client_authn_method", [])

    for _method in _methods:
        if _method is None:
            continue
        if _method.is_usable(request, authorization_token):
            try:
                auth_info = _method.verify(
                    request=request,
                    authorization_token=authorization_token,
                    endpoint=endpoint,
                )
            except Exception as err:
                logger.warning("Verifying auth using {} failed: {}".format(_method.tag, err))
            else:
                if "method" not in auth_info:
                    auth_info["method"] = _method.tag
                break

    if not auth_info:
        if None in _methods:
            auth_info = {"method": "none", "client_id": request.get("client_id")}
        else:
            return auth_info

    if also_known_as:
        client_id = also_known_as[auth_info.get("client_id")]
        auth_info["client_id"] = client_id
    else:
        client_id = auth_info.get("client_id")

    _token = auth_info.get("token")

    if client_id:
        if client_id not in endpoint_context.cdb:
            raise UnknownClient("Unknown Client ID")

        _cinfo = endpoint_context.cdb[client_id]
        if isinstance(_cinfo, str):
            if _cinfo not in endpoint_context.cdb:
                raise UnknownClient("Unknown Client ID")

        if not valid_client_info(_cinfo):
            logger.warning("Client registration has timed out or " "client secret is expired.")
            raise InvalidClient("Not valid client")

        # store what authn method was used
        if auth_info.get("method"):
            _request_type = request.__class__.__name__
            _used_authn_method = endpoint_context.cdb[client_id].get("auth_method")
            if _used_authn_method:
                endpoint_context.cdb[client_id]["auth_method"][_request_type] = auth_info["method"]
            else:
                endpoint_context.cdb[client_id]["auth_method"] = {
                    _request_type: auth_info["method"]
                }
    elif not client_id and get_client_id_from_token:
        if not _token:
            logger.warning("No token")
            raise BearerTokenAuthenticationError("No token")

        try:
            # get_client_id_from_token is a callback... Do not abuse for code readability.
            auth_info["client_id"] = get_client_id_from_token(endpoint_context, _token, request)
        except ToOld:
            raise BearerTokenAuthenticationError("Expired token")
        except KeyError:
            raise BearerTokenAuthenticationError("Unknown token")

    return auth_info


def client_auth_setup(auth_set, server_get):
    res = []

    for item in auth_set:
        if item is None or item.lower() == "none":
            res.append(None)
        else:
            _cls = CLIENT_AUTHN_METHOD.get(item)
            if _cls:
                res.append(_cls(server_get))
            else:
                res.append(importer(item)(server_get))

    return res
