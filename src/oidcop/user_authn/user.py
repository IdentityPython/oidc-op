# coding=utf-8
import base64
import inspect
import json
import logging
import sys
from typing import List
from urllib.parse import unquote
import warnings

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptojwt.jwt import JWT
from oidcmsg.time_util import utc_time_sans_frac

from oidcop.exception import FailedAuthentication
from oidcop.exception import ImproperlyConfigured
from oidcop.exception import OnlyForTestingWarning
from oidcop.util import instantiate

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)

LOC = {
    "en": {
        "title": "User log in",
        "login_title": "Username",
        "passwd_title": "Password",
        "submit_text": "Submit",
        "client_policy_title": "Client Policy",
    },
    "se": {
        "title": "Logga in",
        "login_title": "Användarnamn",
        "passwd_title": "Lösenord",
        "submit_text": "Sänd",
        "client_policy_title": "Klientens sekretesspolicy",
    },
}


class UserAuthnMethod(object):
    # override in subclass specifying suitable url endpoint to POST user input
    url_endpoint = "/verify"
    FAILED_AUTHN = (None, True)

    def __init__(self, server_get=None, **kwargs):
        self.query_param = "upm_answer"
        self.server_get = server_get
        self.kwargs = kwargs

    def __call__(self, **kwargs):
        """
        Display user interaction.

        :param args:
        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def authenticated_as(self, client_id, cookie=None, **kwargs):
        if cookie is None:
            return None, 0
        else:
            _info = self.cookie_info(cookie, client_id)
            logger.debug("authenticated_as: cookie info={}".format(_info))
            if _info:
                if "max_age" in kwargs and kwargs["max_age"] != 0:
                    _max_age = kwargs["max_age"]
                    _now = utc_time_sans_frac()
                    if _now > _info["timestamp"] + _max_age:
                        logger.debug(
                            "Too old by {} seconds".format(_now - (_info["timestamp"] + _max_age))
                        )
                        return None, 0
            return _info, utc_time_sans_frac()

    def verify(self, *args, **kwargs):
        """
        Callback to verify user input
        :return: username of the authenticated user
        """
        raise NotImplementedError

    def unpack_token(self, token):
        return verify_signed_jwt(token=token, keyjar=self.server_get("endpoint_context").keyjar)

    def done(self, areq):
        """

        :param areq: Authentication request
        :return: True if the 'query_parameter' doesn't appear in the request
        """
        try:
            _ = areq[self.query_param]
        except KeyError:
            return True
        else:
            return False

    def cookie_info(self, cookie: List[dict], client_id: str) -> dict:
        _context = self.server_get("endpoint_context")
        logger.debug("Value cookies: {}".format(cookie))

        if cookie is None:
            pass
        else:
            for val in cookie:
                _info = json.loads(val["value"])
                _info["timestamp"] = int(val["timestamp"])
                session_id = _context.session_manager.decrypt_session_id(_info["sid"])
                logger.debug("cookie_info: session id={}".format(session_id))
                # _, cid, _ = _context.session_manager.decrypt_session_id(_info["sid"])
                if session_id[1] != client_id:
                    continue
                else:
                    _info["uid"] = session_id[0]
                    _info["grant_id"] = session_id[2]
                    return _info
        return {}


def create_signed_jwt(issuer, keyjar, sign_alg="RS256", **kwargs):
    signer = JWT(keyjar, iss=issuer, sign_alg=sign_alg)
    return signer.pack(payload=kwargs)


def verify_signed_jwt(token, keyjar, allowed_sign_algs=None):
    verifier = JWT(keyjar, allowed_sign_algs=allowed_sign_algs)
    return verifier.unpack(token)


LABELS = {"tos_uri": "Terms of Service", "policy_uri": "Service policy", "logo_uri": ""}


class UserPassJinja2(UserAuthnMethod):
    url_endpoint = "/verify/user_pass_jinja"

    def __init__(
        self,
        db,
        template_handler,
        template="user_pass.jinja2",
        server_get=None,
        verify_endpoint="",
        **kwargs,
    ):

        super(UserPassJinja2, self).__init__(server_get=server_get)
        self.template_handler = template_handler
        self.template = template

        self.action = verify_endpoint or self.url_endpoint

        self.user_db = instantiate(db["class"], **db["kwargs"])

        self.kwargs = kwargs
        self.kwargs.setdefault("page_header", "Log in")
        self.kwargs.setdefault("user_label", "Username")
        self.kwargs.setdefault("passwd_label", "Password")
        self.kwargs.setdefault("submit_btn", "Log in")
        self.kwargs.setdefault("tos_uri", "")
        self.kwargs.setdefault("logo_uri", "")
        self.kwargs.setdefault("policy_uri", "")
        self.kwargs.setdefault("tos_label", "")
        self.kwargs.setdefault("logo_label", "")
        self.kwargs.setdefault("policy_label", "")

    def __call__(self, **kwargs):
        warnings.warn(
            (
                'Do not use the "UserPassJinja2" authentication method in a '
                "production environment"
            ),
            OnlyForTestingWarning,
        )
        if not self.server_get:
            raise Exception(f"{self.__class__.__name__} doesn't have a working server_get")
        _context = self.server_get("endpoint_context")
        # Stores information need afterwards in a signed JWT that then
        # appears as a hidden input in the form
        jws = create_signed_jwt(_context.issuer, _context.keyjar, **kwargs)
        _kwargs = self.kwargs.copy()
        for attr in ["policy", "tos", "logo"]:
            _uri = "{}_uri".format(attr)
            try:
                _kwargs[_uri] = kwargs[_uri]
            except KeyError:
                pass
            else:
                _label = "{}_label".format(attr)
                _kwargs[_label] = LABELS[_uri]

        return self.template_handler.render(self.template, action=self.action, token=jws, **_kwargs)

    def verify(self, *args, **kwargs):
        username = kwargs["username"]
        if username in self.user_db and self.user_db[username] == kwargs["password"]:
            return username
        else:
            raise FailedAuthentication()


class BasicAuthn(UserAuthnMethod):
    def __init__(self, pwd, ttl=5, server_get=None):
        UserAuthnMethod.__init__(self, server_get=server_get)
        self.passwd = pwd
        self.ttl = ttl

    def verify_password(self, user, password):
        if password != self.passwd[user]:
            raise FailedAuthentication("Wrong password")

    def authenticated_as(self, client_id, cookie=None, authorization="", **kwargs):
        """

        :param cookie: A HTTP Cookie
        :param authorization: The HTTP Authorization header
        :param kwargs: extra key word arguments
        :return:
        """
        if authorization.startswith("Basic"):
            authorization = authorization[6:]

        (user, pwd) = base64.b64decode(authorization).split(b":")
        user = unquote(user.decode())
        self.verify_password(user, pwd.decode())
        res = {"uid": user}
        if cookie:
            res.update(self.cookie_info(cookie, client_id))
        return res, utc_time_sans_frac()


class SymKeyAuthn(UserAuthnMethod):
    # user authentication using a token

    def __init__(self, ttl, symkey, server_get=None):
        UserAuthnMethod.__init__(self, server_get=server_get)

        if symkey is not None and symkey == "":
            msg = "SymKeyAuthn.symkey cannot be an empty value"
            raise ImproperlyConfigured(msg)
        self.symkey = symkey.encode() if isinstance(symkey, str) else symkey
        self.ttl = ttl

    def authenticated_as(self, client_id, cookie=None, authorization="", **kwargs):
        """

        :param cookie: A HTTP Cookie
        :param authorization: The HTTP Authorization header
        :param kwargs: extra key word arguments
        :return:
        """
        (encmsg, iv) = base64.b64decode(authorization).split(b":")
        try:
            aesgcm = AESGCM(self.symkey)
            user = aesgcm.decrypt(iv, encmsg, None)
        except (AssertionError, KeyError):  # pragma: no-cover
            raise FailedAuthentication("Decryption failed")

        res = {"uid": user}
        if cookie:
            res.update(self.cookie_info(cookie, client_id))

        return res, utc_time_sans_frac()


class NoAuthn(UserAuthnMethod):
    # Just for testing allows anyone it without authentication

    def __init__(self, user, server_get=None):
        UserAuthnMethod.__init__(self, server_get=server_get)
        self.user = user
        self.fail = None

    def authenticated_as(self, client_id="", cookie=None, authorization="", **kwargs):
        """

        :param cookie: A list of Cookie information
        :param authorization: The HTTP Authorization header
        :param kwargs: extra key word arguments
        :return:
        """
        if self.fail:  # pragma: no-cover
            raise self.fail()

        res = {"uid": self.user}
        if cookie:
            res.update(self.cookie_info(cookie, client_id))

        return res, utc_time_sans_frac()


def factory(cls, **kwargs):
    """
    Factory method that can be used to easily instantiate a class instance

    :param cls: The name of the class
    :param kwargs: Keyword arguments
    :return: An instance of the class or None if the name doesn't match any
        known class.
    """
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, UserAuthnMethod):
            try:
                if obj.__name__ == cls:
                    return obj(**kwargs)
            except AttributeError:
                pass
