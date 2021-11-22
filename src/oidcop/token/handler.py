import logging
import os
from typing import Optional
import warnings

from cryptojwt.exception import Invalid
from cryptojwt.key_jar import init_key_jar
from cryptojwt.utils import as_unicode
from oidcmsg.impexp import ImpExp
from oidcmsg.item import DLDict

from oidcop.token import DefaultToken
from oidcop.token import Token
from oidcop.token import UnknownToken
from oidcop.token.exception import TokenException
from oidcop.util import importer

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)


class TokenHandler(ImpExp):
    parameter = {"handler": DLDict, "handler_order": [""]}

    def __init__(
        self,
        access_token: Optional[Token] = None,
        authorization_code: Optional[Token] = None,
        refresh_token: Optional[Token] = None,
        id_token: Optional[Token] = None,
    ):
        ImpExp.__init__(self)
        self.handler = {"authorization_code": authorization_code, "access_token": access_token}

        self.handler_order = ["authorization_code", "access_token"]

        if refresh_token:
            self.handler["refresh_token"] = refresh_token
            self.handler_order.append("refresh_token")

        if id_token:
            self.handler["id_token"] = id_token
            self.handler_order.append("id_token")

    def __getitem__(self, typ):
        return self.handler[typ]

    def __contains__(self, item):
        return item in self.handler

    def info(self, item, order=None):
        _handler, item_info = self.get_handler(item, order)

        if _handler is None:
            logger.info("Unknown token format")
            raise UnknownToken(item)
        else:
            return item_info

    def sid(self, token, order=None):
        return self.info(token, order)["sid"]

    def token_class(self, token, order=None):
        return self.info(token, order)["token_class"]

    def get_handler(self, token, order=None):
        if order is None:
            order = self.handler_order

        for typ in order:
            try:
                res = self.handler[typ].info(token)
            except (KeyError, TokenException, Invalid, AttributeError):
                pass
            else:
                return self.handler[typ], res

        return None, None

    def keys(self):
        return self.handler.keys()


def init_token_handler(server_get, spec, token_class):
    _kwargs = spec.get("kwargs", {})

    _lt = spec.get("lifetime")
    if _lt:
        _kwargs["lifetime"] = _lt

    try:
        _cls = spec["class"]
    except KeyError:
        cls = DefaultToken
        _pw = spec.get("password")
        if _pw is not None:
            _kwargs["password"] = _pw
    else:
        cls = importer(_cls)

    if _kwargs is None:
        if cls != DefaultToken:
            warnings.warn(
                "Token initialisation arguments should be grouped under 'kwargs'.",
                DeprecationWarning,
                stacklevel=2,
            )
        _kwargs = spec

    return cls(token_class=token_class, server_get=server_get, **_kwargs)


def _add_passwd(keyjar, conf, kid):
    if keyjar:
        _keys = keyjar.get_encrypt_key(key_type="oct", kid=kid)
        if _keys:
            pw = as_unicode(_keys[0].k)
            if "kwargs" in conf:
                conf["kwargs"]["password"] = pw
            else:
                conf["password"] = pw


def is_defined(key_defs, kid):
    for _def in key_defs:
        if _def["kid"] == kid:
            return True

    return False


def default_token(spec):
    if "class" not in spec or spec["class"] in ["oidcop.token.DefaultToken", DefaultToken]:
        return True
    else:
        return False


JWKS_FILE = "private/token_jwks.json"


def factory(
    server_get,
    code: Optional[dict] = None,
    token: Optional[dict] = None,
    refresh: Optional[dict] = None,
    id_token: Optional[dict] = None,
    jwks_file: Optional[str] = "",
    **kwargs
) -> TokenHandler:
    """
    Create a token handler

    :param code:
    :param token:
    :param refresh:
    :param jwks_file:
    :return: TokenHandler instance
    """

    token_class_map = {
        "code": "authorization_code",
        "token": "access_token",
        "refresh": "refresh_token",
        "idtoken": "id_token",
    }

    key_defs = []
    read_only = False
    cwd = server_get("endpoint_context").cwd
    if kwargs.get("jwks_def"):
        defs = kwargs["jwks_def"]
        if not jwks_file:
            jwks_file = defs.get("private_path", os.path.join(cwd, JWKS_FILE))
        read_only = defs.get("read_only", read_only)
        key_defs = defs.get("key_defs", [])

    if not jwks_file:
        jwks_file = os.path.join(cwd, JWKS_FILE)

    if not key_defs:
        for kid, cnf in [("code", code), ("refresh", refresh), ("token", token)]:
            if cnf is not None:
                if default_token(cnf):
                    key_defs.append({"type": "oct", "bytes": 24, "use": ["enc"], "kid": kid})

    kj = init_key_jar(key_defs=key_defs, private_path=jwks_file, read_only=read_only)

    args = {}
    for cls, cnf, attr in [
        ("code", code, "authorization_code"),
        ("token", token, "access_token"),
        ("refresh", refresh, "refresh_token"),
    ]:
        if cnf is not None:
            if default_token(cnf):
                _add_passwd(kj, cnf, cls)
            args[attr] = init_token_handler(server_get, cnf, token_class_map[cls])

    if id_token is not None:
        args["id_token"] = init_token_handler(server_get, id_token, token_class="")

    return TokenHandler(**args)
