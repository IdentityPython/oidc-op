import logging
import warnings

from cryptography.fernet import InvalidToken
from cryptojwt.exception import Invalid
from cryptojwt.key_jar import init_key_jar
from cryptojwt.utils import as_unicode
from oidcmsg.impexp import ImpExp
from oidcmsg.item import DLDict

from oidcop.token import DefaultToken
from oidcop.token import UnknownToken
from oidcop.token import WrongTokenType
from oidcop.util import importer

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)


class TokenHandler(ImpExp):
    parameter = {
        "handler": DLDict,
        "handler_order": [""]
    }

    def __init__(
            self, access_token_handler=None, code_handler=None, refresh_token_handler=None
    ):
        ImpExp.__init__(self)
        self.handler = {"code": code_handler,
                        "access_token": access_token_handler}

        self.handler_order = ["code", "access_token"]

        if refresh_token_handler:
            self.handler["refresh_token"] = refresh_token_handler
            self.handler_order.append("refresh_token")

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

    def type(self, token, order=None):
        return self.info(token, order)["type"]

    def get_handler(self, token, order=None):
        if order is None:
            order = self.handler_order

        for typ in order:
            try:
                res = self.handler[typ].info(token)
            except (KeyError, WrongTokenType, InvalidToken, UnknownToken, Invalid):
                pass
            else:
                return self.handler[typ], res

        return None, None

    def keys(self):
        return self.handler.keys()


def init_token_handler(server_get, spec, typ):
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

    return cls(typ=typ, server_get=server_get, **_kwargs)


def _add_passwd(keyjar, conf, kid):
    if keyjar:
        _keys = keyjar.get_encrypt_key(key_type="oct", kid=kid)
        if _keys:
            pw = as_unicode(_keys[0].k)
            if "kwargs" in conf:
                conf["kwargs"]["password"] = pw
            else:
                conf["password"] = pw


def factory(server_get, code=None, token=None, refresh=None, jwks_def=None, **kwargs):
    """
    Create a token handler

    :param code:
    :param token:
    :param refresh:
    :param jwks_def:
    :return: TokenHandler instance
    """

    TTYPE = {"code": "A", "token": "T", "refresh": "R"}

    if jwks_def:
        kj = init_key_jar(**jwks_def)
    else:
        kj = None

    args = {}

    if code:
        _add_passwd(kj, code, "code")
        args["code_handler"] = init_token_handler(
            server_get, code, TTYPE["code"])

    if token:
        _add_passwd(kj, token, "token")
        args["access_token_handler"] = init_token_handler(
            server_get, token, TTYPE["token"])

    if refresh is not None:
        _add_passwd(kj, refresh, "refresh")
        args["refresh_token_handler"] = init_token_handler(
            server_get, refresh, TTYPE["refresh"]
        )

    return TokenHandler(**args)