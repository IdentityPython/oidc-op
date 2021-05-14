import base64
import logging
from typing import Optional

from oidcmsg.time_util import time_sans_frac

from oidcop import rndstr
from oidcop.token.exception import UnknownToken, WrongTokenType
from oidcop.util import Crypt, lv_pack, lv_unpack

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)


def is_expired(exp, when=0):
    if exp < 0:
        return False

    if not when:
        when = time_sans_frac()
    return when > exp


class Token(object):
    def __init__(self, typ, lifetime=300, **kwargs):
        self.type = typ
        self.lifetime = lifetime
        self.kwargs = kwargs

    def __call__(
        self, session_id: Optional[str] = "", ttype: Optional[str] = "", **payload
    ) -> str:
        """
        Return a token.

        :param payload: Information to place in the token if possible.
        :return:
        """
        raise NotImplementedError()

    def info(self, token):
        """
        Return type of Token (A=Access code, T=Token, R=Refresh token) and
        the session id.

        :param token: A token
        :return: tuple of token type and session id
        """
        raise NotImplementedError()

    def is_expired(self, token, when=0):
        """
        Evaluate whether the token has expired or not

        :param token: The token
        :param when: The time against which to check the expiration
        :return: True/False
        """
        raise NotImplementedError()

    def gather_args(self, *args, **kwargs):
        return {}


class DefaultToken(Token):
    def __init__(self, password, typ="", token_type="Bearer", **kwargs):
        Token.__init__(self, typ, **kwargs)
        self.crypt = Crypt(password)
        self.token_type = token_type

    def __call__(
        self, session_id: Optional[str] = "", ttype: Optional[str] = "", **payload
    ) -> str:
        """
        Return a token.

        :param payload: Token information
        :return:
        """
        if not ttype and self.type:
            ttype = self.type
        else:
            ttype = "A"

        if self.lifetime >= 0:
            exp = str(time_sans_frac() + self.lifetime)
        else:
            exp = "-1"  # Live for ever

        tmp = ""
        rnd = ""
        while rnd == tmp:  # Don't use the same random value again
            rnd = rndstr(32)  # Ultimate length multiple of 16

        return base64.b64encode(
            self.crypt.encrypt(lv_pack(rnd, ttype, session_id, exp).encode())
        ).decode("utf-8")

    def split_token(self, token):
        try:
            plain = self.crypt.decrypt(base64.b64decode(token))
        except Exception as err:
            raise UnknownToken(err)
        # order: rnd, type, sid
        return lv_unpack(plain)

    def info(self, token: str) -> dict:
        """
        Return token information.

        :param token: A token
        :return: dictionary with info about the token
        """
        _res = dict(zip(["_id", "type", "sid", "exp"], self.split_token(token)))
        if _res["type"] != self.type:
            raise WrongTokenType(_res["type"])
        else:
            _res["handler"] = self
            return _res

    def is_expired(self, token: str, when: int = 0):
        _exp = self.info(token)["exp"]
        if _exp == "-1":
            return False
        else:
            exp = int(_exp)
        return is_expired(exp, when)
