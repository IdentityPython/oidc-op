import base64
import logging
from typing import Optional

from oidcmsg.time_util import utc_time_sans_frac

from oidcop import rndstr
from oidcop.token.exception import UnknownToken
from oidcop.token.exception import WrongTokenClass
from oidcop.util import Crypt
from oidcop.util import lv_pack
from oidcop.util import lv_unpack

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)

ALT_TOKEN_NAME = {
    "authorization_code": "A",
    "access_token": "T",
    "refresh_token": "R",
    "id_token": "I",
}


def is_expired(exp, when=0):
    if exp < 0:
        return False

    if not when:
        when = utc_time_sans_frac()
    return when > exp


class Token(object):
    def __init__(self, token_class, lifetime=300, **kwargs):
        self.token_class = token_class
        try:
            self.alt_token_name = ALT_TOKEN_NAME[token_class]
        except KeyError:
            self.alt_token_name = ""

        self.lifetime = lifetime
        self.kwargs = kwargs

    def __call__(self, session_id: Optional[str] = "", ttype: Optional[str] = "", **payload) -> str:
        """
        Return a token.

        :param payload: Information to place in the token if possible.
        :return:
        """
        raise NotImplementedError()

    def info(self, token):
        """
        Return dictionary with token information.

        :param token: A token
        :return: Dictionary with information about the token
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
    def __init__(self, password, token_class="", token_type="Bearer", **kwargs):
        Token.__init__(self, token_class, **kwargs)
        self.crypt = Crypt(password)
        self.token_type = token_type

    def __call__(
        self, session_id: Optional[str] = "", token_class: Optional[str] = "", **payload
    ) -> str:
        """
        Return a token.

        :param payload: Token information
        :return:
        """
        if not token_class and self.token_class:
            token_class = self.token_class
        else:
            token_class = "authorization_code"

        if self.lifetime >= 0:
            exp = str(utc_time_sans_frac() + self.lifetime)
        else:
            exp = "-1"  # Live for ever

        tmp = ""
        rnd = ""
        while rnd == tmp:  # Don't use the same random value again
            rnd = rndstr(32)  # Ultimate length multiple of 16

        return base64.b64encode(
            self.crypt.encrypt(lv_pack(rnd, token_class, session_id, exp).encode())
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
        _res = dict(zip(["_id", "token_class", "sid", "exp"], self.split_token(token)))
        if _res["token_class"] not in [self.token_class, self.alt_token_name]:
            raise WrongTokenClass(_res["token_class"])
        else:
            _res["token_class"] = self.token_class
            _res["handler"] = self
            return _res

    def is_expired(self, token: str, when: int = 0):
        _exp = self.info(token)["exp"]
        if _exp == "-1":
            return False
        else:
            exp = int(_exp)
        return is_expired(exp, when)
