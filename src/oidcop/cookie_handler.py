import base64
import hashlib
import logging
import os
import time
from typing import List
from typing import Optional
from typing import Union
from urllib.parse import urlparse

from cryptography.exceptions import InvalidTag
from cryptojwt.exception import VerificationError
from cryptojwt.jwe.aes import AES_GCMEncrypter
from cryptojwt.jwe.utils import split_ctx_and_tag
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jws.hmac import HMACSigner
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.key_jar import init_key_jar
from oidcmsg.time_util import epoch_in_a_while

from oidcop.util import lv_pack
from oidcop.util import lv_unpack

__author__ = "Roland Hedberg"

LOGGER = logging.getLogger(__name__)


# The only thing I want to be able to do is to set names, values, expires and max-age on cookies.
# I don't care about the remaining attributes of a cookie.


class CookieHandler:
    def __init__(
            self,
            sign_key: Optional[SYMKey] = None,
            enc_key: Optional[SYMKey] = None,
            keys: Optional[dict] = None,
            sign_alg: [str] = "SHA256",
            name: Optional[dict] = None,
            **kwargs,
    ):

        if keys:
            key_jar = init_key_jar(**keys)
            _keys = key_jar.get_signing_key(key_type="oct", kid="sig")
            if _keys:
                self.sign_key = _keys[0]
            _keys = key_jar.get_encrypt_key(key_type="oct", kid="enc")
            if _keys:
                self.enc_key = _keys[0]
        else:
            if sign_key:
                if isinstance(sign_key, SYMKey):
                    self.sign_key = sign_key
                else:
                    self.sign_key = SYMKey(k=sign_key)
            else:
                self.sign_key = None

            if enc_key:
                if isinstance(enc_key, SYMKey):
                    self.enc_key = enc_key
                else:
                    self.enc_key = SYMKey(k=enc_key)
            else:
                self.enc_key = None

        self.sign_alg = sign_alg

        self.time_format = "%a, %d-%b-%Y %H:%M:%S GMT"

        if name is None:
            self.name = {
                "session": "oidc_op",
                "register": "oidc_op_reg",
                "session_management": "oidc_op_sman",
            }
        else:
            self.name = name

        self.flags = kwargs.get(
            "flags",
            {
                "samesite": "None",
                "httponly": True,
                "secure": True,
            },
        )

    def _sign_enc_payload(self, payload: str, timestamp: Optional[Union[int, str]] = 0):
        """
        Creates signed and/or encrypted information.

        :param load: The basic information in the payload
        :param timestamp: A timestamp (seconds since epoch)
        :return: Signed and/or encrypted payload
        """

        # Just sign, sign and encrypt or just encrypt

        if timestamp:
            timestamp = str(timestamp)
        else:
            timestamp = str(int(utc_time_sans_frac()))

        bytes_load = payload.encode("utf-8")
        bytes_timestamp = timestamp.encode("utf-8")

        if self.sign_key:
            signer = HMACSigner(algorithm=self.sign_alg)
            mac = signer.sign(bytes_load + bytes_timestamp, self.sign_key.key)
        else:
            mac = b""

        if self.enc_key:
            if len(self.enc_key.key) not in [16, 24, 32]:
                raise ValueError("Wrong size of enc_key")

            encrypter = AES_GCMEncrypter(key=self.enc_key.key)
            iv = os.urandom(12)
            if mac:
                msg = lv_pack(payload, timestamp, base64.b64encode(mac).decode("utf-8"))
            else:
                msg = lv_pack(payload, timestamp)

            enc_msg = encrypter.encrypt(msg.encode("utf-8"), iv)
            ctx, tag = split_ctx_and_tag(enc_msg)

            cookie_payload = [
                bytes_timestamp,
                base64.b64encode(iv),
                base64.b64encode(ctx),
                base64.b64encode(tag),
            ]
        else:
            cookie_payload = [bytes_timestamp, bytes_load, base64.b64encode(mac)]

        return (b"|".join(cookie_payload)).decode("utf-8")

    def _ver_dec_content(self, parts):
        """
        Verifies the value of a cookie

        :param parts: The parts of the payload
        :return: A tuple with basic information and a timestamp
        """

        if parts is None:
            return None
        elif len(parts) == 3:
            # verify the cookie signature
            timestamp, payload, b64_mac = parts
            mac = base64.b64decode(b64_mac)
            verifier = HMACSigner(algorithm=self.sign_alg)
            if verifier.verify(
                    payload.encode("utf-8") + timestamp.encode("utf-8"),
                    mac,
                    self.sign_key.key,
            ):
                return payload, timestamp
            else:
                raise VerificationError()
        elif len(parts) == 4:
            iv = base64.b64decode(parts[1])
            ciphertext = base64.b64decode(parts[2])
            tag = base64.b64decode(parts[3])

            decrypter = AES_GCMEncrypter(key=self.enc_key.key)
            try:
                msg = decrypter.decrypt(ciphertext, iv, tag=tag)
            except InvalidTag:
                LOGGER.debug("Decryption failed")
                return None

            p = lv_unpack(msg.decode("utf-8"))
            payload = p[0]
            timestamp = p[1]
            if len(p) == 3:
                verifier = HMACSigner(algorithm=self.sign_alg)
                if verifier.verify(
                        payload.encode("utf-8") + timestamp.encode("utf-8"),
                        base64.b64decode(p[2]),
                        self.sign_key.key,
                ):
                    return payload, timestamp
                else:
                    LOGGER.debug("Could not verify signature")
            else:
                return payload, timestamp
        return None

    def make_cookie_content(
            self,
            name: str,
            value: str,
            typ: Optional[str] = "",
            timestamp: Optional[Union[int, str]] = "",
            max_age: Optional[int] = 0,
            **kwargs,
    ) -> dict:
        """
        Create and return information to put in a cookie

        :param typ: The type of cookie
        :param name: Cookie name
        :param value: Cookie value
        :param timestamp: A time stamp
        :param max_age: The time in seconds for when a cookie will be deleted
        :return: A dictionary
        """

        if not timestamp:
            timestamp = str(int(utc_time_sans_frac()))

        # create cookie payload
        if not value and not typ:
            _cookie_value = ""
        else:
            try:
                cookie_payload = "::".join([value, typ])
            except TypeError:
                cookie_payload = "::".join([value[0], typ])

            _cookie_value = self._sign_enc_payload(cookie_payload, timestamp)

        content = {"name": name, "value": _cookie_value}

        if max_age == -1:
            content["expires"] = "Thu, 01 Jan 1970 00:00:00 GMT;"
        elif max_age:
            content["max-age"] = epoch_in_a_while(seconds=max_age)

        for k, v in self.flags.items():
            content[k] = v

        return content

    def parse_cookie(self, name: str, cookies: List[dict]) -> Optional[List[dict]]:
        """Parses and verifies a cookie value

        Parses a cookie created by `make_cookie` and verifies
        it has not been tampered with.

        You need to provide the same `sign_key` and `enc_key`
        used when creating the cookie, otherwise the verification
        fails. See `make_cookie` for details about the verification.

        :param kakor: A list of dictionaries with cookie information
        :raises InvalidCookieSign: When verification fails.
        :return: A list of dictionaries with information from the cookie or None if parsing fails
        """
        if not cookies:
            return None

        LOGGER.debug("Looking for '{}' cookies".format(name))
        res = []
        for _cookie in cookies:
            LOGGER.debug("Cookie: {}".format(_cookie))
            if "name" in _cookie and _cookie["name"] == name:
                _content = self._ver_dec_content(_cookie["value"].split("|"))
                if _content:
                    payload, timestamp = self._ver_dec_content(_cookie["value"].split("|"))
                    value, typ = payload.split("::")
                    res.append({"value": value, "type": typ, "timestamp": timestamp})
                else:
                    LOGGER.debug(f"Could not verify {name} cookie")
        return res


def compute_session_state(opbs, salt, client_id, redirect_uri):
    """
    Computes a session state value.
    This value is later used during session management to check whether
    the log in state has changed.

    :param opbs: Cookie value
    :param salt:
    :param client_id:
    :param redirect_uri:
    :return: Session state value
    """
    parsed_uri = urlparse(redirect_uri)
    rp_origin_url = "{uri.scheme}://{uri.netloc}".format(uri=parsed_uri)
    session_str = client_id + " " + rp_origin_url + " " + opbs + " " + salt
    return hashlib.sha256(session_str.encode("utf-8")).hexdigest() + "." + salt
