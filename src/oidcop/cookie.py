import base64
import hashlib
import json
import logging
import os
import sys
import time
from http.cookies import SimpleCookie
from urllib.parse import urlparse

from cryptography.exceptions import InvalidTag
from cryptojwt import b64d
from cryptojwt.exception import VerificationError
from cryptojwt.jwe.aes import AES_GCMEncrypter
from cryptojwt.jwe.utils import split_ctx_and_tag
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jws.hmac import HMACSigner
from cryptojwt.key_bundle import import_jwk
from cryptojwt.key_bundle import init_key
from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode
from cryptojwt.utils import b64e
from oidcmsg import time_util
from oidcmsg.time_util import in_a_while

from oidcop.util import lv_pack
from oidcop.util import lv_unpack

__author__ = "Roland Hedberg"

LOGGER = logging.getLogger(__name__)

CORS_HEADERS = [
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Methods", "GET"),
    ("Access-Control-Allow-Headers", "Authorization"),
]


def _expiration(timeout, time_format=None):
    """
    Return an expiration time

    :param timeout: When
    :param time_format: The format of the returned value
    :return: A timeout date
    """
    if timeout == "now":
        return time_util.instant(time_format)
    else:
        # validity time should match lifetime of assertions
        return time_util.in_a_while(minutes=timeout, time_format=time_format)


def sign_enc_payload(load, timestamp=0, sign_key=None, enc_key=None, sign_alg="SHA256"):
    """

    :param load: The basic information in the payload
    :param timestamp: A timestamp (seconds since epoch)
    :param sign_key: A :py:class:`cryptojwt.jwk.hmac.SYMKey` instance
    :param enc_key: A :py:class:`cryptojwt.jwk.hmac.SYMKey` instance
    :param sign_alg: Which signing algorithm to use
    :return: Signed and/or encrypted payload
    """

    # Just sign, sign and encrypt or just encrypt

    if timestamp:
        timestamp = str(timestamp)
    else:
        timestamp = str(int(time.time()))

    bytes_load = load.encode("utf-8")
    bytes_timestamp = timestamp.encode("utf-8")

    if sign_key:
        signer = HMACSigner(algorithm=sign_alg)
        mac = signer.sign(bytes_load + bytes_timestamp, sign_key.key)
    else:
        mac = b""

    if enc_key:
        if len(enc_key.key) not in [16, 24, 32]:
            raise ValueError("Wrong size of enc_key")

        encrypter = AES_GCMEncrypter(key=enc_key.key)
        iv = os.urandom(12)
        if mac:
            msg = lv_pack(load, timestamp, base64.b64encode(mac).decode("utf-8"))
        else:
            msg = lv_pack(load, timestamp)

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


def ver_dec_content(parts, sign_key=None, enc_key=None, sign_alg="SHA256"):
    """
    Verifies the value of a cookie

    :param parts: The parts of the payload
    :param sign_key: A :py:class:`cryptojwt.jwk.hmac.SYMKey` instance
    :param enc_key: A :py:class:`cryptojwt.jwk.hmac.SYMKey` instance
    :param sign_alg: Which signing algorithm to was used
    :return: A tuple with basic information and a timestamp
    """

    if parts is None:
        return None
    elif len(parts) == 3:
        # verify the cookie signature
        timestamp, load, b64_mac = parts
        mac = base64.b64decode(b64_mac)
        verifier = HMACSigner(algorithm=sign_alg)
        if verifier.verify(
            load.encode("utf-8") + timestamp.encode("utf-8"), mac, sign_key.key
        ):
            return load, timestamp
        else:
            raise VerificationError()
    elif len(parts) == 4:
        b_timestamp = parts[0]
        iv = base64.b64decode(parts[1])
        ciphertext = base64.b64decode(parts[2])
        tag = base64.b64decode(parts[3])

        decrypter = AES_GCMEncrypter(key=enc_key.key)
        try:
            msg = decrypter.decrypt(ciphertext, iv, tag=tag)
        except InvalidTag:
            return None

        p = lv_unpack(msg.decode("utf-8"))
        load = p[0]
        timestamp = p[1]
        if len(p) == 3:
            verifier = HMACSigner(algorithm=sign_alg)
            if verifier.verify(
                load.encode("utf-8") + timestamp.encode("utf-8"),
                base64.b64decode(p[2]),
                sign_key.key,
            ):
                return load, timestamp
        else:
            return load, timestamp
    return None


def make_cookie_content(
    name,
    load,
    sign_key,
    domain=None,
    path=None,
    expire=0,
    timestamp="",
    enc_key=None,
    max_age=0,
    sign_alg="SHA256",
    secure=True,
    http_only=True,
    same_site="",
):
    """
    Create and return a cookies content

    If you only provide a `seed`, a HMAC gets added to the cookies value
    and this is checked, when the cookie is parsed again.

    If you provide both `seed` and `enc_key`, the cookie gets protected
    by using AEAD encryption. This provides both a MAC over the whole cookie
    and encrypts the `load` in a single step.

    The `seed` and `enc_key` parameters should be byte strings of at least
    16 bytes length each. Those are used as cryptographic keys.

    :param name: Cookie name
    :type name: text
    :param load: Cookie load
    :type load: text
    :param sign_key: A sign_key key for payload signing
    :type sign_key: A :py:class:`cryptojwt.jwk.hmac.SYMKey` instance
    :param domain: The domain of the cookie
    :param path: The path specification for the cookie
    :param expire: Number of minutes before this cookie goes stale
    :type expire: int
    :param timestamp: A time stamp
    :type timestamp: text
    :param enc_key: The key to use for payload encryption.
    :type enc_key: A :py:class:`cryptojwt.jwk.hmac.SYMKey` instance
    :param max_age: The time in seconds for when a cookie will be deleted
    :type max_age: int
    :param secure: A secure cookie is only sent to the server with an encrypted request over the
        HTTPS protocol.
    :type secure: boolean
    :param http_only: HttpOnly cookies are inaccessible to JavaScript's Document.cookie API
    :type http_only: boolean
    :param same_site: Whether SameSite (None,Strict or Lax) should be added to the cookie
    :type same_site: byte string
    :return: A SimpleCookie instance
    """
    if not timestamp:
        timestamp = str(int(time.time()))

    _cookie_value = sign_enc_payload(
        load, timestamp, sign_key=sign_key, enc_key=enc_key, sign_alg=sign_alg
    )

    content = {name: {"value": _cookie_value}}

    if path is not None:
        content[name]["path"] = path
    if domain is not None:
        content[name]["domain"] = domain
    if max_age:
        content[name]["expires"] = in_a_while(seconds=max_age)
    if path:
        content[name]["path"] = path
    if domain:
        content[name]["domain"] = domain
    if expire:
        content[name]["expires"] = _expiration(expire, "%a, %d-%b-%Y %H:%M:%S GMT")
    if same_site:
        content[name]["SameSite"] = same_site

    # these are booleans so just set them.
    content[name]["Secure"] = secure
    content[name]["httponly"] = http_only

    return content


def make_cookie(
    name,
    payload,
    sign_key,
    domain=None,
    path=None,
    expire=0,
    timestamp="",
    enc_key=None,
    max_age=0,
    sign_alg="SHA256",
    secure=True,
    http_only=True,
    same_site="",
):
    content = make_cookie_content(
        name,
        payload,
        sign_key,
        domain=domain,
        path=path,
        expire=expire,
        timestamp=timestamp,
        enc_key=enc_key,
        max_age=max_age,
        sign_alg=sign_alg,
        secure=secure,
        http_only=http_only,
        same_site=same_site,
    )

    cookie = SimpleCookie()

    for name, args in content.items():
        cookie[name] = args["value"]
        # Necessary if Python version < 3.8
        if sys.version_info[:2] <= (3, 8):
            cookie[name]._reserved[str("samesite")] = str("SameSite")

        for key, value in args.items():
            if key == "value":
                continue
            cookie[name][key] = value

    return cookie


def cookie_parts(name, kaka):
    """
    Give me the parts of the cookie payload

    :param name: A name of a cookie object
    :param kaka: The cookie
    :return: A list of parts or None if there is no cookie object with the
        given name
    """
    cookie_obj = SimpleCookie(as_unicode(kaka))
    morsel = cookie_obj.get(name)
    if morsel:
        return morsel.value.split("|")
    else:
        return None


def parse_cookie(name, sign_key, kaka, enc_key=None, sign_alg="SHA256"):
    """Parses and verifies a cookie value

    Parses a cookie created by `make_cookie` and verifies
    it has not been tampered with.

    You need to provide the same `sign_key` and `enc_key`
    used when creating the cookie, otherwise the verification
    fails. See `make_cookie` for details about the verification.

    :param sign_key: A signing key used to create the signature
    :type sign_key: A :py:class:`cryptojwt.jwk.hmac.SYMKey` instance
    :param kaka: The cookie
    :param enc_key: The encryption key used.
    :type enc_key: A :py:class:`cryptojwt.jwk.hmac.SYMKey` instance or None
    :raises InvalidCookieSign: When verification fails.
    :return: A tuple consisting of (payload, timestamp) or None if parsing fails
    """
    if not kaka:
        return None

    parts = cookie_parts(name, kaka)

    if parts:
        return ver_dec_content(parts, sign_key, enc_key, sign_alg)
    else:
        return None


class CookieDealer(object):
    """
    Functionality that an entity that deals with cookies need to have
    access to.
    """

    def __init__(
        self,
        sign_key="",
        enc_key="",
        sign_alg="SHA256",
        default_values=None,
        sign_jwk=None,
        enc_jwk=None,
        **kwargs
    ):

        if sign_key:
            if isinstance(sign_key, SYMKey):
                self.sign_key = sign_key
            else:
                self.sign_key = SYMKey(k=sign_key)
        elif sign_jwk:
            if isinstance(sign_jwk, dict):
                self.sign_key = init_key(**sign_jwk)
            else:
                self.sign_key = import_jwk(sign_jwk)
        else:
            self.sign_key = None

        self.sign_alg = sign_alg

        if enc_key:
            if isinstance(enc_key, SYMKey):
                self.enc_key = enc_key
            else:
                self.enc_key = SYMKey(k=enc_key)
        elif enc_jwk:
            if isinstance(enc_jwk, dict):
                self.enc_key = init_key(**enc_jwk)
            else:
                self.enc_key = import_jwk(enc_jwk)
        else:
            self.enc_key = None

        if not default_values:
            default_values = {"path": "", "domain": "", "max_age": 0}

        self.default_value = default_values

    def delete_cookie(self, cookie_name=None):
        """
        Create a cookie that will immediately expire when it hits the other
        side.

        :param cookie_name: Name of the cookie
        :return: A tuple to be added to headers
        """
        if cookie_name is None:
            cookie_name = self.default_value["name"]

        return self.create_cookie("", "", cookie_name=cookie_name, kill=True)

    def create_cookie(
        self,
        value,
        typ,
        cookie_name=None,
        ttl=-1,
        kill=False,
        same_site="",
        http_only=True,
    ):
        """

        :param value: Part of the cookie payload
        :param typ: Type of cookie
        :param cookie_name:
        :param ttl: Number of minutes before this cookie goes stale
        :param kill: Whether the the cookie should expire on arrival
        :param same_site:
        :param http_only:
        :return: A tuple to be added to headers
        """
        if kill:
            ttl = -1
        elif ttl < 0:
            ttl = self.default_value["max_age"]

        if cookie_name is None:
            cookie_name = self.default_value["name"]

        c_args = {}

        srvdomain = self.default_value["domain"]
        if srvdomain and srvdomain not in ["localhost", "127.0.0.1", "0.0.0.0"]:
            c_args["domain"] = srvdomain

        srvpath = self.default_value["path"]
        if srvpath:
            c_args["path"] = srvpath

        # now
        timestamp = str(int(time.time()))

        # create cookie payload
        try:
            cookie_payload = "::".join([value, timestamp, typ])
        except TypeError:
            cookie_payload = "::".join([value[0], timestamp, typ])

        cookie = make_cookie(
            cookie_name,
            cookie_payload,
            self.sign_key,
            timestamp=timestamp,
            enc_key=self.enc_key,
            max_age=ttl,
            sign_alg=self.sign_alg,
            same_site=same_site,
            http_only=http_only,
            **c_args
        )

        return cookie

    def get_cookie_value(self, cookie=None, cookie_name=None):
        """
        Return information stored in a Cookie

        :param cookie: A cookie instance
        :param cookie_name: The name of the cookie I'm looking for
        :return: tuple (value, timestamp, type)
        """
        if cookie_name is None:
            cookie_name = self.default_value["name"]

        if cookie is None or cookie_name is None:
            return None
        else:
            try:
                info, timestamp = parse_cookie(
                    cookie_name, self.sign_key, cookie, self.enc_key, self.sign_alg
                )
            except (TypeError, AssertionError):
                return None
            else:
                value, _ts, typ = info.split("::")
                if timestamp == _ts:
                    return value, _ts, typ
        return None

    def append_cookie(
        self,
        cookie,
        name,
        payload,
        typ,
        domain=None,
        path=None,
        timestamp="",
        max_age=0,
        same_site="None",
        http_only=True,
    ):
        """
        Adds a cookie to a SimpleCookie instance

        :param cookie:
        :param name:
        :param payload:
        :param typ:
        :param domain:
        :param path:
        :param timestamp:
        :param max_age:
        :return:
        """
        if not timestamp:
            timestamp = str(int(time.time()))

        # create cookie payload
        try:
            _payload = "::".join([payload, timestamp, typ])
        except TypeError:
            _payload = "::".join([payload[0], timestamp, typ])

        content = make_cookie_content(
            name,
            _payload,
            self.sign_key,
            domain=domain,
            path=path,
            timestamp=timestamp,
            enc_key=self.enc_key,
            max_age=max_age,
            sign_alg=self.sign_alg,
            same_site=same_site,
            http_only=http_only,
        )

        for name, args in content.items():
            cookie[name] = args["value"]
            for key, value in args.items():
                if key == "value":
                    continue
                cookie[name][key] = value

        return cookie


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


def create_session_cookie(name, opbs, **kwargs):
    cookie = SimpleCookie()
    cookie[name] = opbs
    for key, value in kwargs.items():
        cookie[name][key] = value
    return cookie


def append_cookie(kaka1, kaka2):
    for name, args in kaka2.items():
        kaka1[name] = name
        for key, value in args.items():
            if key == "value":
                continue
            kaka1[name][key] = value
    return kaka1


def new_cookie(endpoint_context, cookie_name=None, typ="sso", **kwargs):
    if endpoint_context.cookie_dealer:
        _val = as_unicode(b64e(as_bytes(json.dumps(kwargs))))
        return endpoint_context.cookie_dealer.create_cookie(
            _val, typ=typ, cookie_name=cookie_name, ttl=endpoint_context.sso_ttl
        )
    else:
        return None


def cookie_value(b64):
    try:
        return json.loads(as_unicode(b64d(as_bytes(b64))))
    except Exception:
        return b64
