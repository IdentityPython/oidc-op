import base64
import hashlib
import hmac
import logging
import os
import time

from http.cookies import SimpleCookie

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptojwt import as_bytes
from cryptojwt import as_unicode
from cryptojwt import safe_str_cmp
from cryptojwt.jwe import JWEException
from cryptojwt.jwe import split_ctx_and_tag
from oidcendpoint.exception import InvalidCookieSign
from oidcmsg.time_util import in_a_while

from oidcservice import rndstr
from oidcmsg import time_util

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)


CORS_HEADERS = [
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Methods", "GET"),
    ("Access-Control-Allow-Headers", "Authorization")
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


def cookie_signature(key, *parts):
    """Generates a cookie signature.

       :param key: The HMAC key to use.
       :type key: bytes
       :param parts: List of parts to include in the MAC
       :type parts: list of bytes or strings
       :returns: hexdigest of the HMAC
    """

    sha1 = hmac.new(as_bytes(key), digestmod=hashlib.sha1)
    for part in parts:
        if part:
            sha1.update(as_bytes(part))
    return str(sha1.hexdigest())


def verify_cookie_signature(sig, key, *parts):
    """Constant time verifier for signatures

       :param sig: The signature hexdigest to check
       :type sig: str
       :param key: The HMAC key to use.
       :type key: bytes
       :param parts: List of parts to include in the MAC
       :type parts: list of bytes or strings
       :raises: `InvalidCookieSign` when the signature is wrong
    """
    return safe_str_cmp(as_unicode(sig), cookie_signature(key, *parts))


def _make_hashed_key(parts, hashfunc='sha256'):
    """
    Construct a key via hashing the parts

    If the parts do not have enough entropy of their
    own, this doesn't help.

    The size of the hash digest determines the size.
    """
    h = hashlib.new(hashfunc)
    for part in parts:
        if part:
            h.update(as_bytes(part))
    return h.digest()


def make_cookie(name, load, seed, domain="", path="", timestamp="",
                enc_key=None, max_age=0):
    """
    Create and return a cookie

    The cookie is secured against tampering.

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
    :param seed: A seed key for the HMAC function
    :type seed: byte string
    :param domain: The domain of the cookie
    :param path: The path specification for the cookie
    :param timestamp: A time stamp
    :type timestamp: text
    :param enc_key: The key to use for cookie encryption.
    :type enc_key: byte string
    :param max_age: The time in seconds for when a cookie will be deleted
    :type max_age: int
    :return: A SimpleCookie instance
    """
    cookie = SimpleCookie()
    if not timestamp:
        timestamp = str(int(time.time()))

    bytes_load = load.encode("utf-8")
    bytes_timestamp = timestamp.encode("utf-8")

    if enc_key:
        # Make sure the key is 256-bit long, for AES-128-SIV
        #
        # This should go away once we push the keysize requirements up
        # to the top level APIs.
        key = _make_hashed_key((enc_key, seed))

        # key = AESGCM.generate_key(bit_length=128)
        aesgcm = AESGCM(key)
        iv = os.urandom(12)

        # timestamp does not need to be encrypted, just MAC'ed,
        # so we add it to 'Associated Data' only.
        ct = split_ctx_and_tag(aesgcm.encrypt(iv, bytes_load, bytes_timestamp))

        ciphertext, tag = ct
        cookie_payload = [bytes_timestamp,
                          base64.b64encode(iv),
                          base64.b64encode(ciphertext),
                          base64.b64encode(tag)]
    else:
        cookie_payload = [
            bytes_load, bytes_timestamp,
            cookie_signature(seed, load, timestamp).encode('utf-8')]

    cookie[name] = (b"|".join(cookie_payload)).decode('utf-8')
    if path:
        cookie[name]["path"] = path
    if domain:
        cookie[name]["domain"] = domain

    if max_age:
        cookie[name]["expires"] = in_a_while(seconds=max_age)

    return cookie


def parse_cookie(name, seed, kaka, enc_key=None):
    """Parses and verifies a cookie value

    Parses a cookie created by `make_cookie` and verifies
    it has not been tampered with.

    You need to provide the same `seed` and `enc_key`
    used when creating the cookie, otherwise the verification
    fails. See `make_cookie` for details about the verification.

    :param seed: A seed key used for the HMAC signature
    :type seed: bytes
    :param kaka: The cookie
    :param enc_key: The encryption key used.
    :type enc_key: bytes or None
    :raises InvalidCookieSign: When verification fails.
    :return: A tuple consisting of (payload, timestamp) or None if parsing fails
    """
    if not kaka:
        return None

    seed = as_unicode(seed)

    parts = cookie_parts(name, kaka)
    if parts is None:
        return None
    elif len(parts) == 3:
        # verify the cookie signature
        clear_text, timestamp, sig = parts
        if not verify_cookie_signature(sig, seed, clear_text, timestamp):
            raise InvalidCookieSign()
        return clear_text, timestamp
    elif len(parts) == 4:
        # encrypted and signed
        timestamp = parts[0]
        iv = base64.b64decode(parts[1])
        ciphertext = base64.b64decode(parts[2])
        tag = base64.b64decode(parts[3])
        ct = ciphertext + tag

        # Make sure the key is 32-Bytes long
        key = _make_hashed_key((enc_key, seed))
        aesgcm = AESGCM(key)

        # timestamp does not need to be encrypted, just MAC'ed,
        # so we add it to 'Associated Data' only.
        aad = timestamp.encode('utf-8')
        try:
            cleartext = aesgcm.decrypt(iv, ct, aad)
        except (JWEException, InvalidTag) as err:
            raise InvalidCookieSign('{}'.format(err))
        return cleartext.decode('utf-8'), timestamp
    return None


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


class CookieDealer(object):
    """
    Functionality that an entity that deals with cookies need to have
    access to.
    """
    def __init__(self, symkey='', seed_file='seed.txt', cookie=None):
        self.symkey = as_bytes(symkey)

        for attr, default in {'path':'', 'domain':'', 'max_age':0}.items():
            if attr not in cookie:
                cookie[attr] = default

        self.cookie = cookie

        # Need to be able to restart the OP and still use the same seed
        if os.path.isfile(seed_file):
            _seed = open(seed_file).read()
        else:
            _seed = rndstr(48)
            with open('seed.txt', "w") as f:
                f.write(_seed)

        self.seed= as_bytes(_seed)

    def delete_cookie(self, cookie_name=None):
        """
        Create a cookie that will immediately expire when it hits the other
        side.

        :param cookie_name: Name of the cookie
        :return: A tuple to be added to headers
        """
        if cookie_name is None:
            cookie_name = self.cookie['name']
            
        return self.create_cookie("", "", cookie_name=cookie_name, ttl=-1,
                                  kill=True)

    def create_cookie(self, value, typ, cookie_name=None, ttl=-1, kill=False):
        """

        :param value: Part of the cookie payload
        :param typ: Type of cookie
        :param cookie_name:
        :param ttl: Number of minutes before this cookie goes stale
        :param kill: Whether the the cookie should expire on arrival
        :return: A tuple to be added to headers
        """
        if kill:
            ttl = -1
        elif ttl < 0:
            ttl = self.cookie['max_age']

        if cookie_name is None:
            cookie_name = self.cookie['name']

        try:
            srvdomain = self.cookie['domain']
            cookie_domain = "" if not srvdomain else srvdomain
        except AttributeError:
            cookie_domain = ""

        try:
            srvpath = self.cookie['path']
            cookie_path = "" if not srvpath else srvpath
        except AttributeError:
            cookie_path = ""

        # now
        timestamp = str(int(time.time()))

        # create cookie payload
        try:
            cookie_payload = "::".join([value, timestamp, typ])
        except TypeError:
            cookie_payload = "::".join([value[0], timestamp, typ])

        cookie = make_cookie(
            cookie_name, cookie_payload, self.seed,
            domain=cookie_domain, path=cookie_path, timestamp=timestamp,
            enc_key=self.symkey, max_age=ttl)

        return cookie

    def get_cookie_value(self, cookie=None, cookie_name=None):
        """
        Return information stored in a Cookie

        :param cookie: A cookie instance
        :param cookie_name: The name of the cookie I'm looking for
        :return: tuple (value, timestamp, type)
        """
        if cookie_name is None:
            cookie_name = self.cookie['name']

        if cookie is None or cookie_name is None:
            return None
        else:
            try:
                info, timestamp = parse_cookie(cookie_name, self.seed, cookie,
                                               self.symkey)
            except (TypeError, AssertionError):
                return None
            else:
                value, _ts, typ = info.split("::")
                if timestamp == _ts:
                    return value, _ts, typ
        return None
