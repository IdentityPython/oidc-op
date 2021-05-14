from typing import Callable
from typing import Optional

from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jws.exception import JWSException
from oidcop.token import Crypt

from oidcop.exception import ToOld

from . import Token
from . import is_expired
from .exception import UnknownToken

TYPE_MAP = {
    "A": "code",
    "T": "access_token",
    "R": "refresh_token"
}


class JWTToken(Token):
    def __init__(
            self,
            typ,
            keyjar: KeyJar = None,
            issuer: str = None,
            aud: Optional[list] = None,
            alg: str = "ES256",
            lifetime: int = 300,
            server_get: Callable = None,
            token_type: str = "Bearer",
            password: str = "",
            **kwargs
    ):
        Token.__init__(self, typ, **kwargs)
        self.token_type = token_type
        self.lifetime = lifetime
        self.crypt = Crypt(password)

        self.kwargs = kwargs
        _context = server_get("endpoint_context")
        self.key_jar = keyjar or _context.keyjar
        self.issuer = issuer or _context.issuer
        self.cdb = _context.cdb
        self.server_get = server_get

        self.def_aud = aud or []
        self.alg = alg

    def load_claims(self, payload:dict={}):
        # inherit me and do your things here
        return payload

    def __call__(self,
                 session_id: Optional[str] = '',
                 ttype: Optional[str] = '',
                 **payload) -> str:
        """
        Return a token.

        :param session_id: Session id
        :param subject:
        :param grant:
        :param kwargs: KeyWord arguments
        :return: Signed JSON Web Token
        """
        if not ttype and self.type:
            ttype = self.type
        else:
            ttype = "A"

        payload.update(
            {"sid": session_id,
             "ttype": ttype
            }
        )
        payload = self.load_claims(payload)

        # payload.update(kwargs)
        signer = JWT(
            key_jar=self.key_jar,
            iss=self.issuer,
            lifetime=self.lifetime,
            sign_alg=self.alg,
        )

        return signer.pack(payload)

    def info(self, token):
        """
        Return type of Token (A=Access code, T=Token, R=Refresh token) and
        the session id.

        :param token: A token
        :return: tuple of token type and session id
        """
        verifier = JWT(key_jar=self.key_jar, allowed_sign_algs=[self.alg])
        try:
            _payload = verifier.unpack(token)
        except JWSException:
            raise UnknownToken()

        if is_expired(_payload["exp"]):
            raise ToOld("Token has expired")
        # All the token metadata
        _res = {
            "sid": _payload["sid"],
            "type": _payload["ttype"],
            "exp": _payload["exp"],
            "handler": self,
        }
        return _res

    def is_expired(self, token, when=0):
        """
        Evaluate whether the token has expired or not

        :param token: The token
        :param when: The time against which to check the expiration
            0 means now.
        :return: True/False
        """
        verifier = JWT(key_jar=self.key_jar, allowed_sign_algs=[self.alg])
        _payload = verifier.unpack(token)
        return is_expired(_payload["exp"], when)

    def gather_args(self, sid, sdb, udb):
        # sdb[sid]
        return {}
