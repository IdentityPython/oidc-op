from typing import Callable
from typing import Optional

from cryptojwt import JWT
from cryptojwt.jws.exception import JWSException

from oidcop.exception import ToOld
from oidcop.token import Crypt
from oidcop.token.exception import WrongTokenClass
from . import Token
from . import is_expired
from .exception import UnknownToken
from ..constant import DEFAULT_TOKEN_LIFETIME


class JWTToken(Token):
    def __init__(
        self,
        token_class,
        # keyjar: KeyJar = None,
        issuer: str = None,
        aud: Optional[list] = None,
        alg: str = "ES256",
        lifetime: int = DEFAULT_TOKEN_LIFETIME,
        server_get: Callable = None,
        token_type: str = "Bearer",
        password: str = "",
        **kwargs
    ):
        Token.__init__(self, token_class, **kwargs)
        self.token_type = token_type
        self.lifetime = lifetime
        self.crypt = Crypt(password)

        self.kwargs = kwargs
        _context = server_get("endpoint_context")
        # self.key_jar = keyjar or _context.keyjar
        self.issuer = issuer or _context.issuer
        self.cdb = _context.cdb
        self.server_get = server_get

        self.def_aud = aud or []
        self.alg = alg

    def load_custom_claims(self, payload: dict = None):
        # inherit me and do your things here
        return payload

    def __call__(
        self,
        session_id: Optional[str] = "",
        token_class: Optional[str] = "",
        usage_rules: Optional[dict] = None,
        **payload
    ) -> str:
        """
        Return a token.

        :param session_id: Session id
        :param token_class: Token class
        :param payload: A dictionary with information that is part of the payload of the JWT.
        :return: Signed JSON Web Token
        """
        if not token_class:
            if self.token_class:
                token_class = self.token_class
            else:
                token_class = "authorization_code"

        payload.update({"sid": session_id, "token_class": token_class})
        payload = self.load_custom_claims(payload)

        # payload.update(kwargs)
        _context = self.server_get("endpoint_context")
        if usage_rules and "expires_in" in usage_rules:
            lifetime = usage_rules.get("expires_in")
        else:
            lifetime = self.lifetime
        signer = JWT(
            key_jar=_context.keyjar,
            iss=self.issuer,
            lifetime=lifetime,
            sign_alg=self.alg,
        )

        return signer.pack(payload)

    def get_payload(self, token):
        _context = self.server_get("endpoint_context")
        verifier = JWT(key_jar=_context.keyjar, allowed_sign_algs=[self.alg])
        try:
            _payload = verifier.unpack(token)
        except JWSException:
            raise UnknownToken()

        return _payload

    def info(self, token):
        """
        Return token information

        :param token: A token
        :return: dictionary with token information
        """
        _payload = self.get_payload(token)

        _class = _payload.get("ttype")
        if _class is None:
            _class = _payload.get("token_class")

        if _class not in [self.token_class, self.alt_token_name]:
            raise WrongTokenClass(_payload["token_class"])
        else:
            _payload["token_class"] = self.token_class

        if is_expired(_payload["exp"]):
            raise ToOld("Token has expired")
        # All the token metadata
        _res = {
            "sid": _payload["sid"],
            "token_class": _payload["token_class"],
            "exp": _payload["exp"],
            "handler": self,
        }
        return _res

    def is_expired(self, token, when=0):
        """
        Evaluate whether the token has expired or not

        :param token: The token
        :param when: The time against which to check the expiration. 0 means now.
        :return: True/False
        """
        _payload = self.get_payload(token)
        return is_expired(_payload["exp"], when)

    def gather_args(self, sid, sdb, udb):
        # sdb[sid]
        return {}
