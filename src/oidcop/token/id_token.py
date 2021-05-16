import logging
from typing import Callable
from typing import Optional

from cryptojwt.jws.exception import JWSException
from cryptojwt.jws.jws import factory
from cryptojwt.jws.utils import left_hash
from cryptojwt.jwt import JWT

from oidcop.construct import construct_endpoint_info
from oidcop.exception import ToOld
from oidcop.session import token
from oidcop.session.claims import claims_match
from oidcop.token import is_expired
from . import Token
from . import UnknownToken
from ..util import get_logout_id

logger = logging.getLogger(__name__)

DEF_SIGN_ALG = {
    "id_token": "RS256",
    "userinfo": "RS256",
    "request_object": "RS256",
    "client_secret_jwt": "HS256",
    "private_key_jwt": "RS256",
}
DEF_LIFETIME = 300


def include_session_id(endpoint_context, client_id, where):
    """

    :param endpoint_context:
    :param client_id:
    :param where: front or back
    :return:
    """
    _pinfo = endpoint_context.provider_info

    # Am the OP supposed to support {dir}-channel log out and if so can
    # it pass sid in logout token and ID Token
    for param in ["{}channel_logout_supported", "{}channel_logout_session_supported"]:
        try:
            _supported = _pinfo[param.format(where)]
        except KeyError:
            return False
        else:
            if not _supported:
                return False

    # Does the client support back-channel logout ?
    try:
        endpoint_context.cdb[client_id]["{}channel_logout_uri".format(where)]
    except KeyError:
        return False

    return True


def get_sign_and_encrypt_algorithms(
        endpoint_context, client_info, payload_type, sign=False, encrypt=False
):
    args = {"sign": sign, "encrypt": encrypt}
    if sign:
        try:
            args["sign_alg"] = client_info[
                "{}_signed_response_alg".format(payload_type)
            ]
        except KeyError:  # Fall back to default
            try:
                args["sign_alg"] = endpoint_context.jwx_def["signing_alg"][payload_type]
            except KeyError:
                _def_sign_alg = DEF_SIGN_ALG[payload_type]
                _supported = endpoint_context.provider_info.get(
                    "{}_signing_alg_values_supported".format(payload_type)
                )

                if not _supported:
                    args["sign_alg"] = _def_sign_alg
                else:
                    if _def_sign_alg in _supported:
                        args["sign_alg"] = _def_sign_alg
                    else:
                        args["sign_alg"] = _supported[0]

    if encrypt:
        try:
            args["enc_alg"] = client_info["%s_encrypted_response_alg" % payload_type]
        except KeyError:
            try:
                args["enc_alg"] = endpoint_context.jwx_def["encryption_alg"][
                    payload_type
                ]
            except KeyError:
                _supported = endpoint_context.provider_info.get(
                    "{}_encryption_alg_values_supported".format(payload_type)
                )
                if _supported:
                    args["enc_alg"] = _supported[0]

        try:
            args["enc_enc"] = client_info["%s_encrypted_response_enc" % payload_type]
        except KeyError:
            try:
                args["enc_enc"] = endpoint_context.jwx_def["encryption_enc"][
                    payload_type
                ]
            except KeyError:
                _supported = endpoint_context.provider_info.get(
                    "{}_encryption_enc_values_supported".format(payload_type)
                )
                if _supported:
                    args["enc_enc"] = _supported[0]

    return args


class IDToken(Token, token.IDToken):
    default_capabilities = {
        "id_token_signing_alg_values_supported": None,
        "id_token_encryption_alg_values_supported": None,
        "id_token_encryption_enc_values_supported": None,
    }

    def __init__(
            self,
            typ: Optional[str] = "I",
            lifetime: Optional[int] = 300,
            server_get: Callable = None,
            **kwargs
    ):
        Token.__init__(self, typ, **kwargs)
        self.lifetime = lifetime
        self.server_get = server_get
        self.kwargs = kwargs
        self.scope_to_claims = None
        self.provider_info = construct_endpoint_info(
            self.default_capabilities, **kwargs
        )

    def payload(
            self, session_id, alg="RS256", code=None, access_token=None, extra_claims=None,
    ):
        """

        :param session_id: Session identifier
        :param alg: Which signing algorithm to use for the IdToken
        :param code: Access grant
        :param access_token: Access Token
        :param extra_claims: extra claims to be added to the ID Token
        :return: IDToken instance
        """

        _context = self.server_get("endpoint_context")
        _mngr = _context.session_manager
        session_information = _mngr.get_session_info(session_id, grant=True)
        grant = session_information["grant"]
        _args = {"sub": grant.sub}
        if grant.authentication_event:
            for claim, attr in {"authn_time": "auth_time", "authn_info": "acr"}.items():
                _val = grant.authentication_event.get(claim)
                if _val:
                    _args[attr] = _val

        _claims_restriction = grant.claims.get("id_token")
        if _claims_restriction == {}:
            user_info = None
        else:
            user_info = _context.claims_interface.get_user_claims(
                user_id=session_information["user_id"],
                claims_restriction=_claims_restriction,
            )
            if _claims_restriction and "acr" in _claims_restriction and "acr" in _args:
                if claims_match(_args["acr"], _claims_restriction["acr"]) is False:
                    raise ValueError("Could not match expected 'acr'")

        if user_info:
            try:
                user_info = user_info.to_dict()
            except AttributeError:
                pass

            # Make sure that there are no name clashes
            for key in ["iss", "sub", "aud", "exp", "acr", "nonce", "auth_time"]:
                try:
                    del user_info[key]
                except KeyError:
                    pass

            _args.update(user_info)

        if extra_claims is not None:
            _args.update(extra_claims)

        # Left hashes of code and/or access_token
        halg = "HS%s" % alg[-3:]
        if code:
            _args["c_hash"] = left_hash(code.encode("utf-8"), halg)
        if access_token:
            _args["at_hash"] = left_hash(access_token.encode("utf-8"), halg)

        authn_req = grant.authorization_request
        if authn_req:
            try:
                _args["nonce"] = authn_req["nonce"]
            except KeyError:
                pass

        return _args

    def sign_encrypt(
            self,
            session_id,
            client_id,
            code=None,
            access_token=None,
            sign=True,
            encrypt=False,
            lifetime=None,
            extra_claims=None,
    ) -> str:
        """
        Signed and or encrypt a IDToken

        :param lifetime: How long the ID Token should be valid
        :param session_id: Session information
        :param client_id: Client ID
        :param code: Access grant
        :param access_token: Access Token
        :param sign: If the JWT should be signed
        :param encrypt: If the JWT should be encrypted
        :param extra_claims: Extra claims to be added to the ID Token
        :return: IDToken as a signed and/or encrypted JWT
        """

        _context = self.server_get("endpoint_context")

        client_info = _context.cdb[client_id]
        alg_dict = get_sign_and_encrypt_algorithms(
            _context, client_info, "id_token", sign=sign, encrypt=encrypt
        )

        _payload = self.payload(
            session_id=session_id,
            alg=alg_dict["sign_alg"],
            code=code,
            access_token=access_token,
            extra_claims=extra_claims,
        )

        if lifetime is None:
            lifetime = DEF_LIFETIME

        _jwt = JWT(_context.keyjar, iss=_context.issuer, lifetime=lifetime, **alg_dict)

        return _jwt.pack(_payload, recv=client_id)

    def __call__(
            self, session_id: Optional[str] = "", ttype: Optional[str] = "", **kwargs
    ) -> str:
        _context = self.server_get("endpoint_context")

        user_id, client_id, grant_id = _context.session_manager.decrypt_session_id(
            session_id
        )

        # Should I add session ID. This is about Single Logout.
        if include_session_id(_context, client_id, "back") or \
                include_session_id(_context, client_id, "front"):

            xargs = {"sid": get_logout_id(_context, user_id=user_id, client_id=client_id)}
        else:
            xargs = {}

        lifetime = self.kwargs.get("lifetime")

        # Weed out stuff that doesn't belong here
        kwargs = {
            k: v for k, v in kwargs.items() if k in ["encrypt", "code", "access_token"]
        }

        id_token = self.sign_encrypt(
            session_id,
            client_id,
            sign=True,
            lifetime=lifetime,
            extra_claims=xargs,
            **kwargs
        )

        return id_token

    def info(self, token):
        """
        Return type of Token (A=Access code, T=Token, R=Refresh token) and
        the session id.

        :param token: A token
        :return: tuple of token type and session id
        """
        _context = self.server_get("endpoint_context")

        _jwt = factory(token)
        _payload = _jwt.jwt.payload()
        client_info = _context.cdb[_payload["aud"][0]]
        alg_dict = get_sign_and_encrypt_algorithms(
            _context, client_info, "id_token", sign=True
        )

        verifier = JWT(key_jar=_context.keyjar, allowed_sign_algs=alg_dict["sign_alg"])
        try:
            _payload = verifier.unpack(token)
        except JWSException:
            raise UnknownToken()

        if is_expired(_payload["exp"]):
            raise ToOld("Token has expired")
        # All the token metadata
        return {
            "sid": _payload["sid"],
            # "type": _payload["ttype"],
            "exp": _payload["exp"],
            "handler": self,
        }

    def dump(self, *args, **kwargs):
        _dump = super().dump(*args, **kwargs)
        # do your customization here, if any
        return _dump
