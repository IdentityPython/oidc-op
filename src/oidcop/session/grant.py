from typing import Optional
from uuid import uuid1

from oidcmsg.impexp import ImpExp
from oidcmsg.message import Message
from oidcmsg.oauth2 import AuthorizationRequest

from oidcop.authn_event import AuthnEvent
from oidcop.session import MintingNotAllowed
from oidcop.session import unpack_session_key
from oidcop.session.token import AccessToken
from oidcop.session.token import AuthorizationCode
from oidcop.session.token import Item
from oidcop.session.token import RefreshToken
from oidcop.session.token import SessionToken
from oidcop.token import Token as TokenHandler


class GrantMessage(ImpExp):
    parameter = {
        "authorization_details": {},  # As defined in draft-lodderstedt-oauth-rar
        "claims": {},  # As defined in OIDC core
        "resources": [],  # As defined in RFC8707
        "scope": "",  # As defined in RFC6749
    }

    def __init__(self,
                 scope: Optional[str] = "",
                 authorization_details: Optional[dict] = None,
                 claims: Optional[list] = None,
                 resources: Optional[list] = None
                 ):
        ImpExp.__init__(self)
        self.scope = scope
        self.authorization_details = authorization_details
        self.claims = claims
        self.resources = resources


GRANT_TYPE_MAP = {
    "authorization_code": "code",
    "access_token": "access_token",
    "refresh_token": "refresh_token"
}


def find_token(issued, token_id):
    for iss in issued:
        if iss.id == token_id:
            return iss
    return None


TOKEN_MAP = {
    "authorization_code": AuthorizationCode,
    "access_token": AccessToken,
    "refresh_token": RefreshToken
}


class Grant(Item):
    parameter = Item.parameter.copy()
    parameter.update({
        "authentication_event": AuthnEvent,
        "authorization_details": {},
        "authorization_request": AuthorizationRequest,
        "claims": {},
        "issued_token": [SessionToken],
        "resources": [],
        "scope": [],
        "sub": "",
    })
    type = "grant"

    def __init__(self,
                 scope: Optional[list] = None,
                 claims: Optional[dict] = None,
                 resources: Optional[list] = None,
                 authorization_details: Optional[dict] = None,
                 authorization_request: Optional[Message] = None,
                 authentication_event: Optional[AuthnEvent] = None,
                 issued_token: Optional[list] = None,
                 usage_rules: Optional[dict] = None,
                 issued_at: int = 0,
                 expires_in: int = 0,
                 expires_at: int = 0,
                 revoked: bool = False,
                 token_map: Optional[dict] = None,
                 sub: Optional[str] = ""):
        Item.__init__(self, usage_rules=usage_rules, issued_at=issued_at,
                      expires_in=expires_in, expires_at=expires_at, revoked=revoked)
        self.scope = scope or []
        self.authorization_details = authorization_details or None
        self.authorization_request = authorization_request or None
        self.authentication_event = authentication_event or None
        self.claims = claims or {}  # default is to not release any user information
        self.resources = resources or []
        self.issued_token = issued_token or []
        self.id = uuid1().hex
        self.sub = sub

        if token_map is None:
            self.token_map = TOKEN_MAP
        else:
            self.token_map = token_map

    def get(self) -> object:
        return GrantMessage(scope=self.scope, claims=self.claims,
                            authorization_details=self.authorization_details,
                            resources=self.resources)

    def payload_arguments(self, session_id: str, endpoint_context,
                          token_type: str, scope: Optional[dict] = None) -> dict:
        """

        :return: dictionary containing information to place in a token value
        """
        if not scope:
            scope = self.scope

        payload = {
            "scope": scope,
            "aud": self.resources
        }

        _claims_restriction = endpoint_context.claims_interface.get_claims(session_id,
                                                                           scopes=scope,
                                                                           usage=token_type)
        user_id, _, _ = unpack_session_key(session_id)
        user_info = endpoint_context.claims_interface.get_user_claims(user_id,
                                                                      _claims_restriction)
        payload.update(user_info)

        return payload

    def mint_token(self,
                   session_id: str,
                   endpoint_context: object,
                   token_type: str,
                   token_handler: TokenHandler = None,
                   based_on: Optional[SessionToken] = None,
                   usage_rules: Optional[dict] = None,
                   scope: Optional[list] = None,
                   **kwargs) -> Optional[SessionToken]:
        """

        :param session_id:
        :param endpoint_context:
        :param token_type:
        :param token_handler:
        :param based_on:
        :param usage_rules:
        :param scope:
        :param kwargs:
        :return:
        """
        if self.is_active() is False:
            return None

        if based_on:
            if based_on.supports_minting(token_type) is False:
                raise MintingNotAllowed(
                    f"Minting of {token_type} not supported")
            if not based_on.is_active():
                raise MintingNotAllowed("Token inactive")
            _base_on_ref = based_on.value
        else:
            _base_on_ref = None

        if usage_rules is None and token_type in self.usage_rules:
            usage_rules = self.usage_rules[token_type]

        token_class = self.token_map.get(token_type)
        if token_class:
            item = token_class(type=token_type,
                               based_on=_base_on_ref,
                               usage_rules=usage_rules,
                               scope=scope,
                               **kwargs)
            if token_handler is None:
                token_handler = endpoint_context.session_manager.token_handler.handler[
                    GRANT_TYPE_MAP[token_type]]

            item.value = token_handler(session_id=session_id,
                                       **self.payload_arguments(session_id,
                                                                endpoint_context,
                                                                token_type=token_type,
                                                                scope=scope))
        else:
            raise ValueError("Can not mint that kind of token")

        self.issued_token.append(item)
        self.used += 1
        return item

    def get_token(self, value: str) -> Optional[SessionToken]:
        for t in self.issued_token:
            if t.value == value:
                return t
        return None

    def revoke_token(self,
                     value: Optional[str] = "",
                     based_on: Optional[str] = "",
                     recursive: bool = True):
        for t in self.issued_token:
            if not value and not based_on:
                t.revoked = True
            elif value and based_on:
                if value == t.value and based_on == t.based_on:
                    t.revoked = True
            elif value and t.value == value:
                t.revoked = True
                if recursive:
                    self.revoke_token(based_on=t.value)
            elif based_on and t.based_on == based_on:
                t.revoked = True
                if recursive:
                    self.revoke_token(based_on=t.value)

    def get_spec(self, token: SessionToken) -> Optional[dict]:
        if self.is_active() is False or token.is_active is False:
            return None

        res = {}
        for attr in ["scope", "claims", "resources"]:
            _val = getattr(token, attr)
            if _val:
                res[attr] = _val
            else:
                _val = getattr(self, attr)
                if _val:
                    res[attr] = _val
        return res


DEFAULT_USAGE = {
    "authorization_code": {
        "max_usage": 1,
        "supports_minting": ["access_token", "refresh_token", "id_token"],
        "expires_in": 300
    },
    "access_token": {
        "supports_minting": [],
        "expires_in": 3600
    },
    "refresh_token": {
        "supports_minting": ["access_token", "refresh_token", "id_token"]
    }
}


def get_usage_rules(token_type, endpoint_context, grant, client_id):
    """
    The order of importance:
    Grant, Client, EndPointContext, Default

    :param token_type: The type of token
    :param endpoint_context: An EndpointContext instance
    :param grant: A Grant instance
    :param client_id: The client identifier
    :return: Usage specification
    """

    _usage = endpoint_context.authz.usage_rules_for(client_id, token_type)
    if not _usage:
        _usage = DEFAULT_USAGE[token_type]

    _grant_usage = grant.usage_rules.get(token_type)
    if _grant_usage:
        _usage.update(_grant_usage)

    return _usage


class ExchangeGrant(Grant):
    parameter = Grant.parameter.copy()
    parameter.update({"users": []})
    type = "exchange_grant"

    def __init__(self,
                 scope: Optional[list] = None,
                 claims: Optional[dict] = None,
                 resources: Optional[list] = None,
                 authorization_details: Optional[dict] = None,
                 issued_token: Optional[list] = None,
                 usage_rules: Optional[dict] = None,
                 issued_at: int = 0,
                 expires_in: int = 0,
                 expires_at: int = 0,
                 revoked: bool = False,
                 token_map: Optional[dict] = None,
                 users: list = None):
        Grant.__init__(self, scope=scope, claims=claims, resources=resources,
                       authorization_details=authorization_details,
                       issued_token=issued_token, usage_rules=usage_rules,
                       issued_at=issued_at, expires_in=expires_in,
                       expires_at=expires_at, revoked=revoked,
                       token_map=token_map)

        self.users = users or []
        self.usage_rules = {
            "access_token": {
                "supports_minting": ["access_token"],
                "expires_in": 60
            }
        }
