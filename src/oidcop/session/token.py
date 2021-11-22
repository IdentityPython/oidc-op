from typing import Optional
from uuid import uuid1

from oidcmsg.impexp import ImpExp
from oidcmsg.time_util import utc_time_sans_frac


class MintingNotAllowed(Exception):
    pass


class Item(ImpExp):
    parameter = {
        "expires_at": 0,
        "issued_at": 0,
        "not_before": 0,
        "revoked": bool,
        "usage_rules": {},
        "used": 0,
    }

    def __init__(
        self,
        usage_rules: Optional[dict] = None,
        issued_at: int = 0,
        expires_in: int = 0,
        expires_at: int = 0,
        not_before: int = 0,
        revoked: bool = False,
        used: int = 0,
    ):
        ImpExp.__init__(self)
        self.issued_at = issued_at or utc_time_sans_frac()
        self.not_before = not_before
        if expires_at == 0 and expires_in != 0:
            self.set_expires_at(expires_in)
        else:
            self.expires_at = expires_at

        self.revoked = revoked
        self.used = used
        self.usage_rules = usage_rules or {}

    def set_expires_at(self, expires_in):
        self.expires_at = utc_time_sans_frac() + expires_in

    def max_usage_reached(self):
        if "max_usage" in self.usage_rules:
            return self.used >= self.usage_rules["max_usage"]
        else:
            return False

    def is_active(self, now=0):
        if self.max_usage_reached():
            return False

        if self.revoked:
            return False

        if now == 0:
            now = utc_time_sans_frac()

        if self.not_before:
            if now < self.not_before:
                return False

        if self.expires_at:
            if now > self.expires_at:
                return False

        return True

    def revoke(self):
        self.revoked = True


class SessionToken(Item):
    parameter = Item.parameter.copy()
    parameter.update(
        {
            "based_on": "",
            "claims": {},
            "id": "",
            "name": "",
            "resources": [],
            "scope": [],
            "token_class": "",
            "usage_rules": {},
            "used": 0,
            "value": "",
        }
    )

    def __init__(
        self,
        token_class: str = "",
        value: str = "",
        based_on: Optional[str] = None,
        usage_rules: Optional[dict] = None,
        issued_at: int = 0,
        expires_in: int = 0,
        expires_at: int = 0,
        not_before: int = 0,
        revoked: bool = False,
        used: int = 0,
        id: str = "",
        scope: Optional[list] = None,
        claims: Optional[dict] = None,
        resources: Optional[list] = None,
    ):
        Item.__init__(
            self,
            usage_rules=usage_rules,
            issued_at=issued_at,
            expires_in=expires_in,
            expires_at=expires_at,
            not_before=not_before,
            revoked=revoked,
            used=used,
        )

        self.token_class = token_class
        self.value = value
        self.based_on = based_on
        self.id = id or uuid1().hex
        self.set_defaults()
        self.scope = scope or []
        self.claims = claims or {}  # default is to not release any user information
        self.resources = resources or []
        self.name = self.__class__.__name__

    def set_defaults(self):
        pass

    def register_usage(self):
        self.used += 1

    def has_been_used(self):
        return self.used != 0

    def supports_minting(self, token_class):
        _supports_minting = self.usage_rules.get("supports_minting")
        if _supports_minting is None:
            return False
        else:
            return token_class in _supports_minting


class AccessToken(SessionToken):
    parameter = SessionToken.parameter.copy()
    parameter.update({"token_type": ""})

    def __init__(
        self,
        token_class: str = "",
        value: str = "",
        based_on: Optional[str] = None,
        usage_rules: Optional[dict] = None,
        issued_at: int = 0,
        expires_in: int = 0,
        expires_at: int = 0,
        not_before: int = 0,
        revoked: bool = False,
        used: int = 0,
        id: str = "",
        scope: Optional[list] = None,
        claims: Optional[dict] = None,
        resources: Optional[list] = None,
        token_type: Optional[str] = "bearer",
    ):
        SessionToken.__init__(
            self,
            token_class=token_class,
            value=value,
            based_on=based_on,
            usage_rules=usage_rules,
            issued_at=issued_at,
            expires_in=expires_in,
            expires_at=expires_at,
            not_before=not_before,
            revoked=revoked,
            used=used,
            id=id,
            scope=scope,
            claims=claims,
            resources=resources,
        )

        self.token_type = token_type


class AuthorizationCode(SessionToken):
    def set_defaults(self):
        if "supports_minting" not in self.usage_rules:
            self.usage_rules["supports_minting"] = [
                "access_token",
                "refresh_token",
                "id_token",
            ]

        self.usage_rules["max_usage"] = 1


class RefreshToken(SessionToken):
    def set_defaults(self):
        if "supports_minting" not in self.usage_rules:
            self.usage_rules["supports_minting"] = ["access_token", "refresh_token"]


class IDToken(SessionToken):
    parameter = SessionToken.parameter.copy()
    parameter.update({"session_id": ""})

    def __init__(
        self,
        token_class: str = "",
        value: str = "",
        based_on: Optional[str] = None,
        usage_rules: Optional[dict] = None,
        issued_at: int = 0,
        expires_in: int = 0,
        expires_at: int = 0,
        not_before: int = 0,
        revoked: bool = False,
        used: int = 0,
        id: str = "",
        session_id: str = "",
        scope: Optional[list] = None,
        claims: Optional[dict] = None,
        resources: Optional[list] = None,
        token_type: Optional[str] = "bearer",
    ):
        SessionToken.__init__(
            self,
            token_class=token_class,
            value=value,
            based_on=based_on,
            usage_rules=usage_rules,
            issued_at=issued_at,
            expires_in=expires_in,
            expires_at=expires_at,
            not_before=not_before,
            revoked=revoked,
            used=used,
            id=id,
            scope=scope,
            claims=claims,
            resources=resources,
        )

        self.session_id = session_id


SHORT_TYPE_NAME = {"authorization_code": "A", "access_token": "T", "refresh_token": "R"}
