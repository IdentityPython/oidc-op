from typing import List
from typing import Optional

from oidcmsg.impexp import ImpExp


class SessionInfo(ImpExp):
    parameter = {"subordinate": [], "revoked": bool, "type": "", "extra_args": {}}

    def __init__(
        self,
        subordinate: Optional[List[str]] = None,
        revoked: Optional[bool] = False,
        type: Optional[str] = "",
        **kwargs
    ):
        ImpExp.__init__(self)
        self.subordinate = subordinate or []
        self.revoked = revoked
        self.type = type
        self.extra_args = {}

    def add_subordinate(self, value: str) -> "SessionInfo":
        if value not in self.subordinate:
            self.subordinate.append(value)
        return self

    def remove_subordinate(self, value: str) -> "SessionInfo":
        self.subordinate.remove(value)
        return self

    def revoke(self) -> "SessionInfo":
        self.revoked = True
        return self

    def is_revoked(self) -> bool:
        return self.revoked

    def keys(self):
        return self.parameter.keys()


class UserSessionInfo(SessionInfo):
    parameter = SessionInfo.parameter.copy()
    parameter.update(
        {
            "user_id": "",
        }
    )

    def __init__(self, **kwargs):
        SessionInfo.__init__(self, **kwargs)
        self.type = "UserSessionInfo"
        self.user_id = kwargs.get("user_id", "")
        self.extra_args = {k: v for k, v in kwargs.items() if k not in self.parameter}


class ClientSessionInfo(SessionInfo):
    parameter = SessionInfo.parameter.copy()
    parameter.update({"client_id": ""})

    def __init__(self, **kwargs):
        SessionInfo.__init__(self, **kwargs)
        self.type = "ClientSessionInfo"
        self.client_id = kwargs.get("client_id", "")
        self.extra_args = {k: v for k, v in kwargs.items() if k not in self.parameter}

    def find_grant_and_token(self, val: str):
        for grant in self.subordinate:
            token = grant.get_token(val)
            if token:
                return grant, token
