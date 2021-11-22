import base64
import cryptography
import logging

from typing import List
from typing import Optional
from typing import Union

from oidcmsg.impexp import ImpExp
from oidcmsg.item import DLDict

from oidcop import rndstr
from oidcop.constant import DIVIDER
from oidcop.util import Crypt
from oidcop.util import lv_pack
from oidcop.util import lv_unpack

from .grant import Grant
from .info import ClientSessionInfo
from .info import SessionInfo
from .info import UserSessionInfo

logger = logging.getLogger(__name__)


class NoSuchClientSession(KeyError):
    pass


class NoSuchGrant(KeyError):
    pass


class InconsistentDatabase(TypeError):
    pass


class Database(ImpExp):
    parameter = {"db": DLDict, "key": ""}

    def __init__(self, key: Optional[str] = "", **kwargs):
        ImpExp.__init__(self)
        self.db = DLDict()

        for k, v in kwargs.items():
            setattr(self, k, v)

        self.key = key or rndstr(24)
        self.crypt = Crypt(key)

    @staticmethod
    def _eval_path(path: List[str]):
        uid = path[0]
        client_id = None
        grant_id = None
        if len(path) > 1:
            client_id = path[1]
            if len(path) > 2:
                grant_id = path[2]

        return uid, client_id, grant_id

    def set(self, path: List[str], value: Union[SessionInfo, Grant]):
        """

        :param path: a list of identifiers
        :param value: Class instance to be stored
        """

        uid, client_id, grant_id = self._eval_path(path)

        if grant_id:
            gid_key = self.session_key(uid, client_id, grant_id)
            self.db[gid_key] = value

        if client_id:
            cid_key = self.session_key(uid, client_id)
            cid_info = self.db.get(cid_key, ClientSessionInfo())
            if not grant_id:
                self.db[cid_key] = value
            elif grant_id not in cid_info.subordinate:
                cid_info.add_subordinate(grant_id)
                self.db[cid_key] = cid_info

        userinfo = self.db.get(uid, UserSessionInfo())
        if client_id is None:
            self.db[uid] = value
        if client_id and client_id not in userinfo.subordinate:
            userinfo.add_subordinate(client_id)
            self.db[uid] = userinfo

    def get(self, path: List[str]) -> Union[SessionInfo, Grant]:
        uid, client_id, grant_id = self._eval_path(path)
        try:
            user_info = self.db[uid]
        except KeyError:
            raise KeyError("No such UserID")
        except TypeError:
            raise InconsistentDatabase("Missing session db")
        else:
            if user_info is None:
                raise KeyError("No such UserID")

        if client_id is None:
            return user_info

        if client_id not in user_info.subordinate:
            raise ValueError("No session from that client for that user")

        try:
            skey = self.session_key(uid, client_id)
            client_session_info = self.db[skey]
        except KeyError:
            raise NoSuchClientSession(client_id)

        if grant_id is None:
            return client_session_info

        if grant_id not in client_session_info.subordinate:
            raise ValueError("No such grant for that user and client")
        else:
            try:
                skey = self.session_key(uid, client_id, grant_id)
                return self.db[skey]
            except KeyError:
                raise NoSuchGrant(grant_id)

    def delete(self, path: List[str]):
        uid, client_id, grant_id = self._eval_path(path)

        if uid not in self.db:
            return
        elif not client_id:
            self.db.__delitem__(uid)
            return

        _user_info = self.db[uid]
        skey_uid_client = self.session_key(uid, client_id)
        skey_uid_client_grant = self.session_key(uid, client_id, grant_id or "")

        if client_id not in _user_info.subordinate:
            self.db.__delitem__(client_id)
            return

        elif skey_uid_client in self.db:
            _client_info = self.db[skey_uid_client]
            if grant_id:
                if skey_uid_client_grant in self.db:
                    self.db.__delitem__(skey_uid_client_grant)
                if grant_id in _client_info.subordinate:
                    _client_info.subordinate.remove(grant_id)
            else:
                for grant_id in _client_info.subordinate:
                    if skey_uid_client_grant in self.db:
                        self.db.__delitem__(skey_uid_client_grant)
                _client_info.subordinate = []

            if len(_client_info.subordinate) == 0:
                self.db.__delitem__(skey_uid_client)
                _user_info.subordinate.remove(client_id)
            else:
                self.db[client_id] = _client_info

        if len(_user_info.subordinate) == 0:
            self.db.__delitem__(uid)
        else:
            self.db[uid] = _user_info

    def update(self, path: List[str], new_info: dict):
        _info = self.get(path)
        for key, val in new_info.items():
            setattr(_info, key, val)
        self.set(path, _info)

    def session_key(self, *args):
        return DIVIDER.join(args)

    def unpack_session_key(self, key):
        return key.split(DIVIDER)

    def encrypted_session_id(self, *args) -> str:
        rnd = rndstr(32)
        return base64.b64encode(
            self.crypt.encrypt(lv_pack(rnd, self.session_key(*args)).encode())
        ).decode("utf-8")

    def decrypt_session_id(self, key: str) -> List[str]:
        try:
            plain = self.crypt.decrypt(base64.b64decode(key))
        except cryptography.fernet.InvalidToken as err:
            logger.error(f"cryptography.fernet.InvalidToken: {key}")
            raise ValueError(err)
        except Exception as err:
            raise ValueError(err)
        # order: rnd, type, sid
        return self.unpack_session_key(lv_unpack(plain)[1])
