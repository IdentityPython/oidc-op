import logging
from typing import List
from typing import Union

from oidcmsg.impexp import ImpExp
from oidcmsg.item import DLDict

from . import session_key
from .grant import Grant
from .info import ClientSessionInfo
from .info import SessionInfo
from .info import UserSessionInfo

logger = logging.getLogger(__name__)


class NoSuchClientSession(KeyError):
    pass


class NoSuchGrant(KeyError):
    pass


class Database(ImpExp):
    parameter = {
        "db": DLDict
    }

    def __init__(self):
        ImpExp.__init__(self)
        self.db = DLDict()

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
            gid_key = session_key(uid, client_id, grant_id)
            self.db[gid_key] = value

        if client_id:
            cid_key = session_key(uid, client_id)
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
            raise KeyError('No such UserID')
        else:
            if user_info is None:
                raise KeyError('No such UserID')

        if client_id is None:
            return user_info
        else:
            if client_id not in user_info.subordinate:
                raise ValueError('No session from that client for that user')
            else:
                try:
                    client_session_info = self.db[session_key(uid, client_id)]
                except KeyError:
                    raise NoSuchClientSession(client_id)
                else:
                    if grant_id is None:
                        return client_session_info

                    if grant_id not in client_session_info.subordinate:
                        raise ValueError(
                            'No such grant for that user and client')
                    else:
                        try:
                            return self.db[session_key(uid, client_id, grant_id)]
                        except KeyError:
                            raise NoSuchGrant(grant_id)

    def delete(self, path: List[str]):
        uid, client_id, grant_id = self._eval_path(path)
        try:
            _user_info = self.db[uid]
        except KeyError:
            pass
        else:
            if client_id:
                if client_id in _user_info.subordinate:
                    try:
                        _client_info = self.db[session_key(uid, client_id)]
                    except KeyError:
                        pass
                    else:
                        if grant_id:
                            if grant_id in _client_info.subordinate:
                                try:
                                    self.db.__delitem__(
                                        session_key(uid, client_id, grant_id))
                                except KeyError:
                                    pass
                                _client_info.subordinate.remove(grant_id)
                        else:
                            for grant_id in _client_info.subordinate:
                                self.db.__delitem__(
                                    session_key(uid, client_id, grant_id))
                            _client_info.subordinate = []

                        if len(_client_info.subordinate) == 0:
                            self.db.__delitem__(session_key(uid, client_id))
                            _user_info.subordinate.remove(client_id)
                        else:
                            self.db[client_id] = _client_info

                    if len(_user_info.subordinate) == 0:
                        self.db.__delitem__(uid)
                    else:
                        self.db[uid] = _user_info
                else:
                    pass
            else:
                self.db.__delitem__(uid)

    def update(self, path: List[str], new_info: dict):
        _info = self.get(path)
        for key, val in new_info.items():
            setattr(_info, key, val)
        self.set(path, _info)
