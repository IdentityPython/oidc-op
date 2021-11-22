import hashlib
import logging
import os
from typing import List
from typing import Optional
import uuid

from oidcmsg.oauth2 import AuthorizationRequest

from oidcop import rndstr
from oidcop.authn_event import AuthnEvent
from oidcop.exception import ConfigurationError
from oidcop.token import handler
from oidcop.util import Crypt
from oidcop.session.database import NoSuchClientSession
from .database import Database
from .grant import Grant
from .grant import SessionToken
from .info import ClientSessionInfo
from .info import UserSessionInfo
from ..token import UnknownToken
from ..token import WrongTokenClass
from ..token.handler import TokenHandler

logger = logging.getLogger(__name__)


class RawID(object):
    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, uid, *args, **kwargs):
        return uid


def pairwise_id(uid, sector_identifier, salt="", **kwargs):
    return hashlib.sha256(
        ("{}{}{}".format(uid, sector_identifier, salt)).encode("utf-8")
    ).hexdigest()


class PairWiseID(object):
    def __init__(self, salt: Optional[str] = "", filename: Optional[str] = ""):
        if salt:
            self.salt = salt
        elif filename:
            if os.path.isfile(filename):
                self.salt = open(filename).read()
            elif not os.path.isfile(filename) and os.path.exists(
                filename
            ):  # Not a file, Something else
                raise ConfigurationError("Salt filename points to something that is not a file")
            else:
                self.salt = rndstr(24)
                # May raise an exception
                fp = open(filename, "w")
                fp.write(self.salt)
                fp.close()
        else:
            self.salt = rndstr(24)

    def __call__(self, uid, sector_identifier, *args, **kwargs):
        return pairwise_id(uid, sector_identifier, self.salt)


def public_id(uid, salt="", **kwargs):
    return hashlib.sha256("{}{}".format(uid, salt).encode("utf-8")).hexdigest()


class PublicID(PairWiseID):
    def __call__(self, uid, sector_identifier, *args, **kwargs):
        return public_id(uid, self.salt)


def ephemeral_id(*args, **kwargs):
    return uuid.uuid4().hex


class SessionManager(Database):
    parameter = Database.parameter.copy()
    parameter.update({"salt": ""})
    init_args = ["handler"]

    def __init__(
        self,
        handler: TokenHandler,
        conf: Optional[dict] = None,
        sub_func: Optional[dict] = None,
    ):
        super(SessionManager, self).__init__()
        self.conf = conf or {}

        # these won't change runtime
        session_params = self.conf.get("session_params") or {}
        self._key = session_params.get("password") or rndstr(24)
        self._salt = session_params.get("salt") or rndstr(32)

        self.key = self.load_key()
        self.salt = self.load_key()

        self._init_db()
        self.token_handler = handler

        # this allows the subject identifier minters to be defined by someone
        # else then me.
        if sub_func is None:
            self.sub_func = {
                "public": public_id,
                "pairwise": pairwise_id,
                "ephemeral": ephemeral_id,
            }
        else:
            self.sub_func = sub_func
            if "public" not in sub_func:
                self.sub_func["public"] = public_id
            if "pairwise" not in sub_func:
                self.sub_func["pairwise"] = pairwise_id
            if "ephemeral" not in sub_func:
                self.sub_func["ephemeral"] = ephemeral_id

    def load_key(self):
        """returns the original key assigned in init"""
        return self._key

    def load_salt(self):
        """returns the original salt assigned in init"""
        return self._salt

    def __setattr__(self, key, value):
        if key in ("_key", "_salt"):
            if hasattr(self, key):
                # not first time we configure it!
                raise AttributeError(f"{key} is a ReadOnly attribute " "that can't be overwritten!")
        super().__setattr__(key, value)

    def _init_db(self):
        Database.__init__(self, key=self.load_key(), salt=self.load_salt())

    def get_user_info(self, uid: str) -> UserSessionInfo:
        usi = self.get([uid])
        if isinstance(usi, UserSessionInfo):
            return usi
        else:  # pragma: no cover
            raise ValueError("Not UserSessionInfo")

    def find_token(self, session_id: str, token_value: str) -> Optional[SessionToken]:
        """

        :param session_id: Based on 3-tuple, user_id, client_id and grant_id
        :param token_value:
        :return:
        """
        user_id, client_id, grant_id = self.decrypt_session_id(session_id)
        grant = self.get([user_id, client_id, grant_id])
        for token in grant.issued_token:
            if token.value == token_value:
                return token

        return None  # pragma: no cover

    def create_grant(
        self,
        authn_event: AuthnEvent,
        auth_req: AuthorizationRequest,
        user_id: str,
        client_id: Optional[str] = "",
        sub_type: Optional[str] = "public",
        token_usage_rules: Optional[dict] = None,
        scopes: Optional[list] = None,
    ) -> str:
        """

        :param scopes: Scopes
        :param authn_event: AuthnEvent instance
        :param auth_req:
        :param user_id:
        :param client_id:
        :param sub_type:
        :param token_usage_rules:
        :return:
        """
        sector_identifier = auth_req.get("sector_identifier_uri", "")

        _claims = auth_req.get("claims", {})

        grant = Grant(
            authorization_request=auth_req,
            authentication_event=authn_event,
            sub=self.sub_func[sub_type](
                user_id, salt=self.salt, sector_identifier=sector_identifier
            ),
            usage_rules=token_usage_rules,
            scope=scopes,
            claims=_claims,
        )

        self.set([user_id, client_id, grant.id], grant)

        return self.encrypted_session_id(user_id, client_id, grant.id)

    def create_session(
        self,
        authn_event: AuthnEvent,
        auth_req: AuthorizationRequest,
        user_id: str,
        client_id: Optional[str] = "",
        sub_type: Optional[str] = "public",
        token_usage_rules: Optional[dict] = None,
        scopes: Optional[list] = None,
    ) -> str:
        """
        Create part of a user session. The parts added are user- and client
        information and a grant.

        :param scopes:
        :param authn_event: Authentication Event information
        :param auth_req: Authorization Request
        :param client_id: Client ID
        :param user_id: User ID
        :param sub_type: What kind of subject will be assigned
        :param token_usage_rules: Rules for how tokens can be used
        :return: Session key
        """

        try:
            _usi = self.get([user_id])
        except KeyError:
            _usi = UserSessionInfo(user_id=user_id)
            self.set([user_id], _usi)

        if not client_id:
            client_id = auth_req["client_id"]

        try:
            self.get([user_id, client_id])
        except (NoSuchClientSession, ValueError):
            client_info = ClientSessionInfo(client_id=client_id)
            self.set([user_id, client_id], client_info)

        return self.create_grant(
            auth_req=auth_req,
            authn_event=authn_event,
            user_id=user_id,
            client_id=client_id,
            sub_type=sub_type,
            token_usage_rules=token_usage_rules,
            scopes=scopes,
        )

    def __getitem__(self, session_id: str):
        return self.get(self.decrypt_session_id(session_id))

    def __setitem__(self, session_id: str, value):
        return self.set(self.decrypt_session_id(session_id), value)

    def get_client_session_info(self, session_id: str) -> ClientSessionInfo:
        """
        Return client connected information for a user session.

        :param session_id: Session identifier
        :return: ClientSessionInfo instance
        """
        _user_id, _client_id, _grant_id = self.decrypt_session_id(session_id)
        csi = self.get([_user_id, _client_id])
        if isinstance(csi, ClientSessionInfo):
            return csi
        else:  # pragma: no cover
            raise ValueError("Wrong type of session info")

    def get_user_session_info(self, session_id: str) -> UserSessionInfo:
        """
        Return client connected information for a user session.

        :param session_id: Session identifier
        :return: ClientSessionInfo instance
        """
        _user_id, _client_id, _grant_id = self.decrypt_session_id(session_id)
        usi = self.get([_user_id])
        if isinstance(usi, UserSessionInfo):
            return usi
        else:  # pragma: no cover
            raise ValueError("Wrong type of session info")

    def get_grant(self, session_id: str) -> Grant:
        """
        Return client connected information for a user session.

        :param session_id: Session identifier
        :return: ClientSessionInfo instance
        """
        _user_id, _client_id, _grant_id = self.decrypt_session_id(session_id)
        grant = self.get([_user_id, _client_id, _grant_id])
        if isinstance(grant, Grant):
            return grant
        else:  # pragma: no cover
            raise ValueError("Wrong type of item")

    def _revoke_dependent(self, grant: Grant, token: SessionToken):
        for t in grant.issued_token:
            if t.based_on == token.value:
                t.revoked = True  # TODO: not covered yet!
                self._revoke_dependent(grant, t)

    def revoke_token(self, session_id: str, token_value: str, recursive: bool = False):
        """
        Revoke a specific token that belongs to a specific user session.

        :param session_id: Session identifier
        :param token_value: SessionToken value
        :param recursive: Revoke all tokens that was minted using this token or
            tokens minted by this token. Recursively.
        """
        token = self.find_token(session_id, token_value)
        if token is None:  # pragma: no cover
            raise UnknownToken()

        token.revoked = True
        if recursive:  # TODO: not covered yet!
            grant = self[session_id]
            self._revoke_dependent(grant, token)

    def get_authentication_events(
        self,
        session_id: Optional[str] = "",
        user_id: Optional[str] = "",
        client_id: Optional[str] = "",
    ) -> List[AuthnEvent]:
        """
        Return the authentication events that exists for a user/client combination.

        :param client_id:
        :param user_id:
        :param session_id: A session identifier
        :return: None if no authentication event could be found or an AuthnEvent instance.
        """
        if session_id:
            user_id, client_id, _ = self.decrypt_session_id(session_id)
        elif user_id and client_id:
            pass
        else:
            raise AttributeError("Must have session_id or user_id and client_id")

        c_info = self.get([user_id, client_id])

        _grants = [self.get([user_id, client_id, gid]) for gid in c_info.subordinate]
        return [g.authentication_event for g in _grants]

    def get_authorization_request(self, session_id):
        res = self.get_session_info(session_id=session_id, authorization_request=True)
        return res["authorization_request"]

    def get_authentication_event(self, session_id):
        res = self.get_session_info(session_id=session_id, authentication_event=True)
        return res["authentication_event"]

    def revoke_client_session(self, session_id: str):
        """
        Revokes a client session

        :param session_id: Session identifier
        """
        parts = self.decrypt_session_id(session_id)
        if len(parts) == 2:
            _user_id, _client_id = parts
        elif len(parts) == 3:
            _user_id, _client_id, _ = parts
        else:
            raise ValueError("Invalid session ID")

        _info = self.get([_user_id, _client_id])
        logger.debug(f"revoke_client_session: {_user_id}:{_client_id}")
        self.set([_user_id, _client_id], _info.revoke())

        # revoked all grants
        for gid in _info.subordinate:
            _grant = self.get([_user_id, _client_id, gid])
            _grant.revoke()

    def client_session_is_revoked(self, session_id: str):
        _user_id, _client_id, _ = self.decrypt_session_id(session_id)
        _client_inst = self.get([_user_id, _client_id])
        return _client_inst.revoked

    def revoke_grant(self, session_id: str):
        """
        Revokes the grant pointed to by a session identifier.

        :param session_id: A session identifier
        """
        _path = self.decrypt_session_id(session_id)
        _info = self.get(_path)
        _info.revoke()
        self.set(_path, _info)

    def grants(
        self,
        session_id: Optional[str] = "",
        user_id: Optional[str] = "",
        client_id: Optional[str] = "",
    ) -> List[Grant]:
        """
        Find all grant connected to a user session

        :param client_id:
        :param user_id:
        :param session_id: A session identifier
        :return: A list of grants
        """
        if session_id:
            user_id, client_id, _ = self.decrypt_session_id(session_id)
        elif user_id and client_id:
            pass
        else:
            raise AttributeError("Must have session_id or user_id and client_id")

        _csi = self.get([user_id, client_id])
        return [self.get([user_id, client_id, gid]) for gid in _csi.subordinate]

    def get_session_info(
        self,
        session_id: str,
        user_session_info: bool = False,
        client_session_info: bool = False,
        grant: bool = False,
        authentication_event: bool = False,
        authorization_request: bool = False,
    ) -> dict:
        """
        Returns information connected to a session.

        :param session_id: The identifier of the session
        :param user_session_info: Whether user session info should part of the response
        :param client_session_info: Whether client session info should part of the response
        :param grant: Whether the grant should part of the response
        :param authentication_event: Whether the authentication event information should part of
            the response
        :param authorization_request: Whether the authorization_request should part of the response
        :return: A dictionary with session information
        """
        _user_id, _client_id, _grant_id = self.decrypt_session_id(session_id)
        _grant = None
        res = {
            "session_id": session_id,
            "user_id": _user_id,
            "client_id": _client_id,
            "grant_id": _grant_id,
        }
        if user_session_info:
            res["user_session_info"] = self.get([_user_id])
        if client_session_info:
            res["client_session_info"] = self.get([_user_id, _client_id])
        if grant:
            res["grant"] = self.get([_user_id, _client_id, _grant_id])

        if authentication_event:
            if grant:
                res["authentication_event"] = res["grant"]["authentication_event"]
            else:
                _grant = self.get([_user_id, _client_id, _grant_id])
                res["authentication_event"] = _grant.authentication_event

        if authorization_request:
            if grant:
                res["authorization_request"] = res["grant"].authorization_request
            elif _grant:
                res["authorization_request"] = _grant.authorization_request
            else:
                _grant = self.get([_user_id, _client_id, _grant_id])
                res["authorization_request"] = _grant.authorization_request

        return res

    def _compatible_sid(self, sid):
        # To be backward compatible is this an old time sid
        p = self.unpack_session_key(sid)
        if len(p) == 3:
            sid = self.encrypted_session_id(*p)
        return sid

    def get_session_info_by_token(
        self,
        token_value: str,
        user_session_info: bool = False,
        client_session_info: bool = False,
        grant: bool = False,
        authentication_event: bool = False,
        authorization_request: bool = False,
    ) -> dict:
        _token_info = self.token_handler.info(token_value)
        sid = _token_info.get("sid")
        # If the token is an ID Token then the sid will not be in the
        # _token_info
        if not sid:
            raise WrongTokenClass

        # To be backward compatible is this an old time sid
        sid = self._compatible_sid(sid)

        return self.get_session_info(
            sid,
            user_session_info=user_session_info,
            client_session_info=client_session_info,
            grant=grant,
            authentication_event=authentication_event,
            authorization_request=authorization_request,
        )

    def get_session_id_by_token(self, token_value: str) -> str:
        _token_info = self.token_handler.info(token_value)
        sid = _token_info.get("sid")
        return self._compatible_sid(sid)

    def add_grant(self, user_id: str, client_id: str, **kwargs) -> Grant:
        """
        Creates and adds a grant to a user session.

        :param user_id: User identifier
        :param client_id: Client identifier
        :param kwargs: Keyword arguments to the Grant class initialization
        :return: A Grant instance
        """
        args = {k: v for k, v in kwargs.items() if k in Grant.parameter}
        _grant = Grant(**args)
        self.set([user_id, client_id, _grant.id], _grant)
        _client_session_info = self.get([user_id, client_id])
        _client_session_info.subordinate.append(_grant.id)
        self.set([user_id, client_id], _client_session_info)
        return _grant

    def remove_session(self, session_id: str):
        _user_id, _client_id, _grant_id = self.decrypt_session_id(session_id)
        self.delete([_user_id, _client_id, _grant_id])

    def local_load_adjustments(self, **kwargs):
        self.crypt = Crypt(self.key)

    def flush(self):
        super().flush()
        self._init_db()


def create_session_manager(server_get, token_handler_args, sub_func=None, conf=None):
    _token_handler = handler.factory(server_get, **token_handler_args)
    return SessionManager(_token_handler, sub_func=sub_func, conf=conf)
