import logging
from typing import Union

from cryptojwt.jwe.exception import JWEException
from cryptojwt.jws.exception import NoSuitableSigningKeys
from cryptojwt.jwt import utc_time_sans_frac
from oidcop.oidc.token import RefreshTokenHelper
from oidcmsg.message import Message

from oidcop.oidc.token import AccessTokenHelper

logger = logging.getLogger(__name__)


class DPOPAccessTokenHelper(AccessTokenHelper):
    def process_request(self, req: Union[Message, dict], **kwargs):
        """

        :param req:
        :param kwargs:
        :return:
        """
        _context = self.endpoint.server_get("endpoint_context")

        _mngr = _context.session_manager
        _log_debug = logger.debug

        if req["grant_type"] != "authorization_code":
            return self.error_cls(
                error="invalid_request", error_description="Unknown grant_type"
            )

        try:
            _access_code = req["code"].replace(" ", "+")
        except KeyError:  # Missing code parameter - absolutely fatal
            return self.error_cls(
                error="invalid_request", error_description="Missing code"
            )

        _session_info = _mngr.get_session_info_by_token(
            _access_code, grant=True)
        grant = _session_info["grant"]

        code = grant.get_token(_access_code)
        _authn_req = grant.authorization_request

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _authn_req:
            if req["redirect_uri"] != _authn_req["redirect_uri"]:
                return self.error_cls(
                    error="invalid_request", error_description="redirect_uri mismatch"
                )

        _log_debug("All checks OK")

        issue_refresh = False
        if "issue_refresh" in kwargs:
            issue_refresh = kwargs["issue_refresh"]
        else:
            if "offline_access" in grant.scope:
                issue_refresh = True

        _response = {
            "token_type": "Bearer",
            "scope": grant.scope,
        }

        if "dpop_jkt" in req:
            token_args = {"cnf": {"jkt": req["dpop_jkt"]}}
        else:
            token_args = {}

        token = self._mint_token(type="access_token",
                                 grant=grant,
                                 session_id=_session_info["session_id"],
                                 client_id=_session_info["client_id"],
                                 based_on=code,
                                 token_args=token_args)
        if "dpop_jkt" in req:
            if token.extension is None:
                token.extension = {"dpop_jkt": req["dpop_jkt"]}
            else:
                token.extension["dpop_jkt"] = req["dpop_jkt"]

        _response["access_token"] = token.value
        _response["expires_in"] = token.expires_at - utc_time_sans_frac()

        if issue_refresh:
            refresh_token = self._mint_token(type="refresh_token",
                                             grant=grant,
                                             session_id=_session_info["session_id"],
                                             client_id=_session_info["client_id"],
                                             based_on=code)
            if "dpop_jkt" in req:
                if refresh_token.extension is None:
                    refresh_token.extension = {"dpop_jkt": req["dpop_jkt"]}
                else:
                    refresh_token.extension["dpop_jkt"] = req["dpop_jkt"]

            _response["refresh_token"] = refresh_token.value

        code.register_usage()

        # since the grant content has changed. Make sure it's stored
        _mngr[_session_info["session_id"]] = grant

        if "openid" in _authn_req["scope"]:
            try:
                _idtoken = _context.idtoken.make(_session_info["session_id"])
            except (JWEException, NoSuitableSigningKeys) as err:
                logger.warning(str(err))
                resp = self.error_cls(
                    error="invalid_request",
                    error_description="Could not sign/encrypt id_token",
                )
                return resp

            _response["id_token"] = _idtoken

        return _response


class DPOPRefreshTokenHelper(RefreshTokenHelper):
    def process_request(self, req: Union[Message, dict], **kwargs):
        _context = self.endpoint.server_get("endpoint_context")
        _mngr = _context.session_manager

        if req["grant_type"] != "refresh_token":
            return self.error_cls(
                error="invalid_request", error_description="Wrong grant_type"
            )

        token_value = req["refresh_token"]
        _session_info = _mngr.get_session_info_by_token(
            token_value, grant=True)
        token = _mngr.find_token(_session_info["session_id"], token_value)

        _grant = _session_info["grant"]
        access_token = self._mint_token(type="access_token",
                                        grant=_grant,
                                        session_id=_session_info["session_id"],
                                        client_id=_session_info["client_id"],
                                        based_on=token)

        if "dpop_jkt" in req:
            if access_token.extension is None:
                access_token.extension = {"dpop_jkt": req["dpop_jkt"]}
            else:
                access_token.extension["dpop_jkt"] = req["dpop_jkt"]

        _resp = {
            "access_token": access_token.value,
            "token_type": access_token.token_type,
            "scope": _grant.scope
        }

        if access_token.expires_at:
            _resp["expires_in"] = access_token.expires_at - \
                utc_time_sans_frac()

        _mints = token.usage_rules.get("supports_minting")
        if "refresh_token" in _mints:
            refresh_token = self._mint_token(type="refresh_token",
                                             grant=_grant,
                                             session_id=_session_info["session_id"],
                                             client_id=_session_info["client_id"],
                                             based_on=token)
            refresh_token.usage_rules = token.usage_rules.copy()
            if "dpop_jkt" in req:
                if refresh_token.extension is None:
                    refresh_token.extension = {"dpop_jkt": req["dpop_jkt"]}
                else:
                    refresh_token.extension["dpop_jkt"] = req["dpop_jkt"]

            _resp["refresh_token"] = refresh_token.value

        if "id_token" in _mints:
            try:
                _idtoken = _context.idtoken.make(_session_info["session_id"])
            except (JWEException, NoSuitableSigningKeys) as err:
                logger.warning(str(err))
                resp = self.error_cls(
                    error="invalid_request",
                    error_description="Could not sign/encrypt id_token",
                )
                return resp

            _resp["id_token"] = _idtoken

        return _resp
