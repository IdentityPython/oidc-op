"""Implements RFC7662"""
import logging
from typing import Optional

from oidcmsg import oauth2

from oidcop.endpoint import Endpoint
from oidcop.token.exception import UnknownToken
from oidcop.token.exception import WrongTokenClass

LOGGER = logging.getLogger(__name__)


class Introspection(Endpoint):
    """Implements RFC 7662"""

    request_cls = oauth2.TokenIntrospectionRequest
    response_cls = oauth2.TokenIntrospectionResponse
    request_format = "urlencoded"
    response_format = "json"
    endpoint_name = "introspection_endpoint"
    name = "introspection"

    def __init__(self, server_get, **kwargs):
        Endpoint.__init__(self, server_get, **kwargs)
        self.offset = kwargs.get("offset", 0)

    def _introspect(self, token, client_id, grant):
        # Make sure that the token is an access_token or a refresh_token
        if token.token_class not in ["access_token", "refresh_token"]:
            return None

        if not token.is_active():
            return None

        scope = token.scope
        if not scope:
            if token.based_on:
                scope = grant.find_scope(token.based_on)
            else:
                scope = grant.scope
        aud = token.resources
        if not aud:
            aud = grant.resources

        _context = self.server_get("endpoint_context")
        ret = {
            "active": True,
            "scope": " ".join(scope),
            "client_id": client_id,
            "token_class": token.token_class,
            "exp": token.expires_at,
            "iat": token.issued_at,
            "sub": grant.sub,
            "iss": _context.issuer,
        }

        try:
            _token_type = token.token_type
        except AttributeError:
            _token_type = None

        if _token_type:
            ret["token_type"] = _token_type

        if aud:
            ret["aud"] = aud

        token_args = {}
        for meth in _context.token_args_methods:
            token_args = meth(_context, client_id, token_args)

        if token_args:
            ret.update(token_args)

        return ret

    def process_request(self, request=None, release: Optional[list] = None, **kwargs):
        """

        :param request: The authorization request as a dictionary
        :param release: Information about what should be released
        :param kwargs:
        :return:
        """
        _introspect_request = self.request_cls(**request)
        if "error" in _introspect_request:
            return _introspect_request

        request_token = _introspect_request["token"]
        _resp = self.response_cls(active=False)
        _context = self.server_get("endpoint_context")

        try:
            _session_info = _context.session_manager.get_session_info_by_token(
                request_token, grant=True
            )
        except (UnknownToken, WrongTokenClass):
            return {"response_args": _resp}

        grant = _session_info["grant"]
        _token = grant.get_token(request_token)

        _info = self._introspect(_token, _session_info["client_id"], _session_info["grant"])
        if _info is None:
            return {"response_args": _resp}

        if release:
            if "username" in release:
                try:
                    _info["username"] = _session_info["user_id"]
                except KeyError:
                    pass

        _resp.update(_info)
        _resp.weed()

        _claims_restriction = grant.claims.get("introspection")
        if _claims_restriction:
            user_info = _context.claims_interface.get_user_claims(
                _session_info["user_id"], _claims_restriction
            )
            if user_info:
                _resp.update(user_info)

        _resp["active"] = True

        return {"response_args": _resp}
