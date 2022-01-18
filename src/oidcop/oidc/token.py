import logging
from typing import Optional
from typing import Union
from urllib.parse import urlparse

from cryptojwt.exception import JWKESTException
from cryptojwt.jwe.exception import JWEException
from cryptojwt.jws.exception import NoSuitableSigningKeys
from cryptojwt.jwt import utc_time_sans_frac
from oidcmsg import oidc
from oidcmsg.message import Message
from oidcmsg.exception import MissingRequiredValue, MissingRequiredAttribute
from oidcmsg.oidc import RefreshAccessTokenRequest
from oidcmsg.oidc import TokenErrorResponse
from oidcmsg.oauth2 import (TokenExchangeRequest, ResponseMessage,
                            TokenExchangeResponse)
from oidcop import oauth2
from oidcop import sanitize
from oidcop.oauth2.authorization import check_unknown_scopes_policy
from oidcop.oauth2.token import TokenEndpointHelper
from oidcop.session.grant import AuthorizationCode
from oidcop.session.grant import RefreshToken
from oidcop.session.token import MintingNotAllowed
from oidcop.token.exception import UnknownToken
from oidcop.exception import UnAuthorizedClientScope, ToOld
from oidcop.session.token import AccessToken
from oidcop.authn_event import create_authn_event
from oidcop.util import importer

logger = logging.getLogger(__name__)


class AccessTokenHelper(TokenEndpointHelper):
    def process_request(self, req: Union[Message, dict], **kwargs):
        """

        :param req:
        :param kwargs:
        :return:
        """
        _context = self.endpoint.server_get("endpoint_context")

        _mngr = _context.session_manager
        logger.debug("OIDC Access Token")

        if req["grant_type"] != "authorization_code":
            return self.error_cls(error="invalid_request", error_description="Unknown grant_type")

        try:
            _access_code = req["code"].replace(" ", "+")
        except KeyError:  # Missing code parameter - absolutely fatal
            return self.error_cls(error="invalid_request", error_description="Missing code")

        _session_info = _mngr.get_session_info_by_token(_access_code, grant=True)
        logger.debug(f"Session info: {_session_info}")

        client_id = _session_info["client_id"]
        if client_id != req["client_id"]:
            logger.debug("{} owner of token".format(client_id))
            logger.warning("{} using token it was not given".format(req["client_id"]))
            return self.error_cls(error="invalid_grant", error_description="Wrong client")

        if "grant_types_supported" in _context.cdb[client_id]:
            grant_types_supported = _context.cdb[client_id].get("grant_types_supported")
        else:
            grant_types_supported = _context.provider_info["grant_types_supported"]
        grant = _session_info["grant"]

        token_type = "Bearer"

        # Is DPOP supported
        try:
            _dpop_enabled = _context.dpop_enabled
        except AttributeError:
            _dpop_enabled = False

        if _dpop_enabled:
            _dpop_jkt = req.get("dpop_jkt")
            if _dpop_jkt:
                grant.extra["dpop_jkt"] = _dpop_jkt
                token_type = "DPoP"

        _based_on = grant.get_token(_access_code)
        _supports_minting = _based_on.usage_rules.get("supports_minting", [])

        _authn_req = grant.authorization_request

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _authn_req:
            if req["redirect_uri"] != _authn_req["redirect_uri"]:
                return self.error_cls(
                    error="invalid_request", error_description="redirect_uri mismatch"
                )

        logger.debug("All checks OK")

        issue_refresh = kwargs.get("issue_refresh", None)
        # The existence of offline_access scope overwrites issue_refresh
        if issue_refresh is None and "offline_access" in grant.scope:
            issue_refresh = True

        _response = {
            "token_type": token_type,
            "scope": grant.scope,
        }

        if "access_token" in _supports_minting:
            try:
                token = self._mint_token(
                    token_class="access_token",
                    grant=grant,
                    session_id=_session_info["session_id"],
                    client_id=_session_info["client_id"],
                    based_on=_based_on,
                    token_type=token_type,
                )
            except MintingNotAllowed as err:
                logger.warning(err)
            else:
                _response["access_token"] = token.value
                if token.expires_at:
                    _response["expires_in"] = token.expires_at - utc_time_sans_frac()

        if (
            issue_refresh
            and "refresh_token" in _supports_minting
            and "refresh_token" in grant_types_supported
        ):
            try:
                refresh_token = self._mint_token(
                    token_class="refresh_token",
                    grant=grant,
                    session_id=_session_info["session_id"],
                    client_id=_session_info["client_id"],
                    based_on=_based_on,
                )
            except MintingNotAllowed as err:
                logger.warning(err)
            else:
                _response["refresh_token"] = refresh_token.value

        # since the grant content has changed. Make sure it's stored
        _mngr[_session_info["session_id"]] = grant

        if "openid" in _authn_req["scope"] and "id_token" in _supports_minting:
            if "id_token" in _based_on.usage_rules.get("supports_minting"):
                try:
                    _idtoken = self._mint_token(
                        token_class="id_token",
                        grant=grant,
                        session_id=_session_info["session_id"],
                        client_id=_session_info["client_id"],
                        based_on=_based_on,
                    )
                except (JWEException, NoSuitableSigningKeys) as err:
                    logger.warning(str(err))
                    resp = self.error_cls(
                        error="invalid_request",
                        error_description="Could not sign/encrypt id_token",
                    )
                    return resp

                _response["id_token"] = _idtoken.value

        _based_on.register_usage()

        return _response

    def post_parse_request(
        self, request: Union[Message, dict], client_id: Optional[str] = "", **kwargs
    ):
        """
        This is where clients come to get their access tokens

        :param request: The request
        :param client_id: Client identifier
        :returns:
        """

        _mngr = self.endpoint.server_get("endpoint_context").session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(request["code"], grant=True)
        except (KeyError, UnknownToken):
            logger.error("Access Code invalid")
            return self.error_cls(error="invalid_grant", error_description="Unknown code")

        grant = _session_info["grant"]
        code = grant.get_token(request["code"])
        if not isinstance(code, AuthorizationCode):
            return self.error_cls(error="invalid_request", error_description="Wrong token type")

        if code.used:  # Has been used already
            # invalidate all tokens that has been minted using this code
            grant.revoke_token(based_on=request["code"], recursive=True)
            return self.error_cls(error="invalid_grant", error_description="Code inactive")

        if code.is_active() is False:
            return self.error_cls(error="invalid_grant", error_description="Code inactive")

        _auth_req = grant.authorization_request

        if "client_id" not in request:  # Optional for access token request
            request["client_id"] = _auth_req["client_id"]

        logger.debug("%s: %s" % (request.__class__.__name__, sanitize(request)))

        return request


class RefreshTokenHelper(TokenEndpointHelper):
    def process_request(self, req: Union[Message, dict], **kwargs): 
        _context = self.endpoint.server_get("endpoint_context")
        _mngr = _context.session_manager

        if req["grant_type"] != "refresh_token":
            return self.error_cls(error="invalid_request", error_description="Wrong grant_type")

        token_value = req["refresh_token"]
        _session_info = _mngr.get_session_info_by_token(token_value, grant=True)
        grant = _session_info["grant"]
        audience = grant.authorization_request.get("audience", {})
        if _session_info["client_id"] != req["client_id"]:
            logger.debug("{} owner of token".format(_session_info["client_id"]))
            logger.warning("{} using token it was not given".format(req["client_id"]))
            return self.error_cls(error="invalid_grant", error_description="Wrong client")

        _grant = _session_info["grant"]

        token_type = "Bearer"

        # Is DPOP supported
        if "dpop_signing_alg_values_supported" in _context.provider_info:
            _dpop_jkt = req.get("dpop_jkt")
            if _dpop_jkt:
                _grant.extra["dpop_jkt"] = _dpop_jkt
                token_type = "DPoP"

        token = _grant.get_token(token_value)
        scope = _grant.find_scope(token.based_on)
        if "scope" in req:
            scope = req["scope"]
        access_token = self._mint_token(
            token_class="access_token",
            grant=_grant,
            session_id=_session_info["session_id"],
            client_id=_session_info["client_id"],
            based_on=token,
            scope=scope,
            token_type=token_type,
        )

        _resp = {
            "access_token": access_token.value,
            "token_type": token_type,
            "scope": scope,
        }

        if access_token.expires_at:
            _resp["expires_in"] = access_token.expires_at - utc_time_sans_frac()

        _mints = token.usage_rules.get("supports_minting")

        issue_refresh = kwargs.get("issue_refresh", None)
        # The existence of offline_access scope overwrites issue_refresh
        if issue_refresh is None and "offline_access" in scope:
            issue_refresh = True

        if "refresh_token" in _mints and issue_refresh:
            refresh_token = self._mint_token(
                token_class="refresh_token",
                grant=_grant,
                session_id=_session_info["session_id"],
                client_id=_session_info["client_id"],
                based_on=token,
                scope=scope,
            )
            refresh_token.usage_rules = token.usage_rules.copy()
            _resp["refresh_token"] = refresh_token.value

        if "id_token" in _mints and "openid" in scope:
            try:
                _idtoken = self._mint_token(
                    token_class="id_token",
                    grant=_grant,
                    session_id=_session_info["session_id"],
                    client_id=_session_info["client_id"],
                    based_on=token,
                    scope=scope,
                )
            except (JWEException, NoSuitableSigningKeys) as err:
                logger.warning(str(err))
                resp = self.error_cls(
                    error="invalid_request",
                    error_description="Could not sign/encrypt id_token",
                )
                return resp

            _resp["id_token"] = _idtoken.value

        token.register_usage()

        if (
            "client_id" in req
            and req["client_id"] in _context.cdb
            and "revoke_refresh_on_issue" in _context.cdb[req["client_id"]]
        ):
            revoke_refresh = _context.cdb[req["client_id"]].get("revoke_refresh_on_issue")
        else:
            revoke_refresh = revoke_refresh = self.endpoint.revoke_refresh_on_issue

        if revoke_refresh:
            token.revoke()

        return _resp

    def post_parse_request(
        self, request: Union[Message, dict], client_id: Optional[str] = "", **kwargs
    ):
        """
        This is where clients come to refresh their access tokens

        :param request: The request
        :param client_id: Client identifier
        :returns:
        """

        request = RefreshAccessTokenRequest(**request.to_dict())
        _context = self.endpoint.server_get("endpoint_context")
        try:
            keyjar = _context.keyjar
        except AttributeError:
            keyjar = ""

        request.verify(keyjar=keyjar, opponent_id=client_id)

        _mngr = _context.session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(request["refresh_token"], grant=True)
        except KeyError:
            logger.error("Access Code invalid")
            return self.error_cls(error="invalid_grant")

        grant = _session_info["grant"]
        token = grant.get_token(request["refresh_token"])

        if not isinstance(token, RefreshToken):
            return self.error_cls(error="invalid_request", error_description="Wrong token type")

        if token.is_active() is False:
            return self.error_cls(
                error="invalid_request", error_description="Refresh token inactive"
            )

        if "scope" in request:
            req_scopes = set(request["scope"])
            scopes = set(grant.find_scope(token.based_on))
            if not req_scopes.issubset(scopes):
                return self.error_cls(
                    error="invalid_request",
                    error_description="Invalid refresh scopes",
                )

        return request

class TokenExchangeHelper(TokenEndpointHelper):
    """Implements Token Exchange a.k.a. RFC8693"""

    def __init__(self, endpoint, config=None):
        TokenEndpointHelper.__init__(self, endpoint=endpoint, config=config)

        if config is None:
            self.config = {
                "subject_token_types_supported": [
                    "urn:ietf:params:oauth:token-type:access_token",
                    "urn:ietf:params:oauth:token-type:refresh_token",
                ],
                "requested_token_types_supported": [
                    "urn:ietf:params:oauth:token-type:access_token",
                    "urn:ietf:params:oauth:token-type:refresh_token",
                ],
                "policy": {
                    "": {
                        "callable": default_token_exchange_policy,
                        "kwargs": {
                            "scope": ["openid"]
                        }
                    }
                }
            }
        else:
            self.config = config

        self.total_subject_token_types_supported = {
            "urn:ietf:params:oauth:token-type:access_token": "access_token",
            "urn:ietf:params:oauth:token-type:refresh_token": "refresh_token"
        }

    def post_parse_request(self, request, client_id="", **kwargs):
        request = TokenExchangeRequest(**request.to_dict())

        _context = self.endpoint.server_get("endpoint_context")
        if "token_exchange" in _context.cdb[request["client_id"]]:
            config = _context.cdb[request["client_id"]]["token_exchange"]
        else:
            config = self.config

        try:
            keyjar = _context.keyjar
        except AttributeError:
            keyjar = ""

        try:
            request.verify(keyjar=keyjar, opponent_id=client_id)
        except (
            MissingRequiredAttribute,
            ValueError,
            MissingRequiredValue,
            JWKESTException,
        ) as err:
            return self.endpoint.error_cls(
                error="invalid_request", error_description="%s" % err
            )

        _mngr = _context.session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(
                request["subject_token"], grant=True
            )
        except (KeyError, UnknownToken):
            logger.error("Subject token invalid.")
            return self.error_cls(
                error="invalid_request",
                error_description="Subject token invalid"
            )

        token = _mngr.find_token(_session_info["session_id"], request["subject_token"])
        if token.is_active() is False:
            return self.error_cls(
                error="invalid_request", error_description="Subject token inactive"
            )

        resp = self._enforce_policy(request, token, config)

        return resp

    def _enforce_policy(self, request, token, config):
        _context = self.endpoint.server_get("endpoint_context")

        subject_token_types_supported = (
            self.total_subject_token_types_supported.keys()
            & config.get("subject_token_types_supported", "urn:ietf:params:oauth:token-type:access_token")
        )
        subject_token_types_supported = {
            k:self.total_subject_token_types_supported[k] for k in subject_token_types_supported
        }

        if (
            request["subject_token_type"] in subject_token_types_supported
            and (
                subject_token_types_supported[request["subject_token_type"]] != token.token_class
            )
        ):
            return self.error_cls(
                error="invalid_request", error_description="Wrong token type"
            )

        if request["subject_token_type"] not in subject_token_types_supported:
            return TokenErrorResponse(
                error="invalid_request",
                error_description="Unsupported subject token type",
            )

        if (
            "requested_token_type" in request
            and request["requested_token_type"] not in config["requested_token_types_supported"]
        ):
            return TokenErrorResponse(
                error="invalid_request",
                error_description="Unsupported requested token type",
            )

        request_info = dict(scope=request.get("scope", []))
        try:
            check_unknown_scopes_policy(request_info, request["client_id"], _context)
        except UnAuthorizedClientScope:
            logger.error("Unauthorized scope requested.")
            return self.error_cls(
                error="invalid_grant",
                error_description="Unauthorized scope requested",
            )

        try:
            subject_token_type = request.get("subject_token_type", "")
            if subject_token_type not in config["policy"]:
                subject_token_type = ""
            callable = config["policy"][subject_token_type]["callable"]
            kwargs = config["policy"][subject_token_type]["kwargs"]

            if isinstance(callable, str):
                fn = importer(callable)
            else:
                fn = callable
            return fn(request, context=_context, subject_token=token, **kwargs)

        except Exception:
            return self.error_cls(
                error="server_error",
                error_description="Internal server error"
            )

    def token_exchange_response(self, token):
        response_args = {}
        response_args["access_token"] = token.value
        response_args["scope"] = token.scope
        response_args["issued_token_type"] = token.token_class
        response_args["expires_in"] = token.usage_rules.get("expires_in", 0)
        response_args["token_type"] = "bearer"

        return TokenExchangeResponse(**response_args)

    def process_request(self, request, **kwargs):
        _context = self.endpoint.server_get("endpoint_context")
        _mngr = _context.session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(
                request["subject_token"], grant=True
            )
        except ToOld:
            logger.error("Subject token has expired.")
            return self.error_cls(
                error="invalid_request",
                error_description="Subject token has expired"
            )
        except (KeyError, UnknownToken):
            logger.error("Subject token invalid.")
            return self.error_cls(
                error="invalid_request",
                error_description="Subject token invalid"
            )

        token = _mngr.find_token(_session_info["session_id"], request["subject_token"])
        grant = _session_info["grant"]
        _requested_token_type = request.get("requested_token_type",
                                           "urn:ietf:params:oauth:token-type:access_token")

        _token_class = _requested_token_type.split(":")[-1]
        if _token_class == "access_token":
            _token_type = _token_class
        else:
            _token_type = None

        sid = _session_info["session_id"]
        if request["client_id"] != _session_info["client_id"]:
            _token_usage_rules = _context.authz.usage_rules(request["client_id"])

            sid = _mngr.create_exchange_session(
                exchange_request=request,
                original_session_id=sid,
                user_id=_session_info["user_id"],
                client_id=request["client_id"],
                token_usage_rules=_token_usage_rules,
            )

            try:
                _session_info = _mngr.get_session_info(
                    session_id=sid, grant=True)
            except Exception:
                logger.error("Error retrieving token exchabge session information")
                return self.error_cls(
                    error="server_error",
                    error_description="Internal server error"
                )

        try:
            new_token = self._mint_token(
                token_class=_token_class,
                grant=_session_info["grant"],
                session_id=sid,
                client_id=request["client_id"],
                based_on=token,
                scope=request.get("scope"),
                token_args={
                    "resources":request.get("resource"),
                },
                token_type=_token_type
            )
        except MintingNotAllowed:
            logger.error(f"Minting not allowed for {_token_class}")
            return self.error_cls(
                error="invalid_grant",
                error_description="Token Exchange not allowed with that token",
                )

        return self.token_exchange_response(token=new_token)

def default_token_exchange_policy(request, context, subject_token, **kwargs):
    if "resource" in request:
        resource = kwargs.get("resource", [])
        if not resource:
            pass
        elif (not len(set(request["resource"]).intersection(set(resource)))):
            return TokenErrorResponse(
                error="invalid_target", error_description="Unknown resource"
            )

    if "audience" in request:
        if request["subject_token_type"] == "urn:ietf:params:oauth:token-type:refresh_token":
            return TokenErrorResponse(
                error="invalid_target", error_description="Refresh token has single owner"
        )
        audience = kwargs.get("audience", [])
        if not audience:
            pass
        elif (audience and not len(set(request["audience"]).intersection(set(audience)))):
            return TokenErrorResponse(
                error="invalid_target", error_description="Unknown audience"
            )

    if "actor_token" in request or "actor_token_type" in request:
        return TokenErrorResponse(
            error="invalid_request", error_description="Actor token not supported"
        )

    if (
        "requested_token_type" in request
        and request["requested_token_type"] == "urn:ietf:params:oauth:token-type:refresh_token"
    ):
        if "offline_access" not in subject_token.scope:
            return TokenErrorResponse(
                error="invalid_request",
                error_description=f"Exchange {request['subject_token_type']} to refresh token forbbiden",
            )

    scopes = list(set(request.get("scope", ["openid"])).intersection(kwargs.get("scope", ["openid"])))
    if scopes:
        request["scope"] = scopes
    else:
        return TokenErrorResponse(
            error="invalid_request",
            error_description="No supported scope requested",
        )
    return request

class Token(oauth2.token.Token):
    request_cls = Message
    response_cls = oidc.AccessTokenResponse
    error_cls = TokenErrorResponse
    request_format = "json"
    request_placement = "body"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "token_endpoint"
    name = "token"
    default_capabilities = {"token_endpoint_auth_signing_alg_values_supported": None}
    helper_by_grant_type = {
        "authorization_code": AccessTokenHelper,
        "refresh_token": RefreshTokenHelper,
        "urn:ietf:params:oauth:grant-type:token-exchange": TokenExchangeHelper,
    }
