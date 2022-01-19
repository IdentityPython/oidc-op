import logging
from typing import Optional
from typing import Union

from cryptojwt.exception import JWKESTException
from cryptojwt.jwe.exception import JWEException
from oidcmsg.exception import MissingRequiredAttribute
from oidcmsg.exception import MissingRequiredValue
from oidcmsg.message import Message
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oauth2 import TokenExchangeRequest
from oidcmsg.oauth2 import TokenExchangeResponse
from oidcmsg.oidc import RefreshAccessTokenRequest
from oidcmsg.oidc import TokenErrorResponse
from oidcmsg.time_util import utc_time_sans_frac

from oidcop import sanitize
from oidcop.constant import DEFAULT_TOKEN_LIFETIME
from oidcop.endpoint import Endpoint
from oidcop.exception import ImproperlyConfigured
from oidcop.exception import ProcessError
from oidcop.exception import ToOld
from oidcop.exception import UnAuthorizedClientScope
from oidcop.oauth2.authorization import check_unknown_scopes_policy
from oidcop.session.grant import AuthorizationCode
from oidcop.session.grant import Grant
from oidcop.session.grant import RefreshToken
from oidcop.session.token import MintingNotAllowed
from oidcop.session.token import SessionToken
from oidcop.token.exception import UnknownToken
from oidcop.util import importer

logger = logging.getLogger(__name__)


class TokenEndpointHelper(object):
    def __init__(self, endpoint, config=None):
        self.endpoint = endpoint
        self.config = config
        self.error_cls = self.endpoint.error_cls

    def post_parse_request(
        self, request: Union[Message, dict], client_id: Optional[str] = "", **kwargs
    ):
        """Context specific parsing of the request.
        This is done after general request parsing and before processing
        the request.
        """
        raise NotImplementedError

    def process_request(self, req: Union[Message, dict], **kwargs):
        """Acts on a process request."""
        raise NotImplementedError

    def _mint_token(
        self,
        token_class: str,
        grant: Grant,
        session_id: str,
        client_id: str,
        based_on: Optional[SessionToken] = None,
        scope: Optional[list] = None,
        token_args: Optional[dict] = None,
        token_type: Optional[str] = "",
    ) -> SessionToken:
        _context = self.endpoint.server_get("endpoint_context")
        _mngr = _context.session_manager
        usage_rules = grant.usage_rules.get(token_class)
        if usage_rules:
            _exp_in = usage_rules.get("expires_in")
        else:
            _exp_in = DEFAULT_TOKEN_LIFETIME

        token_args = token_args or {}
        for meth in _context.token_args_methods:
            token_args = meth(_context, client_id, token_args)

        if token_args:
            _args = token_args
        else:
            _args = {}

        token = grant.mint_token(
            session_id,
            endpoint_context=_context,
            token_class=token_class,
            token_handler=_mngr.token_handler[token_class],
            based_on=based_on,
            usage_rules=usage_rules,
            scope=scope,
            token_type=token_type,
            **_args,
        )

        if _exp_in:
            if isinstance(_exp_in, str):
                _exp_in = int(_exp_in)

            if _exp_in:
                token.expires_at = utc_time_sans_frac() + _exp_in

        _context.session_manager.set(_context.session_manager.unpack_session_key(session_id), grant)

        return token


class AccessTokenHelper(TokenEndpointHelper):
    def process_request(self, req: Union[Message, dict], **kwargs):
        """

        :param req:
        :param kwargs:
        :return:
        """
        _context = self.endpoint.server_get("endpoint_context")
        _mngr = _context.session_manager
        logger.debug("Access Token")

        if req["grant_type"] != "authorization_code":
            return self.error_cls(error="invalid_request", error_description="Unknown grant_type")

        try:
            _access_code = req["code"].replace(" ", "+")
        except KeyError:  # Missing code parameter - absolutely fatal
            return self.error_cls(error="invalid_request", error_description="Missing code")

        _session_info = _mngr.get_session_info_by_token(_access_code, grant=True)
        client_id = _session_info["client_id"]
        if client_id != req["client_id"]:
            logger.debug("{} owner of token".format(client_id))
            logger.warning("Client using token it was not given")
            return self.error_cls(error="invalid_grant", error_description="Wrong client")

        if "grant_types_supported" in _context.cdb[client_id]:
            grant_types_supported = _context.cdb[client_id].get("grant_types_supported")
        else:
            grant_types_supported = _context.provider_info["grant_types_supported"]
        grant = _session_info["grant"]

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

        issue_refresh = kwargs.get("issue_refresh", False)
        _response = {
            "token_type": "Bearer",
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

        if code.is_active() is False:
            return self.error_cls(error="invalid_request", error_description="Code inactive")

        _auth_req = grant.authorization_request

        if "client_id" not in request:  # Optional for access token request
            request["client_id"] = _auth_req["client_id"]

        logger.debug("%s: %s" % (request.__class__.__name__, sanitize(request)))

        return request


class RefreshTokenHelper(TokenEndpointHelper):
    def process_request(self, req: Union[Message, dict], **kwargs):
        _context = self.endpoint.server_get("endpoint_context")
        _mngr = _context.session_manager
        logger.debug("Refresh Token")

        if req["grant_type"] != "refresh_token":
            return self.error_cls(error="invalid_request", error_description="Wrong grant_type")

        token_value = req["refresh_token"]
        _session_info = _mngr.get_session_info_by_token(token_value, grant=True)
        logger.debug("Session info: {}".format(_session_info))

        if _session_info["client_id"] != req["client_id"]:
            logger.debug("{} owner of token".format(_session_info["client_id"]))
            logger.warning("Client using token it was not given")
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
            "token_type": access_token.token_type,
            "scope": scope,
        }

        if access_token.expires_at:
            _resp["expires_in"] = access_token.expires_at - utc_time_sans_frac()

        _mints = token.usage_rules.get("supports_minting")
        issue_refresh = kwargs.get("issue_refresh", False)
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

        token.register_usage()

        if (
            "client_id" in req
            and req["client_id"] in _context.cdb
            and "revoke_refresh_on_issue" in _context.cdb[req["client_id"]]
        ):
            revoke_refresh = _context.cdb[req["client_id"]].get("revoke_refresh_on_issue")
        else:
            revoke_refresh = self.endpoint.revoke_refresh_on_issue

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

    token_types_mapping = {
        "urn:ietf:params:oauth:token-type:access_token": "access_token",
        "urn:ietf:params:oauth:token-type:refresh_token": "refresh_token",
    }

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
                "policy": {"": {"callable": default_token_exchange_policy}},
            }
        else:
            self.config = config

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
            return self.endpoint.error_cls(error="invalid_request", error_description="%s" % err)

        _mngr = _context.session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(request["subject_token"], grant=True)
        except (KeyError, UnknownToken):
            logger.error("Subject token invalid.")
            return self.error_cls(
                error="invalid_request", error_description="Subject token invalid"
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
        subject_token_types_supported = config.get(
            "subject_token_types_supported", self.token_types_mapping.keys()
        )
        subject_token_type = request["subject_token_type"]
        if subject_token_type not in subject_token_types_supported:
            return TokenErrorResponse(
                error="invalid_request",
                error_description="Unsupported subject token type",
            )
        if self.token_types_mapping[subject_token_type] != token.token_class:
            return TokenErrorResponse(
                error="invalid_request",
                error_description="Wrong token type",
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
            return self.error_cls(
                error="invalid_grant",
                error_description="Unauthorized scope requested",
            )

        if subject_token_type not in config["policy"]:
            if "" not in config["policy"]:
                raise ImproperlyConfigured(
                    "subject_token_type {subject_token_type} missing from "
                    "policy and no default is defined"
                )
            subject_token_type = ""

        policy = config["policy"][subject_token_type]
        callable = policy["callable"]
        kwargs = policy.get("kwargs", {})

        if isinstance(callable, str):
            try:
                fn = importer(callable)
            except Exception:
                raise ImproperlyConfigured(f"Error importing {callable} policy callable")
        else:
            fn = callable

        try:
            return fn(request, context=_context, subject_token=token, **kwargs)
        except Exception as e:
            logger.error(f"Error while executing the {fn} policy callable: {e}")
            return self.error_cls(error="server_error", error_description="Internal server error")

    def token_exchange_response(self, token):
        response_args = {}
        response_args["access_token"] = token.value
        response_args["scope"] = token.scope
        response_args["issued_token_type"] = token.token_class
        if token.expires_at:
            response_args["expires_in"] = token.expires_at - utc_time_sans_frac()
        if hasattr(token, "token_type"):
            response_args["token_type"] = token.token_type
        else:
            response_args["token_type"] = "N_A"

        return TokenExchangeResponse(**response_args)

    def process_request(self, request, **kwargs):
        _context = self.endpoint.server_get("endpoint_context")
        _mngr = _context.session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(request["subject_token"], grant=True)
        except ToOld:
            logger.error("Subject token has expired.")
            return self.error_cls(
                error="invalid_request", error_description="Subject token has expired"
            )
        except (KeyError, UnknownToken):
            logger.error("Subject token invalid.")
            return self.error_cls(
                error="invalid_request", error_description="Subject token invalid"
            )

        token = _mngr.find_token(_session_info["session_id"], request["subject_token"])
        _requested_token_type = request.get(
            "requested_token_type", "urn:ietf:params:oauth:token-type:access_token"
        )

        _token_class = self.token_types_mapping[_requested_token_type]

        sid = _session_info["session_id"]

        _token_type = "Bearer"
        # Is DPOP supported
        if "dpop_signing_alg_values_supported" in _context.provider_info:
            if request.get("dpop_jkt"):
                _token_type = "DPoP"

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
                _session_info = _mngr.get_session_info(session_id=sid, grant=True)
            except Exception:
                logger.error("Error retrieving token exchange session information")
                return self.error_cls(
                    error="server_error", error_description="Internal server error"
                )

        resources = request.get("resource")
        if resources and request.get("audience"):
            resources = list(set(resources + request.get("audience")))
        else:
            resources = request.get("audience")

        try:
            new_token = self._mint_token(
                token_class=_token_class,
                grant=_session_info["grant"],
                session_id=sid,
                client_id=request["client_id"],
                based_on=token,
                scope=request.get("scope"),
                token_args={
                    "resources": resources,
                },
                token_type=_token_type,
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
        if not set(request["resource"]).issubset(set(resource)):
            return TokenErrorResponse(error="invalid_target", error_description="Unknown resource")

    if "audience" in request:
        if request["subject_token_type"] == "urn:ietf:params:oauth:token-type:refresh_token":
            return TokenErrorResponse(
                error="invalid_target", error_description="Refresh token has single owner"
            )
        audience = kwargs.get("audience", [])
        if audience and not set(request["audience"]).issubset(set(audience)):
            return TokenErrorResponse(error="invalid_target", error_description="Unknown audience")

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

    if "scope" in request:
        scopes = list(set(request.get("scope")).intersection(kwargs.get("scope")))
        if scopes:
            request["scope"] = scopes
        else:
            return TokenErrorResponse(
                error="invalid_request",
                error_description="No supported scope requested",
            )

    return request

class Token(Endpoint):
    request_cls = Message
    response_cls = AccessTokenResponse
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
    }

    def __init__(self, server_get, new_refresh_token=False, **kwargs):
        Endpoint.__init__(self, server_get, **kwargs)
        self.post_parse_request.append(self._post_parse_request)
        if "client_authn_method" in kwargs:
            self.endpoint_info["token_endpoint_auth_methods_supported"] = kwargs[
                "client_authn_method"
            ]
        self.allow_refresh = False
        self.new_refresh_token = new_refresh_token
        self.configure_grant_types(kwargs.get("grant_types_supported"))
        self.revoke_refresh_on_issue = kwargs.get("revoke_refresh_on_issue", False)

    def configure_grant_types(self, grant_types_supported):
        if grant_types_supported is None:
            self.helper = {k: v(self) for k, v in self.helper_by_grant_type.items()}
            return

        self.helper = {}
        # TODO: do we want to allow any grant_type?
        for grant_type, grant_type_options in grant_types_supported.items():
            _conf = grant_type_options.get("kwargs", {})
            if _conf is False:
                continue

            try:
                grant_class = grant_type_options["class"]
            except (KeyError, TypeError):
                raise ProcessError(
                    "Token Endpoint's grant types must be True, None or a dict with a"
                    " 'class' key."
                )

            if isinstance(grant_class, str):
                try:
                    grant_class = importer(grant_class)
                except (ValueError, AttributeError):
                    raise ProcessError(
                        f"Token Endpoint's grant type class {grant_class} can't" " be imported."
                    )

            try:
                self.helper[grant_type] = grant_class(self, _conf)
            except Exception as e:
                raise ProcessError(f"Failed to initialize class {grant_class}: {e}")

    def _post_parse_request(
        self, request: Union[Message, dict], client_id: Optional[str] = "", **kwargs
    ):
        grant_type = request["grant_type"]
        _helper = self.helper.get(grant_type)
        client = kwargs["endpoint_context"].cdb[client_id]
        if "grant_types_supported" in client and grant_type not in client["grant_types_supported"]:
            return self.error_cls(
                error="invalid_request",
                error_description=f"Unsupported grant_type: {grant_type}",
            )
        if _helper:
            return _helper.post_parse_request(request, client_id, **kwargs)
        else:
            return self.error_cls(
                error="invalid_request",
                error_description=f"Unsupported grant_type: {grant_type}",
            )

    def process_request(self, request: Optional[Union[Message, dict]] = None, **kwargs):
        """

        :param request:
        :param kwargs:
        :return: Dictionary with response information
        """
        if isinstance(request, self.error_cls):
            return request

        if request is None:
            return self.error_cls(error="invalid_request")

        try:
            _helper = self.helper.get(request["grant_type"])
            if _helper:
                response_args = _helper.process_request(request, **kwargs)
            else:
                return self.error_cls(
                    error="invalid_request",
                    error_description=f"Unsupported grant_type: {request['grant_type']}",
                )
        except JWEException as err:
            return self.error_cls(error="invalid_request", error_description="%s" % err)

        if isinstance(response_args, ResponseMessage):
            return response_args

        _access_token = response_args["access_token"]
        _context = self.server_get("endpoint_context")
        _session_info = _context.session_manager.get_session_info_by_token(
            _access_token, grant=True
        )

        _cookie = _context.new_cookie(
            name=_context.cookie_handler.name["session"],
            sub=_session_info["grant"].sub,
            sid=_context.session_manager.session_key(
                _session_info["user_id"],
                _session_info["client_id"],
                _session_info["grant"].id,
            ),
        )

        _headers = [("Content-type", "application/json")]
        resp = {"response_args": response_args, "http_headers": _headers}
        if _cookie:
            resp["cookie"] = [_cookie]
        return resp
