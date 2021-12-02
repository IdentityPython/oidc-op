import json
import logging
from datetime import datetime
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt.exception import MissingValue
from cryptojwt.jwt import JWT
from cryptojwt.jwt import utc_time_sans_frac
from oidcmsg import oidc
from oidcmsg.message import Message
from oidcmsg.oauth2 import ResponseMessage

from oidcop.endpoint import Endpoint
from oidcop.token.exception import UnknownToken
from oidcop.util import OAUTH2_NOCACHE_HEADERS

logger = logging.getLogger(__name__)


class UserInfo(Endpoint):
    request_cls = Message
    response_cls = oidc.OpenIDSchema
    request_format = "json"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "userinfo_endpoint"
    name = "userinfo"
    default_capabilities = {
        "claim_types_supported": ["normal", "aggregated", "distributed"],
        "userinfo_signing_alg_values_supported": None,
        "userinfo_encryption_alg_values_supported": None,
        "userinfo_encryption_enc_values_supported": None,
        "client_authn_method": ["bearer_header", "bearer_body"],
    }

    def __init__(self, server_get: Callable, add_claims_by_scope: Optional[bool] = True, **kwargs):
        Endpoint.__init__(
            self,
            server_get,
            add_claims_by_scope=add_claims_by_scope,
            **kwargs,
        )
        # Add the issuer ID as an allowed JWT target
        self.allowed_targets.append("")

    def get_client_id_from_token(self, endpoint_context, token, request=None):
        _info = endpoint_context.session_manager.get_session_info_by_token(token)
        return _info["client_id"]

    def do_response(
        self,
        response_args: Optional[Union[Message, dict]] = None,
        request: Optional[Union[Message, dict]] = None,
        client_id: Optional[str] = "",
        **kwargs
    ) -> dict:

        if "error" in kwargs and kwargs["error"]:
            return Endpoint.do_response(self, response_args, request, **kwargs)

        _context = self.server_get("endpoint_context")
        if not client_id:
            raise MissingValue("client_id")

        # Should I return a JSON or a JWT ?
        _cinfo = _context.cdb[client_id]

        # default is not to sign or encrypt
        try:
            sign_alg = _cinfo["userinfo_signed_response_alg"]
            sign = True
        except KeyError:
            sign_alg = ""
            sign = False

        try:
            enc_enc = _cinfo["userinfo_encrypted_response_enc"]
            enc_alg = _cinfo["userinfo_encrypted_response_alg"]
            encrypt = True
        except KeyError:
            encrypt = False
            enc_alg = enc_enc = ""

        if encrypt or sign:
            _jwt = JWT(
                _context.keyjar,
                iss=_context.issuer,
                sign=sign,
                sign_alg=sign_alg,
                encrypt=encrypt,
                enc_enc=enc_enc,
                enc_alg=enc_alg,
            )

            resp = _jwt.pack(response_args, recv=client_id)
            content_type = "application/jwt"
        else:
            if isinstance(response_args, dict):
                resp = json.dumps(response_args)
            else:
                resp = response_args.to_json()
            content_type = "application/json"

        http_headers = [("Content-type", content_type)]
        http_headers.extend(OAUTH2_NOCACHE_HEADERS)

        return {"response": resp, "http_headers": http_headers}

    def process_request(self, request=None, **kwargs):
        _mngr = self.server_get("endpoint_context").session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(request["access_token"], grant=True)
        except (KeyError, ValueError):
            return self.error_cls(error="invalid_token", error_description="Invalid Token")

        _grant = _session_info["grant"]
        token = _grant.get_token(request["access_token"])
        # should be an access token
        if token and token.token_class != "access_token":
            return self.error_cls(error="invalid_token", error_description="Wrong type of token")

        # And it should be valid
        if token.is_active() is False:
            return self.error_cls(error="invalid_token", error_description="Invalid Token")

        allowed = True
        _auth_event = _grant.authentication_event
        # if the authenticate is still active or offline_access is granted.
        if not _auth_event["valid_until"] >= utc_time_sans_frac():
            logger.debug(
                "authentication not valid: {} > {}".format(
                    datetime.fromtimestamp(_auth_event["valid_until"]),
                    datetime.fromtimestamp(utc_time_sans_frac()),
                )
            )
            allowed = False

            # This has to be made more fine grained.
            # if "offline_access" in session["authn_req"]["scope"]:
            #     pass

        if allowed:
            _claims = _grant.claims.get("userinfo")
            info = self.server_get("endpoint_context").claims_interface.get_user_claims(
                user_id=_session_info["user_id"], claims_restriction=_claims
            )
            info["sub"] = _grant.sub
            if _grant.add_acr_value("userinfo"):
                info["acr"] = _grant.authentication_event["authn_info"]
        else:
            info = {
                "error": "invalid_request",
                "error_description": "Access not granted",
            }

        return {"response_args": info, "client_id": _session_info["client_id"]}

    def parse_request(self, request, http_info=None, **kwargs):
        """

        :param request:
        :param auth:
        :param kwargs:
        :return:
        """

        if not request:
            request = {}

        # Verify that the client is allowed to do this
        try:
            auth_info = self.client_authentication(request, http_info, **kwargs)
        except (ValueError, UnknownToken) as e:
            return self.error_cls(error="invalid_token", error_description=e.args[0])

        if isinstance(auth_info, ResponseMessage):
            return auth_info
        else:
            request["client_id"] = auth_info["client_id"]
            request["access_token"] = auth_info["token"]

        return request
