import logging
from typing import Callable
from urllib.parse import urlsplit

from oidcmsg import oidc
from oidcmsg.oidc import Claims
from oidcmsg.oidc import verified_claim_name

from oidcop.oauth2 import authorization

logger = logging.getLogger(__name__)


def proposed_user(request):
    cn = verified_claim_name("it_token_hint")
    if request.get(cn):
        return request[cn].get("sub", "")
    return ""


def acr_claims(request):
    acrdef = None

    _claims = request.get("claims")
    if isinstance(_claims, str):
        _claims = Claims().from_json(_claims)

    if _claims:
        _id_token_claim = _claims.get("id_token")
        if _id_token_claim:
            acrdef = _id_token_claim.get("acr")

    if isinstance(acrdef, dict):
        if acrdef.get("value"):
            return [acrdef["value"]]
        elif acrdef.get("values"):
            return acrdef["values"]


def host_component(url):
    res = urlsplit(url)
    return "{}://{}".format(res.scheme, res.netloc)


ALG_PARAMS = {
    "sign": [
        "request_object_signing_alg",
        "request_object_signing_alg_values_supported",
    ],
    "enc_alg": [
        "request_object_encryption_alg",
        "request_object_encryption_alg_values_supported",
    ],
    "enc_enc": [
        "request_object_encryption_enc",
        "request_object_encryption_enc_values_supported",
    ],
}


def re_authenticate(request, authn):
    if "prompt" in request and "login" in request["prompt"]:
        if authn.done(request):
            return True

    return False


class Authorization(authorization.Authorization):
    request_cls = oidc.AuthorizationRequest
    response_cls = oidc.AuthorizationResponse
    error_cls = oidc.AuthorizationErrorResponse
    request_format = "urlencoded"
    response_format = "urlencoded"
    response_placement = "url"
    endpoint_name = "authorization_endpoint"
    name = "authorization"
    default_capabilities = {
        "claims_parameter_supported": True,
        "request_parameter_supported": True,
        "request_uri_parameter_supported": True,
        "response_types_supported": [
            "code",
            "token",
            "id_token",
            "code token",
            "code id_token",
            "id_token token",
            "code id_token token",
        ],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "request_object_signing_alg_values_supported": None,
        "request_object_encryption_alg_values_supported": None,
        "request_object_encryption_enc_values_supported": None,
        "grant_types_supported": ["authorization_code", "implicit"],
        "claim_types_supported": ["normal", "aggregated", "distributed"],
    }

    def __init__(self, server_get: Callable, **kwargs):
        authorization.Authorization.__init__(self, server_get, **kwargs)
        # self.pre_construct.append(self._pre_construct)
        self.post_parse_request.append(self._do_request_uri)
        self.post_parse_request.append(self._post_parse_request)

    def do_request_user(self, request_info, **kwargs):
        if proposed_user(request_info):
            kwargs["req_user"] = proposed_user(request_info)
        else:
            _login_hint = request_info.get("login_hint")
            if _login_hint:
                _context = self.server_get("endpoint_context")
                if _context.login_hint_lookup:
                    kwargs["req_user"] = _context.login_hint_lookup(_login_hint)
        return kwargs
