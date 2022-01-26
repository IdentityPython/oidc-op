import logging
from typing import Optional
from typing import Union

from oidcmsg.oidc import OpenIDSchema

from oidcop.exception import ImproperlyConfigured
from oidcop.exception import ServiceError

logger = logging.getLogger(__name__)

# USAGE = Literal["userinfo", "id_token", "introspection"]

IGNORE = ["error", "error_description", "error_uri", "_claim_names", "_claim_sources"]
STANDARD_CLAIMS = [c for c in OpenIDSchema.c_param.keys() if c not in IGNORE]


def available_claims(endpoint_context):
    _supported = endpoint_context.provider_info.get("claims_supported")
    if _supported:
        return _supported
    else:
        return STANDARD_CLAIMS


class ClaimsInterface:
    init_args = {"add_claims_by_scope": False, "enable_claims_per_client": False}
    claims_release_points = ["userinfo", "introspection", "id_token", "access_token"]

    def __init__(self, server_get):
        self.server_get = server_get

    def authorization_request_claims(
        self,
        authorization_request: dict,
        claims_release_point: Optional[str] = "",
    ) -> dict:
        if authorization_request and "claims" in authorization_request:
            return authorization_request["claims"].get(claims_release_point, {})

        return {}

    def _get_module(self, usage, endpoint_context):
        module = None
        if usage == "userinfo":
            module = self.server_get("endpoint", "userinfo")
        elif usage == "id_token":
            try:
                module = endpoint_context.session_manager.token_handler["id_token"]
            except KeyError:
                raise ServiceError("No support for ID Tokens")
        elif usage == "introspection":
            module = self.server_get("endpoint", "introspection")
        elif usage == "access_token":
            try:
                module = endpoint_context.session_manager.token_handler["access_token"]
            except KeyError:
                raise ServiceError("No support for Access Tokens")

        return module

    def _client_claims(
        self,
        client_id: str,
        module: object,
        claims_release_point: str,
        secondary_identifier: Optional[str] = "",
    ):
        _context = self.server_get("endpoint_context")
        add_claims_by_scope = _context.cdb[client_id].get("add_claims", {}).get("by_scope", {})
        if add_claims_by_scope:
            _claims_by_scope = add_claims_by_scope.get(claims_release_point, False)
            if not _claims_by_scope and secondary_identifier:
                _claims_by_scope = add_claims_by_scope.get(secondary_identifier, False)

            if not _claims_by_scope:
                _claims_by_scope = module.kwargs.get("add_claims_by_scope", {})
        else:
            _claims_by_scope = module.kwargs.get("add_claims_by_scope", {})

        add_claims_always = _context.cdb[client_id].get("add_claims", {}).get("always", {})
        _always_add = add_claims_always.get(claims_release_point, [])
        if secondary_identifier:
            _always_2 = add_claims_always.get(secondary_identifier, [])
            _always_add.extend(_always_2)

        return _claims_by_scope, _always_add

    def get_claims_from_request(
        self,
        auth_req: dict,
        claims_release_point: str,
        scopes: str = None,
        client_id: str = None,
        secondary_identifier: str = "",
    ) -> dict:
        _context = self.server_get("endpoint_context")
        # which endpoint module configuration to get the base claims from
        module = self._get_module(claims_release_point, _context)

        # claims that are always returned to any client.
        if module:
            base_claims = module.kwargs.get("base_claims", {}).copy()
        else:
            return {}

        if not client_id:
            client_id = auth_req.get("client_id")

        # If specific client configuration exists overwrite add_claims_by_scope
        if module.kwargs.get("enable_claims_per_client") and client_id in _context.cdb:
            _claims_by_scope, _always_add = self._client_claims(
                client_id, module, claims_release_point, secondary_identifier
            )
        else:
            _claims_by_scope = module.kwargs.get("add_claims_by_scope")
            _always_add = module.kwargs.get("always_add_claims", {})

        if _always_add:
            if isinstance(_always_add, list):
                base_claims.update({k: None for k in _always_add})
            else:
                base_claims.update(_always_add)

        if _claims_by_scope:
            if scopes is None:
                scopes = auth_req.get("scope")
            if scopes:
                _claims = _context.scopes_handler.scopes_to_claims(scopes, client_id=client_id)
                base_claims.update(_claims)

        # Bring in claims specification from the authorization request
        # This only goes for ID Token and user info
        request_claims = self.authorization_request_claims(
            authorization_request=auth_req, claims_release_point=claims_release_point
        )

        # This will add claims that has not be added before and
        # set filters on those claims that also appears in one of the sources
        # above
        if request_claims:
            base_claims.update(request_claims)

        return base_claims

    def get_claims(
        self,
        session_id: str,
        scopes: str,
        claims_release_point: str,
        secondary_identifier: Optional[str] = "",
    ) -> dict:
        """

        :param secondary_identifier: If claims should also be release by the rules for this
            release_point.
        :param session_id: Session identifier
        :param scopes: Scopes
        :param claims_release_point: Where to release the claims. One of
            "userinfo"/"id_token"/"introspection"/"access_token"
        :return: Claims specification as a dictionary.
        """
        _context = self.server_get("endpoint_context")
        session_info = _context.session_manager.get_session_info(session_id, grant=True)
        client_id = session_info["client_id"]
        grant = session_info["grant"]

        if grant.authorization_request:
            auth_req = grant.authorization_request
        else:
            auth_req = {}
        claims = self.get_claims_from_request(
            auth_req=auth_req,
            claims_release_point=claims_release_point,
            scopes=scopes,
            client_id=client_id,
            secondary_identifier=secondary_identifier,
        )

        return claims

    def get_claims_all_usage_from_request(
        self, auth_req: dict, scopes: str = None, client_id: str = None
    ) -> dict:
        _claims = {}
        for usage in self.claims_release_points:
            _claims[usage] = self.get_claims_from_request(
                auth_req, usage, scopes=scopes, client_id=client_id
            )
        return _claims

    def get_claims_all_usage(self, session_id: str, scopes: str) -> dict:
        grant = self.server_get("endpoint_context").session_manager.get_grant(session_id)
        if grant.authorization_request:
            auth_req = grant.authorization_request
        else:
            auth_req = {}
        return self.get_claims_all_usage_from_request(auth_req, scopes)

    def get_user_claims(self, user_id: str, claims_restriction: dict) -> dict:
        """

        :param user_id: User identifier
        :param claims_restriction: Specifies the upper limit of which claims can be returned
        :return:
        """
        meth = self.server_get("endpoint_context").userinfo
        if not meth:
            raise ImproperlyConfigured("userinfo MUST be defined in the configuration")
        if claims_restriction:
            # Get all possible claims
            user_info = meth(user_id, client_id=None)
            # Filter out the claims that can be returned
            return {
                k: user_info.get(k)
                for k, v in claims_restriction.items()
                if claims_match(user_info.get(k), v)
            }
        else:
            return {}


def claims_match(value: Union[str, int], claimspec: Optional[dict]) -> bool:
    """
    Implements matching according to section 5.5.1 of
    http://openid.net/specs/openid-connect-core-1_0.html
    The lack of value is not checked here.
    Also the text doesn't prohibit having both 'value' and 'values'.

    :param value: single value
    :param claimspec: None or dictionary with 'essential', 'value' or 'values'
        as key
    :return: Boolean
    """
    if value is None:
        return False

    if claimspec is None:  # match anything
        return True

    matched = False
    for key, val in claimspec.items():
        if key == "value":
            if value == val:
                matched = True
        elif key == "values":
            if value in val:
                matched = True
        elif key == "essential":
            # Whether it's essential or not doesn't change anything here
            continue

        if matched:
            break

    if matched is False:
        if list(claimspec.keys()) == ["essential"]:
            return True

    return matched


def by_schema(cls, **kwa):
    """
    Will return only those claims that are listed in the Class definition.

    :param cls: A subclass of :py:class:´oidcmsg.message.Message`
    :param kwa: Keyword arguments
    :return: A dictionary with claims (keys) that meets the filter criteria
    """
    return dict([(key, val) for key, val in kwa.items() if key in cls.c_param])


class OAuth2ClaimsInterface(ClaimsInterface):
    claims_release_points = ["introspection", "access_token"]

    def _get_module(self, usage, endpoint_context):
        module = None
        if usage == "introspection":
            module = self.server_get("endpoint", "introspection")
        elif usage == "access_token":
            try:
                module = endpoint_context.session_manager.token_handler["access_token"]
            except KeyError:
                raise ServiceError("No support for Access Tokens")

        return module

    def get_claims_all_usage(self, session_id: str, scopes: str) -> dict:
        _claims = {}
        for usage in self.claims_release_points:
            _claims[usage] = self.get_claims(session_id, scopes, usage)
        return _claims
