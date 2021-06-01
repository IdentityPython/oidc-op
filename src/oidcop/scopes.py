# default set can be changed by configuration

SCOPE2CLAIMS = {
    "openid": ["sub"],
    "profile": [
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at",
        "preferred_username",
    ],
    "email": ["email", "email_verified"],
    "address": ["address"],
    "phone": ["phone_number", "phone_number_verified"],
    "offline_access": [],
}


def available_scopes(endpoint_context):
    _supported = endpoint_context.provider_info.get("scopes_supported")
    if _supported:
        return [s for s in endpoint_context.scope2claims.keys() if s in _supported]
    else:
        return [s for s in endpoint_context.scope2claims.keys()]


def convert_scopes2claims(scopes, allowed_claims=None, scope2claim_map=None):
    scope2claim_map = scope2claim_map or SCOPE2CLAIMS

    res = {}
    if allowed_claims is None:
        for scope in scopes:
            claims = {name: None for name in scope2claim_map[scope]}
            res.update(claims)
    else:
        for scope in scopes:
            try:
                claims = {name: None for name in scope2claim_map[scope] if name in allowed_claims}
                res.update(claims)
            except KeyError:
                continue

    return res


class Scopes:
    def __init__(self):
        pass

    def allowed_scopes(self, client_id, endpoint_context):
        """
        Returns the set of scopes that a specific client can use.

        :param client_id: The client identifier
        :param endpoint_context: A EndpointContext instance
        :returns: List of scope names. Can be empty.
        """
        _cli = endpoint_context.cdb.get(client_id)
        if _cli is not None:
            _scopes = _cli.get("allowed_scopes")
            if _scopes:
                return _scopes
            else:
                return available_scopes(endpoint_context)
        return []

    def filter_scopes(self, client_id, endpoint_context, scopes):
        allowed_scopes = self.allowed_scopes(client_id, endpoint_context)
        return [s for s in scopes if s in allowed_scopes]
