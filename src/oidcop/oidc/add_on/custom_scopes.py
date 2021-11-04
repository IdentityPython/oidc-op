import logging

from oidcop.scopes import SCOPE2CLAIMS

LOGGER = logging.getLogger(__name__)


def add_custom_scopes(endpoint, **kwargs):
    """
    :param endpoint: A dictionary with endpoint instances as values
    """
    # Just need an endpoint, anyone will do
    LOGGER.warning(
        "The custom_scopes add on is deprecated. The `scopes_to_claims` config "
        "option should be used instead."
    )
    _endpoint = list(endpoint.values())[0]

    _scopes2claims = SCOPE2CLAIMS.copy()
    _scopes2claims.update(kwargs)
    _context = _endpoint.server_get("endpoint_context")
    _context.scopes_handler.set_scopes_mapping(_scopes2claims)

    pi = _context.provider_info
    _scopes = set(pi.get("scopes_supported", []))
    _scopes.update(set(kwargs.keys()))
    pi["scopes_supported"] = list(_scopes)
    _context.scopes_handler.allowed_scopes = pi["scopes_supported"]

    _claims = set(pi.get("claims_supported", []))
    for vals in kwargs.values():
        _claims.update(set(vals))
    pi["claims_supported"] = list(_claims)
