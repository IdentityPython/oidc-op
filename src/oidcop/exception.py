class OidcOPError(Exception):
    pass


class OidcEndpointError(OidcOPError):
    pass


class InvalidRedirectURIError(OidcEndpointError):
    pass


class InvalidSectorIdentifier(OidcEndpointError):
    pass


class ConfigurationError(OidcEndpointError):
    pass


class NoSuchAuthentication(OidcEndpointError):
    pass


class TamperAllert(OidcEndpointError):
    pass


class ToOld(OidcEndpointError):
    pass


class MultipleUsage(OidcEndpointError):
    pass


class FailedAuthentication(OidcEndpointError):
    pass


class InstantiationError(OidcEndpointError):
    pass


class ImproperlyConfigured(OidcEndpointError):
    pass


class NotForMe(OidcEndpointError):
    pass


class UnknownAssertionType(OidcEndpointError):
    pass


class RedirectURIError(OidcEndpointError):
    pass


class ClientAuthenticationError(OidcEndpointError):
    pass


class UnknownClient(ClientAuthenticationError):
    pass


class InvalidClient(ClientAuthenticationError):
    pass


class InvalidToken(ClientAuthenticationError):
    pass


class UnAuthorizedClient(ClientAuthenticationError):
    pass


class BearerTokenAuthenticationError(OidcEndpointError):
    pass


class UnAuthorizedClientScope(OidcEndpointError):
    pass


class InvalidCookieSign(Exception):
    pass


class OnlyForTestingWarning(Warning):
    "Warned when using a feature that only should be used for testing."


class ProcessError(OidcEndpointError):
    pass


class ServiceError(OidcEndpointError):
    pass


class InvalidRequest(OidcEndpointError):
    pass


class CapabilitiesMisMatch(OidcEndpointError):
    pass


class MultipleCodeUsage(OidcEndpointError):
    pass
