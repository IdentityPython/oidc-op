from oidcop.exception import OidcOPError


class TokenException(OidcOPError):
    pass


class ExpiredToken(TokenException):
    pass


class WrongTokenType(TokenException):
    pass


class WrongTokenClass(TokenException):
    pass


class AccessCodeUsed(TokenException):
    pass


class UnknownToken(TokenException):
    pass


class NotAllowed(TokenException):
    pass


class InvalidToken(TokenException):
    pass
