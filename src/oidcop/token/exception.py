class ExpiredToken(Exception):
    pass


class WrongTokenType(Exception):
    pass


class WrongTokenClass(Exception):
    pass

class AccessCodeUsed(Exception):
    pass


class UnknownToken(Exception):
    pass


class NotAllowed(Exception):
    pass
