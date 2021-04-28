from typing import List

DIVIDER = ";;"


def session_key(*args) -> str:
    return DIVIDER.join(args)


def unpack_session_key(key: str) -> List[str]:
    return key.split(DIVIDER)


class Revoked(Exception):
    pass


class MintingNotAllowed(Exception):
    pass
