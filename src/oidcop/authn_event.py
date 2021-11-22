from oidcmsg.message import SINGLE_OPTIONAL_INT
from oidcmsg.message import SINGLE_OPTIONAL_STRING
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.message import Message
from oidcmsg.time_util import utc_time_sans_frac

DEFAULT_AUTHN_EXPIRES_IN = 3600


class AuthnEvent(Message):
    c_param = {
        "uid": SINGLE_REQUIRED_STRING,
        "authn_info": SINGLE_REQUIRED_STRING,
        "authn_time": SINGLE_OPTIONAL_INT,
        "valid_until": SINGLE_OPTIONAL_INT,
        "sub": SINGLE_OPTIONAL_STRING,
    }

    def is_valid(self, now=0):
        if now:
            return self["valid_until"] > now
        else:
            return self["valid_until"] > utc_time_sans_frac()

    def expires_in(self):
        return self["valid_until"] - utc_time_sans_frac()


def create_authn_event(
    uid,
    authn_info=None,
    authn_time: int = 0,
    valid_until: int = 0,
    expires_in: int = 0,
    sub: str = "",
    **kwargs
):
    """

    :param uid: User ID. This is the identifier used by the user DB
    :param authn_time: When the authentication took place
    :param authn_info: Information about the authentication
    :param valid_until: Until when the authentication is valid
    :param expires_in: How long before the authentication expires
    :param sub: Subject identifier. The identifier for the user used between
        the AS and the RP.
    :param kwargs:
    :return:
    """
    args = {"uid": uid, "authn_info": authn_info}

    if sub:
        args["sub"] = sub

    if authn_time:
        args["authn_time"] = authn_time
    else:
        _ts = kwargs.get("timestamp")
        if _ts:
            args["authn_time"] = _ts
        else:
            args["authn_time"] = utc_time_sans_frac()

    if valid_until:
        args["valid_until"] = valid_until
    else:
        if expires_in:
            args["valid_until"] = args["authn_time"] + expires_in
        else:
            args["valid_until"] = args["authn_time"] + DEFAULT_AUTHN_EXPIRES_IN

    return AuthnEvent(**args)
