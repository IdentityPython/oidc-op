from urllib.parse import urlparse


class LoginHintLookup(object):
    def __init__(self, userinfo=None, server_get=None):
        self.userinfo = userinfo
        self.default_country_code = "46"
        self.server_get = server_get

    def __call__(self, arg):
        if arg.startswith("tel:"):
            _pnr = arg[4:]
            if _pnr[0] == "+":
                pass
            else:
                _pnr = "+" + self.default_country_code + _pnr[1:]
            return self.userinfo.search(phone_number=_pnr)
        elif arg.startswith("mail:"):
            _mail = arg[5:]
            return self.userinfo.search(email=_mail)


class LoginHint2Acrs(object):
    """
    OIDC Login hint support
    """

    def __init__(self, scheme_map, server_get=None):
        self.scheme_map = scheme_map
        self.server_get = server_get

    def __call__(self, hint):
        p = urlparse(hint)
        try:
            return self.scheme_map[p.scheme]
        except KeyError:
            return []
