import copy
import json

__author__ = "rolandh"


def dict_subset(a, b):
    for attr, values in a.items():
        try:
            _val = b[attr]
        except KeyError:
            return False
        else:
            if isinstance(_val, list):
                if isinstance(values, list):
                    if not set(values).issubset(set(_val)):
                        return False
                else:
                    if values not in _val:
                        return False
            else:
                if isinstance(values, list):
                    return False
                else:
                    if values != _val:
                        return False
    return True


class UserInfo(object):
    """ Read only interface to a user info store """

    def __init__(self, db=None, db_file=""):
        if db is not None:
            self.db = db
        elif db_file:
            self.db = json.loads(open(db_file).read())
        else:
            self.db = {}

    def filter(self, userinfo, user_info_claims=None):
        """
        Return only those claims that are asked for.
        It's a best effort task; if essential claims are not present
        no error is flagged.

        :param userinfo: A dictionary containing the available info for one user
        :param user_info_claims: A dictionary specifying the asked for claims
        :return: A dictionary of filtered claims.
        """

        if user_info_claims is None:
            return copy.copy(userinfo)
        else:
            result = {}
            missing = []
            optional = []
            for key, restr in user_info_claims.items():
                try:
                    result[key] = userinfo[key]
                except KeyError:
                    if restr == {"essential": True}:
                        missing.append(key)
                    else:
                        optional.append(key)
            return result

    def __call__(self, user_id, client_id, user_info_claims=None, **kwargs):
        try:
            return self.filter(self.db[user_id], user_info_claims)
        except KeyError:
            return {}

    def search(self, **kwargs):
        for uid, args in self.db.items():
            if dict_subset(kwargs, args):
                return uid

        raise KeyError("No matching user")
