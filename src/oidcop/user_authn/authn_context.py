import logging

from oidcmsg.oidc import verified_claim_name

from oidcop.util import instantiate

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)

SAML_AC = "urn:oasis:names:tc:SAML:2.0:ac:classes"
UNSPECIFIED = "{}:unspecified".format(SAML_AC)
INTERNETPROTOCOLPASSWORD = "{}:InternetProtocolPassword".format(SAML_AC)
MOBILETWOFACTORCONTRACT = "{}:MobileTwoFactorContract".format(SAML_AC)
PASSWORDPROTECTEDTRANSPORT = "{}:PasswordProtectedTransport".format(SAML_AC)
PASSWORD = "{}:Password".format(SAML_AC)
TLSCLIENT = "{}:TLSClient".format(SAML_AC)
TIMESYNCTOKEN = "{}:TimeSyncToken".format(SAML_AC)

CMP_TYPE = ["exact", "minimum", "maximum", "better"]


class AuthnBroker(object):
    def __init__(self):
        self.db = {}
        self.acr2id = {}

    def __setitem__(self, key, info):
        """
        Adds a new authentication method.

        :param value: A dictionary with metadata and configuration information
        """

        for attr in ["acr", "method"]:
            if attr not in info:
                raise ValueError('Required attribute "{}" missing'.format(attr))

        self.db[key] = info
        try:
            self.acr2id[info["acr"]].append(key)
        except KeyError:
            self.acr2id[info["acr"]] = [key]

    def __delitem__(self, key):
        _acr = self.db[key]["acr"]
        del self.db[key]
        self.acr2id[_acr].remove(key)
        if not self.acr2id[_acr]:
            del self.acr2id[_acr]

    def __getitem__(self, key):
        return self.db[key]

    def _pick_by_class_ref(self, acr):
        try:
            _ids = self.acr2id[acr]
        except KeyError:
            return []
        else:
            return [self.db[_i] for _i in _ids]

    def get_method(self, cls_name):
        """
        Generator that returns all registered authenticators based on a
        specific authentication class.

        :param acr: Authentication Class
        :return: generator
        """
        for id, spec in self.db.items():
            if spec["method"].__class__.__name__ == cls_name:
                yield spec["method"]

    def get_method_by_id(self, id):
        return self[id]["method"]

    def pick(self, acr=None):
        """
        Given the authentication context find zero or more authn methods
        that could be used.

        :param acr: The authentication class reference requested
        :return: An URL
        """

        if acr is None:
            # Anything else doesn't make sense
            return self.db.values()
        else:
            return self._pick_by_class_ref(acr)

    def get_acr_values(self):
        """Return a list of acr values"""
        return [item["acr"] for item in self.db.values()]

    def __iter__(self):
        for item in self.db.values():
            yield item["method"]

    def __len__(self):
        return len(self.db.keys())

    def default(self):
        if len(self.db) >= 1:
            return list(self.db.values())[0]
        else:
            return None


def _acr_claim(request):
    _claims = request.get("claims")
    if _claims:
        _id_token_claim = _claims.get("id_token")
        if _id_token_claim:
            _acr = _id_token_claim.get("acr")
            if "value" in _acr:
                return [_acr["value"]]
            elif "values" in _acr:
                return _acr["values"]
    return None


def pick_auth(endpoint_context, areq, pick_all=False):
    """
    Pick authentication method

    :param areq: AuthorizationRequest instance
    :return: A dictionary with the authentication method and its authn class ref
    """
    acrs = []
    if len(endpoint_context.authn_broker) == 1:
        return endpoint_context.authn_broker.default()

    if "acr_values" in areq:
        if not isinstance(areq["acr_values"], list):
            areq["acr_values"] = [areq["acr_values"]]
        acrs = areq["acr_values"]

    else:
        acrs = _acr_claim(areq)
        if not acrs:
            _ith = verified_claim_name("id_token_hint")
            if areq.get(_ith):
                _ith = areq[verified_claim_name("id_token_hint")]
                if _ith.get("acr"):
                    acrs = [_ith["acr"]]
            else:
                if areq.get("login_hint") and endpoint_context.login_hint2acrs:
                    acrs = endpoint_context.login_hint2acrs(areq["login_hint"])

    if not acrs:
        return endpoint_context.authn_broker.default()

    for acr in acrs:
        res = endpoint_context.authn_broker.pick(acr)
        logger.debug(f"Picked AuthN broker for ACR {str(acr)}: {str(res)}")
        if res:
            return res if pick_all else res[0]

    return None


def init_method(authn_spec, server_get, template_handler=None):
    try:
        _args = authn_spec["kwargs"]
    except KeyError:
        _args = {}

    if "template" in _args:
        _args["template_handler"] = template_handler

    _args["server_get"] = server_get

    args = {"method": instantiate(authn_spec["class"], **_args)}
    args.update({k: v for k, v in authn_spec.items() if k not in ["class", "kwargs"]})
    return args


def populate_authn_broker(methods, server_get, template_handler=None):
    """

    :param methods: Authentication method specifications
    :param server_get: method that returns things from server
    :param template_handler: A class used to render templates
    :return:
    """
    authn_broker = AuthnBroker()

    for id, authn_spec in methods.items():
        args = init_method(authn_spec, server_get, template_handler)
        authn_broker[id] = args

    return authn_broker
