import json
import logging
from typing import Any
from typing import Callable
from typing import Optional
from typing import Union

import requests
from cryptojwt import KeyJar
from jinja2 import Environment
from jinja2 import FileSystemLoader
from oidcmsg.context import OidcContext

from oidcop import rndstr
from oidcop.configure import OPConfiguration
from oidcop.scopes import SCOPE2CLAIMS
from oidcop.scopes import Scopes
from oidcop.session.manager import SessionManager
from oidcop.template_handler import Jinja2TemplateHandler
from oidcop.util import get_http_params
from oidcop.util import importer

logger = logging.getLogger(__name__)


def add_path(url: str, path: str) -> str:
    if url.endswith("/"):
        if path.startswith("/"):
            return "{}{}".format(url, path[1:])

        return "{}{}".format(url, path)

    if path.startswith("/"):
        return "{}{}".format(url, path)

    return "{}/{}".format(url, path)


def init_user_info(conf, cwd: str):
    kwargs = conf.get("kwargs", {})

    if isinstance(conf["class"], str):
        return importer(conf["class"])(**kwargs)

    return conf["class"](**kwargs)


def init_service(conf, server_get=None):
    kwargs = conf.get("kwargs", {})

    if server_get:
        kwargs["server_get"] = server_get

    if isinstance(conf["class"], str):
        try:
            return importer(conf["class"])(**kwargs)
        except TypeError as err:
            logger.error("Could not init service class: {}".format(conf["class"]), err)
            raise

    return conf["class"](**kwargs)


def get_token_handler_args(conf: dict) -> dict:
    """

    :param conf: The configuration
    :rtype: dict
    """
    th_args = conf.get("token_handler_args", None)
    if not th_args:
        # create 3 keys
        keydef = [
            {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"},
            {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "token"},
            {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "refresh"},
        ]

        jwks_def = {
            "private_path": "private/token_jwks.json",
            "key_defs": keydef,
            "read_only": False,
        }
        th_args = {"jwks_def": jwks_def}
        for typ, tid in [("code", 600), ("token", 3600), ("refresh", 86400)]:
            th_args[typ] = {"lifetime": tid}

    return th_args


class EndpointContext(OidcContext):
    parameter = {
        "args": {},
        # "authn_broker": AuthnBroker,
        # "authz": AuthzHandling,
        "cdb": "DICT_TYPE",
        "conf": {},
        # "cookie_handler": None,
        "cwd": "",
        "endpoint_to_authn_method": {},
        "httpc_params": {},
        # "idtoken": IDToken,
        "issuer": "",
        "jti_db": {},
        "jwks_uri": "",
        "keyjar": KeyJar,
        "login_hint_lookup": None,
        "login_hint2acrs": {},
        "par_db": {},
        "provider_info": {},
        "registration_access_token": {},
        "scope2claims": {},
        # "session_db": {},
        "session_manager": SessionManager,
        "sso_ttl": None,
        "symkey": "",
        "token_args_methods": [],
        # "userinfo": UserInfo,
    }

    def __init__(
            self,
            conf: Union[dict, OPConfiguration],
            server_get: Callable,
            keyjar: Optional[KeyJar] = None,
            cwd: Optional[str] = "",
            cookie_handler: Optional[Any] = None,
            httpc: Optional[Any] = None,
    ):
        OidcContext.__init__(self, conf, keyjar, entity_id=conf.get("issuer", ""))
        self.conf = conf
        self.server_get = server_get

        _client_db = conf.get("client_db")
        if _client_db:
            logger.debug(f"Loading client db using: {_client_db}")
            self.cdb = importer(_client_db["class"])(**_client_db["kwargs"])
        else:
            logger.debug("No special client db, will use memory based dictionary")
            self.cdb = {}

        # For my Dev environment
        self.jti_db = {}
        self.registration_access_token = {}
        # self.session_db = {}

        self.cwd = cwd

        # Default values, to be changed below depending on configuration
        # arguments for endpoints add-ons
        self.add_on = {}
        self.args = {}
        self.authn_broker = None
        self.authz = None
        self.cookie_handler = cookie_handler
        self.endpoint_to_authn_method = {}
        self.httpc = httpc or requests
        self.idtoken = None
        self.issuer = ""
        self.jwks_uri = None
        self.login_hint_lookup = None
        self.login_hint2acrs = None
        self.par_db = {}
        self.provider_info = {}
        self.scope2claims = conf.get("scopes_to_claims", SCOPE2CLAIMS)
        self.session_manager = None
        self.sso_ttl = 14400  # 4h
        self.symkey = rndstr(24)
        self.template_handler = None
        self.token_args_methods = []
        self.userinfo = None

        for param in [
            "issuer",
            "sso_ttl",
            "symkey",
            "client_authn",
            # "id_token_schema",
        ]:
            try:
                setattr(self, param, conf[param])
            except KeyError:
                pass

        self.th_args = get_token_handler_args(conf)

        # session db
        self._sub_func = {}
        self.do_sub_func()

        _handler = conf.get("template_handler")
        if _handler:
            self.template_handler = _handler
        else:
            _loader = conf.get("template_loader")

            if _loader is None:
                _template_dir = conf.get("template_dir")
                if _template_dir:
                    _loader = Environment(loader=FileSystemLoader(_template_dir), autoescape=True)

            if _loader:
                self.template_handler = Jinja2TemplateHandler(_loader)

        # self.setup = {}
        _keys_conf = conf.get("key_conf")
        if _keys_conf:
            jwks_uri_path = _keys_conf["uri_path"]

            if self.issuer.endswith("/"):
                self.jwks_uri = "{}{}".format(self.issuer, jwks_uri_path)
            else:
                self.jwks_uri = "{}/{}".format(self.issuer, jwks_uri_path)

        for item in [
            "cookie_handler",
            "authentication",
            "id_token",
        ]:
            _func = getattr(self, "do_{}".format(item), None)
            if _func:
                _func()

        for item in ["login_hint2acrs"]:
            _func = getattr(self, "do_{}".format(item), None)
            if _func:
                _func()

        # which signing/encryption algorithms to use in what context
        self.jwx_def = {}

        # The HTTP clients request arguments
        _cnf = conf.get("httpc_params")
        if _cnf:
            self.httpc_params = get_http_params(_cnf)
        else:  # Backward compatibility
            self.httpc_params = {"verify": conf.get("verify_ssl", True)}

        self.set_scopes_handler()
        self.dev_auth_db = None
        self.claims_interface = None

    def new_cookie(self, name: str, max_age: Optional[int] = 0, **kwargs):
        cookie_cont = self.cookie_handler.make_cookie_content(
            name=name, value=json.dumps(kwargs), max_age=max_age
        )
        return cookie_cont

    def set_scopes_handler(self):
        _spec = self.conf.get("scopes_handler")
        if _spec:
            _kwargs = _spec.get("kwargs", {})
            _cls = importer(_spec["class"])
            self.scopes_handler = _cls(self.server_get, **_kwargs)
        else:
            self.scopes_handler = Scopes(
                self.server_get,
                allowed_scopes=self.conf.get("allowed_scopes"),
                scopes_to_claims=self.conf.get("scopes_to_claims"),
            )

    def do_add_on(self, endpoints):
        _add_on_conf = self.conf.get("add_on")
        if _add_on_conf:
            for spec in _add_on_conf.values():
                if isinstance(spec["function"], str):
                    _func = importer(spec["function"])
                else:
                    _func = spec["function"]
                _func(endpoints, **spec["kwargs"])

    def do_login_hint2acrs(self):
        _conf = self.conf.get("login_hint2acrs")

        if _conf:
            self.login_hint2acrs = init_service(_conf)
        else:
            self.login_hint2acrs = None

    def do_userinfo(self):
        _conf = self.conf.get("userinfo")
        if _conf:
            if self.session_manager:
                self.userinfo = init_user_info(_conf, self.cwd)
                self.session_manager.userinfo = self.userinfo
            else:
                logger.warning("Cannot init_user_info if no session manager was provided.")

    def do_cookie_handler(self):
        _conf = self.conf.get("cookie_handler")
        if _conf:
            if not self.cookie_handler:
                self.cookie_handler = init_service(_conf)

    def do_sub_func(self) -> None:
        """
        Loads functions that creates subject "sub" values

        :return: string
        """
        ses_par = self.conf.get("session_params") or {}
        sub_func = ses_par.get("sub_func") or {}
        for key, args in sub_func.items():
            if "class" in args:
                self._sub_func[key] = init_service(args)
            elif "function" in args:
                if isinstance(args["function"], str):
                    self._sub_func[key] = importer(args["function"])
                else:
                    self._sub_func[key] = args["function"]

    def create_providerinfo(self, capabilities):
        """
        Dynamically create the provider info response

        :param capabilities:
        :return:
        """

        _provider_info = capabilities
        _provider_info["issuer"] = self.issuer
        _provider_info["version"] = "3.0"

        # acr_values
        if self.authn_broker:
            acr_values = self.authn_broker.get_acr_values()
            if acr_values is not None:
                _provider_info["acr_values_supported"] = acr_values

        if self.jwks_uri and self.keyjar:
            _provider_info["jwks_uri"] = self.jwks_uri

        if "scopes_supported" not in _provider_info:
            _provider_info["scopes_supported"] = self.scopes_handler.get_allowed_scopes()
        if "claims_supported" not in _provider_info:
            _provider_info["claims_supported"] = list(
                self.scopes_handler.scopes_to_claims(_provider_info["scopes_supported"]).keys()
            )

        return _provider_info
