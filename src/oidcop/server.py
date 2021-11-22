from typing import Any
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from oidcmsg.impexp import ImpExp

from oidcop import authz
from oidcop.client_authn import client_auth_setup
from oidcop.configure import ASConfiguration
from oidcop.configure import OPConfiguration
from oidcop.endpoint import Endpoint
from oidcop.endpoint_context import EndpointContext
from oidcop.endpoint_context import init_service
from oidcop.endpoint_context import init_user_info
from oidcop.session.manager import create_session_manager
from oidcop.user_authn.authn_context import populate_authn_broker
from oidcop.util import allow_refresh_token
from oidcop.util import build_endpoints


def do_endpoints(conf, server_get):
    endpoints = build_endpoints(conf["endpoint"], server_get=server_get, issuer=conf["issuer"])

    _cap = conf.get("capabilities", {})

    for endpoint, endpoint_instance in endpoints.items():
        if endpoint in ["webfinger", "provider_config"]:
            continue

        if endpoint_instance.endpoint_info:
            for key, val in endpoint_instance.endpoint_info.items():
                if key not in _cap:
                    _cap[key] = val

    return endpoints


def get_capabilities(conf, endpoints):
    _cap = conf.get("capabilities", {})
    if _cap is None:
        _cap = {}

    for endpoint, endpoint_instance in endpoints.items():
        if endpoint in ["webfinger", "provider_config"]:
            continue

        if endpoint_instance.endpoint_info:
            for key, val in endpoint_instance.endpoint_info.items():
                if key not in _cap:
                    _cap[key] = val

    return _cap


class Server(ImpExp):
    parameter = {"endpoint": [Endpoint], "endpoint_context": EndpointContext}

    def __init__(
        self,
        conf: Union[dict, OPConfiguration, ASConfiguration],
        keyjar: Optional[KeyJar] = None,
        cwd: Optional[str] = "",
        cookie_handler: Optional[Any] = None,
        httpc: Optional[Any] = None,
    ):
        ImpExp.__init__(self)
        self.conf = conf
        self.endpoint_context = EndpointContext(
            conf=conf,
            server_get=self.server_get,
            keyjar=keyjar,
            cwd=cwd,
            cookie_handler=cookie_handler,
            httpc=httpc,
        )
        self.endpoint_context.authz = self.do_authz()

        self.do_authentication(self.endpoint_context)

        self.endpoint = do_endpoints(conf, self.server_get)
        _cap = get_capabilities(conf, self.endpoint)

        self.endpoint_context.provider_info = self.endpoint_context.create_providerinfo(_cap)
        self.endpoint_context.do_add_on(endpoints=self.endpoint)

        self.endpoint_context.session_manager = create_session_manager(
            self.server_get,
            self.endpoint_context.th_args,
            sub_func=self.endpoint_context._sub_func,
            conf=self.conf,
        )
        self.endpoint_context.do_userinfo()
        # Must be done after userinfo
        self.do_login_hint_lookup()

        for endpoint_name, endpoint_conf in self.endpoint.items():
            _endpoint = self.endpoint[endpoint_name]
            _methods = _endpoint.kwargs.get("client_authn_method")

            self.client_authn_method = []
            if _methods:
                _endpoint.client_authn_method = client_auth_setup(_methods, self.server_get)
            elif _methods is not None:  # [] or '' or something not None but regarded as nothing.
                _endpoint.client_authn_method = [None]  # Ignore default value
            elif _endpoint.default_capabilities:
                _methods = _endpoint.default_capabilities.get("client_authn_method")
                if _methods:
                    _endpoint.client_authn_method = client_auth_setup(
                        auth_set=_methods, server_get=self.server_get
                    )

            _endpoint.server_get = self.server_get

        _token_endp = self.endpoint.get("token")
        if _token_endp:
            _token_endp.allow_refresh = allow_refresh_token(self.endpoint_context)

        self.endpoint_context.claims_interface = init_service(
            conf["claims_interface"], self.server_get
        )

        _id_token_handler = self.endpoint_context.session_manager.token_handler.handler.get(
            "id_token"
        )
        if _id_token_handler:
            self.endpoint_context.provider_info.update(_id_token_handler.provider_info)

    def server_get(self, what, *arg):
        _func = getattr(self, "get_{}".format(what), None)
        if _func:
            return _func(*arg)
        return None

    def get_endpoints(self, *arg):
        return self.endpoint

    def get_endpoint(self, endpoint_name, *arg):
        try:
            return self.endpoint[endpoint_name]
        except KeyError:
            return None

    def get_endpoint_context(self, *arg):
        return self.endpoint_context

    def do_authz(self):
        authz_spec = self.conf.get("authz")
        if authz_spec:
            return init_service(authz_spec, self.server_get)
        else:
            return authz.Implicit(self.server_get)

    def do_authentication(self, target):
        _conf = self.conf.get("authentication")
        if _conf:
            target.authn_broker = populate_authn_broker(
                _conf, self.server_get, target.template_handler
            )
        else:
            target.authn_broker = {}

        target.endpoint_to_authn_method = {}
        for method in target.authn_broker:
            try:
                target.endpoint_to_authn_method[method.action] = method
            except AttributeError:
                pass

    def do_login_hint_lookup(self):
        _conf = self.conf.get("login_hint_lookup")
        if _conf:
            _userinfo = None
            _kwargs = _conf.get("kwargs")
            if _kwargs:
                _userinfo_conf = _kwargs.get("userinfo")
                if _userinfo_conf:
                    _userinfo = init_user_info(_userinfo_conf, self.endpoint_context.cwd)

            if _userinfo is None:
                _userinfo = self.endpoint_context.userinfo

            self.endpoint_context.login_hint_lookup = init_service(_conf)
            self.endpoint_context.login_hint_lookup.userinfo = _userinfo
