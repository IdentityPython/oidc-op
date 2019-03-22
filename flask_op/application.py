import os
from urllib.parse import urlparse

from cryptojwt.key_jar import init_key_jar
from flask.app import Flask
from oidcendpoint.cookie import CookieDealer
from oidcendpoint.endpoint_context import EndpointContext

folder = os.path.dirname(os.path.realpath(__file__))


def init_oidc_op_endpoints(app):
    _config = app.srv_config.op
    # _provider_config = _config['provider']
    _server_info_config = _config['server_info']

    # for path,val in app.srv_config.get('PATH').items():
    #     pos = _server_info_config
    #     part = path.split(':')
    #     for p in part[:-1]:
    #         try:
    #             pos = pos[p]
    #         except TypeError:
    #             p = int(p)
    #             pos = pos[p]
    #     pos[part[-1]] = val.format(folder)

    _kj_args = {k:v for k,v in _server_info_config['jwks'].items() if k != 'uri_path'}
    _kj = init_key_jar(**_kj_args)

    iss = _server_info_config['issuer']

    # make sure I have a set of keys under my 'real' name
    _kj.import_jwks_as_json(_kj.export_jwks_as_json(True, ''), iss)

    cookie_dealer = CookieDealer(**_server_info_config['cookie_dealer'])

    endpoint_context = EndpointContext(_server_info_config, keyjar=_kj,
                                       cwd=folder, cookie_dealer=cookie_dealer)

    for endp in endpoint_context.endpoint.values():
        p = urlparse(endp.endpoint_path)
        _vpath = p.path.split('/')
        if _vpath[0] == '':
            endp.vpath = _vpath[1:]
        else:
            endp.vpath = _vpath

    cookie_dealer.endpoint_context = endpoint_context

    return endpoint_context


def oidc_provider_init_app(config, name=None, **kwargs):
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)
    app.srv_config = config

    try:
        from .views import oidc_op_views
    except ImportError:
        from views import oidc_op_views

    app.register_blueprint(oidc_op_views)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.endpoint_context = init_oidc_op_endpoints(app)

    return app
