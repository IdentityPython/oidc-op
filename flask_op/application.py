import os
from urllib.parse import urlparse

from cryptojwt.key_jar import init_key_jar
from flask.app import Flask
from oidcendpoint.endpoint_context import EndpointContext

folder = os.path.dirname(os.path.realpath(__file__))


def init_oidc_op_endpoints(app):
    _config = app.srv_config.op
    _server_info_config = _config['server_info']

    iss = _server_info_config['issuer']
    if '{domain}' in iss:
        iss = iss.format(domain=app.srv_config.domain,
                         port=app.srv_config.port)
        _server_info_config['issuer'] = iss

    _kj_args = {k:v for k,v in _server_info_config['jwks'].items() if k != 'uri_path'}
    _kj = init_key_jar(**_kj_args)
    # make sure I have a set of keys under my 'real' name
    _kj.import_jwks_as_json(_kj.export_jwks_as_json(True, ''), iss)

    endpoint_context = EndpointContext(_server_info_config, keyjar=_kj, cwd=folder)

    # sort of backward but work so...
    _kj.httpc_params = endpoint_context.httpc_params

    for endp in endpoint_context.endpoint.values():
        p = urlparse(endp.endpoint_path)
        _vpath = p.path.split('/')
        if _vpath[0] == '':
            endp.vpath = _vpath[1:]
        else:
            endp.vpath = _vpath

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
