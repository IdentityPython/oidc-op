import logging
import os

from django.conf import settings
from oidcop.endpoint_context import EndpointContext
from oidcop.server import Server

from urllib.parse import urlparse
from oidcop.configure import Configuration

folder = os.path.dirname(os.path.realpath(__file__))
logger = logging.getLogger(__name__)


def init_oidc_op_endpoints(app):
    _config = app.srv_config.op
    _server_info_config = _config['server_info']

    iss = _server_info_config['issuer']
    if '{domain}' in iss:
        iss = iss.format(domain=app.srv_config.domain,
                         port=app.srv_config.port)
        _server_info_config['issuer'] = iss

    server = Server(_server_info_config, cwd=folder)

    for endp in server.endpoint.values():
        p = urlparse(endp.endpoint_path)
        _vpath = p.path.split('/')
        if _vpath[0] == '':
            endp.vpath = _vpath[1:]
        else:
            endp.vpath = _vpath

    return server


def oidc_provider_init_app(config, name='oidc_op', **kwargs):
    name = name or __name__
    app = type('OIDCAppEndpoint', (object,), {"srv_config": config})
    # Initialize the oidc_provider after views to be able to set correct urls
    app.endpoint_context = init_oidc_op_endpoints(app)
    return app


def oidcop_application(conf = settings.OIDCOP_CONF):
    config = Configuration(conf = conf)
    app = oidc_provider_init_app(config)
    return app
