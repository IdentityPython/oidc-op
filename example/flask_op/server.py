#!/usr/bin/env python3
import argparse
import json
import logging
import os

from oidcmsg.configure import Configuration
from oidcmsg.configure import create_from_config_file

from oidcop.configure import OPConfiguration
from oidcop.utils import create_context

try:
    from .application import oidc_provider_init_app
except (ModuleNotFoundError, ImportError):
    from application import oidc_provider_init_app

dir_path = os.path.dirname(os.path.realpath(__file__))

logger = logging.getLogger(__name__)


# class PeerCertWSGIRequestHandler(werkzeug.serving.WSGIRequestHandler):
#     """
#     We subclass this class so that we can gain access to the connection
#     property. self.connection is the underlying client socket. When a TLS
#     connection is established, the underlying socket is an instance of
#     SSLSocket, which in turn exposes the getpeercert() method.
#
#     The output from that method is what we want to make available elsewhere
#     in the application.
#     """
#
#     def make_environ(self):
#         """
#         The superclass method develops the environ hash that eventually
#         forms part of the Flask request object.
#
#         We allow the superclass method to run first, then we insert the
#         peer certificate into the hash. That exposes it to us later in
#         the request variable that Flask provides
#         """
#         environ = super(PeerCertWSGIRequestHandler, self).make_environ()
#         x509_binary = self.connection.getpeercert(True)
#         if x509_binary:
#             x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509_binary)
#             environ['peercert'] = x509
#         else:
#             logger.warning('No peer certificate')
#             environ['peercert'] = ''
#         return environ


def main(config_file, args):
    logging.basicConfig(level=logging.DEBUG)
    config = create_from_config_file(Configuration,
                                     entity_conf=[{
                                         "class": OPConfiguration, "attr": "op",
                                         "path": ["op", "server_info"]
                                     }],
                                     filename=config_file,
                                     base_path=dir_path)
    app = oidc_provider_init_app(config.op, 'oidc_op')
    app.logger = config.logger

    web_conf = config.web_conf

    context = create_context(dir_path, web_conf)

    if args.display:
        print(json.dumps(app.endpoint_context.provider_info, indent=4, sort_keys=True))
        exit(0)

    kwargs = {}
    if context:
        kwargs["ssl_context"] = context
        # kwargs["request_handler"] = PeerCertWSGIRequestHandler

    app.run(host=web_conf['domain'], port=web_conf['port'], debug=web_conf['debug'], **kwargs)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='display', action='store_true')
    parser.add_argument('-t', dest='tls', action='store_true')
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument(dest="config")
    args = parser.parse_args()
    main(args.config, args)
