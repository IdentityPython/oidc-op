#!/usr/bin/env python3
import logging
import os

import argparse

from oidcop.configure import Configuration

try:
    from .application import oidc_provider_init_app
except ModuleNotFoundError:
    from application import oidc_provider_init_app

dir_path = os.path.dirname(os.path.realpath(__file__))


def main(config_file):
    logging.basicConfig(level=logging.DEBUG)
    config = Configuration.create_from_config_file(config_file)
    app = oidc_provider_init_app(config, 'oidc_op')

    web_conf = config.webserver
    ssl_context = (web_conf['cert'].format(dir_path),
                   web_conf['key'].format(dir_path))

    app.run(host=web_conf['domain'], port=web_conf['port'],
            debug=web_conf['debug'], ssl_context=ssl_context)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='tls', action='store_true')
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument(dest="config")
    args = parser.parse_args()
    main(args.config)
