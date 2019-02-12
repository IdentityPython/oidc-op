#/usr/bin/env python3
import logging
import os

try:
    from . import application
except ImportError:
    import application

logger = logging.getLogger("")
LOGFILE_NAME = 'floop.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

dir_path = os.path.dirname(os.path.realpath(__file__))

template_dir = os.path.join(dir_path, 'templates')

name = 'oidc_op'
app = application.oidc_provider_init_app(name, template_folder=template_dir)
logging.basicConfig(level=logging.DEBUG)

if __name__ == "__main__":
    _conf = app.config.get('CONFIG')
    web_conf = _conf['webserver']
    ssl_context = (web_conf['cert'].format(dir_path),
                   web_conf['key'].format(dir_path))
    app.run(host=app.config.get('DOMAIN'), port=app.config.get('PORT'),
            debug=True, ssl_context=ssl_context)
