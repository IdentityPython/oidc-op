import datetime
import json
import pytz

from oidcmsg.message import Message
from cryptojwt.key_jar import KeyJar

from . views import oidcop_app


def timestamp2dt(value):
    return int(datetime.datetime.timestamp(value))


def dt2timestamp(value):
    pytz.utc.localize(datetime.datetime.fromtimestamp(value))


def decode_token(txt, attr_name='access_token', verify_sign=True):
    issuer = oidcop_app.srv_config.conf['op']['server_info']['issuer']
    jwks_path = oidcop_app.srv_config.conf['OIDC_KEYS']['private_path']
    jwks = json.loads(open(jwks_path).read())

    key_jar = KeyJar()
    key_jar.import_jwks(jwks, issuer=issuer)

    jwt = json.loads(txt)
    msg = Message().from_jwt(jwt.get(attr_name, ''),
                             keyjar=key_jar,
                             verify=verify_sign)
    return msg
