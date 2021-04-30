import os
import re
import requests
import json
import urllib
import urllib3

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar

from oidcmsg.message import Message
from oidcrp import rp_handler
from oidcrp.util import load_yaml_config

RPHandler = rp_handler.RPHandler

def decode_token(bearer_token, keyjar, verify_sign=True):
    msg = Message().from_jwt(bearer_token,
                             keyjar=keyjar,
                             verify=verify_sign)
    return msg.to_dict()


def init_oidc_rp_handler(app):
    _rp_conf = app.config

    if _rp_conf.get('rp_keys'):
        _kj = init_key_jar(**_rp_conf['rp_keys'])
        _path = _rp_conf['rp_keys']['public_path']
        # removes ./ and / from the begin of the string
        _path = re.sub('^(.)/', '', _path)
    else:
        _kj = KeyJar()
        _path = ''
    _kj.httpc_params = _rp_conf['httpc_params']
    hash_seed = app.config.get('hash_seed', "BabyHoldOn")
    rph = RPHandler(_rp_conf['base_url'], _rp_conf['clients'], services=_rp_conf['services'],
                    hash_seed=hash_seed, keyjar=_kj, jwks_path=_path,
                    httpc_params=_rp_conf['httpc_params']) #, verify_ssl=False)

    return rph


def get_rph(config_fname):
    config = load_yaml_config(config_file)
    app = type('RPApplication', (object,), {"config": config})
    rph = init_oidc_rp_handler(app)
    return rph


def fancy_print(msg, dict_obj):
    print('\n\n{}\n'.format(msg),
          json.dumps(dict_obj, indent=2) if dict_obj else '')


def run_rp_session(rph, issuer_id, username, password):
    # register client (provider info and client registration)
    info = rph.begin(issuer_id)

    issuer_fqdn = rph.hash2issuer[issuer_id]
    issuer_keyjar = rph.issuer2rp[issuer_fqdn]

    fancy_print("Client registration done...\n"
                "Connecting to Authorization url:",
                info)

    # info contains the url to the authorization endpoint
    # {'url': 'https://127.0.0.1:8000/authorization?redirect_uri=https%3A%2F%2F127.0.0.1%3A8099%2Fauthz_cb%2Fdjango_oidc_op&scope=openid+profile+email+address+phone&response_type=code&nonce=HhDGhvuIoQ9MaVLSqXi3D6r4&state=AdgqZVTxwdHaE9kjRUCLTnI78GpoQq90&code_challenge=v3UDlTl4qOrbA1owsEBdKMHwSubmvheGrjUiBeCQqhk&code_challenge_method=S256&client_id=shoInN4jcqIe', 'state': 'AdgqZVTxwdHaE9kjRUCLTnI78GpoQq90'}

    print('\nStarting connection to Authorization URL')
    res = requests.get(info['url'], verify=rph.verify_ssl)

    # this contains the html form
    #  res.text

    #'<!doctype html>\n\n<html lang="en">\n<head>\n    <meta charset="utf-8">\n    <title>Please login</title>\n</head>\n\n<body>\n<h1>Testing log in</h1>\n\n<form action="verify/oidc_user_login/" method="post">\n    <input type="hidden" name="token" value="eyJhbGciOiJSUzI1NiIsImtpZCI6ImJXdG9SekV4VXkxak9GVXlSV2hwZUdkbFREWlBaME55TW1ka05ERlFaakJSUzJreVQwaExVazVJUVEifQ.eyJhdXRobl9jbGFzc19yZWYiOiAib2lkY2VuZHBvaW50LnVzZXJfYXV0aG4uYXV0aG5fY29udGV4dC5JTlRFUk5FVFBST1RPQ09MUEFTU1dPUkQiLCAicXVlcnkiOiAicmVkaXJlY3RfdXJpPWh0dHBzJTNBJTJGJTJGMTI3LjAuMC4xJTNBODA5OSUyRmF1dGh6X2NiJTJGZGphbmdvX29pZGNfb3Amc2NvcGU9b3BlbmlkK3Byb2ZpbGUrZW1haWwrYWRkcmVzcytwaG9uZSZyZXNwb25zZV90eXBlPWNvZGUmbm9uY2U9SGhER2h2dUlvUTlNYVZMU3FYaTNENnI0JnN0YXRlPUFkZ3FaVlR4d2RIYUU5a2pSVUNMVG5JNzhHcG9RcTkwJmNvZGVfY2hhbGxlbmdlPXYzVURsVGw0cU9yYkExb3dzRUJkS01Id1N1Ym12aGVHcmpVaUJlQ1FxaGsmY29kZV9jaGFsbGVuZ2VfbWV0aG9kPVMyNTYmY2xpZW50X2lkPXNob0luTjRqY3FJZSIsICJyZXR1cm5fdXJpIjogImh0dHBzOi8vMTI3LjAuMC4xOjgwOTkvYXV0aHpfY2IvZGphbmdvX29pZGNfb3AiLCAiaXNzIjogImh0dHBzOi8vMTI3LjAuMC4xOjgwMDAiLCAiaWF0IjogMTU3NTg4Mzk3MX0.LZC8SU-4jN4Ktzdj4lYl-qW5o8uhvA17Pw4l0Ugj0Wg7pBx4ZyjJ_o8PQ_Q1qoOZ-2wpMFgGma1KFbHqHGP0FGDzMErytLiLkLz1dLzXCvKbjtnf9IYRbIIS92e2we68ikC9_H9lPFcs705Egmrq3oRx759VBj-7dD5LOc2qSTMiuLx9EJ8sUFP4lq5nISQw7gueJttPD6YRlZQ4tbJTa2l6afbkoRXUTt411UAVCSROP-9QXhFRdVQgtpg4I7Ndppj2ihPJIqzn5PbH9RcmLkW-tEVAxk7UQH6pEKBgoiouNHmpZjiwza7t41MQuqDJBJJ56o7HGaebd8_L7OGt8w">\n\n    <p>\n        <label for="username">Nickname</label>\n        <input type="text" id="username" name="username" autofocus\n               required>\n    </p>\n\n    <p>\n        <label for="password">Secret sauce</label>\n        <input type="password" id="password" name="password" required>\n    </p>\n\n    <p>\n        <img src="" alt="">\n    </p>\n    <p>\n        <a href=""></a>\n    </p>\n    <p>\n        <a href=""></a>\n    </p>\n\n    <input type="submit" value="Get me in!">\n</form>\n</body>\n</html>\n'
    try:
        auth_code = re.search('value="(?P<token>[a-zA-Z\-\.\_0-9]*)"', res.text).groupdict()['token']
        auth_url = re.search('action="(?P<url>[a-zA-Z0-9\/\-\_\.\:]*)"', res.text).groupdict()['url']
    except Exception as e:
        print(res.text)
        raise Exception(res.text)

    fancy_print("The Authorization endpoint returns a "
                "HTML authentication form with a token",
                {'token': auth_code,
                 'url': auth_url})

    fancy_print('Authorization code content: ',
                decode_token(auth_code,
                             keyjar=issuer_keyjar.get_service_context().keyjar
,
                             verify_sign=False))

    auth_dict = {'username': username,
                 'password': password,
                 'token': auth_code}

    auth_url = '/'.join((issuer_fqdn, auth_url))
    print('Credential form submit ...')
    req = requests.post(auth_url,
                        data=auth_dict, verify=rph.verify_ssl,
                        allow_redirects=False)
    print('Credential form submitted!')

    # req is a 302, a redirect to the https://127.0.0.1:8099/authz_cb/django_oidc_op
    if req.status_code != 302:
        raise Exception(req.content)
    rp_final_url = req.headers['Location']

    fancy_print("The Authorization returns a "
                "HttpRedirect (302) to {}".format(rp_final_url), None)

    # what we found later in request_args ...
    #  code = urllib.parse.parse_qs( urllib.parse.urlparse(rp_final_url).query)
    #  fancy_print("That contains: ", code)

    ws, args = urllib.parse.splitquery(rp_final_url)
    request_args = urllib.parse.parse_qs(args)

    # from list to str
    request_args = {k:v[0] for k,v in request_args.items()}

    fancy_print("Going to finalize the session ...", request_args)

    # oidcrp.RPHandler.finalize() will parse the authorization response and depending on the configuration run the needed RP service
    result = rph.finalize(request_args['iss'], request_args)

    fancy_print("Got Access Token.", None)

    # Tha't the access token, the bearer used to access to userinfo endpoint
    #  result['token']
    fancy_print("Bearer Access Token", result['token'])

    # get the keyjar related to the issuer
    decoded_access_token = decode_token(result['token'],
                                        keyjar=issuer_keyjar.get_service_context().keyjar)
    fancy_print("Access Token", decoded_access_token)

    # id_token
    #  import pdb; pdb.set_trace()
    #  result['id_token'].to_dict()
    fancy_print("ID Token", result['id_token'].to_dict())

    # userinfo
    result['userinfo'].to_dict()
    fancy_print("Userinfo endpoint result:", result['userinfo'].to_dict())


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-conf', required=True,
                        help="settings file where RP configuration is")
    parser.add_argument('-u', required=True,
                        help="username")
    parser.add_argument('-p', required=True,
                        help="password")
    parser.add_argument('-iss', required=True,
                        help="The issuer Id you want to "
                             "requests authorization. Example: "
                             "django_oidc_op")
    args = parser.parse_args()

    # 'django-oidc-op/example/data/oidc_rp/conf.django.yaml'
    config_file = args.conf
    rph = get_rph(config_file)

    rph.verify_ssl = rph.httpc_params['verify']
    if not rph.verify_ssl:
        urllib3.disable_warnings()

    # select the OP you want to, example: "django_oidc_op"
    issuer_id = args.iss
    run_rp_session(rph, issuer_id, args.u, args.p)

# python3 snippets/rp_handler.py -conf example/data/oidc_rp/conf.django.yaml -u user -p pass -iss django_oidc_op
