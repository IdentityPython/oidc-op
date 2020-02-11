import io
import json
import ssl
import sys

import yaml


def load_json(file_name):
    with open(file_name) as fp:
        js = json.load(fp)
    return js


def load_yaml_config(file_name):
    with open(file_name) as fp:
        c = yaml.safe_load(fp)
    return c

def yaml_to_py_stream(file_name):
    d = load_yaml_config(file_name)
    fstream = io.StringIO()
    for i in d:
        section = '{} = {}\n\n'.format(i, json.dumps(d[i], indent=2))
        fstream.write(section)
    fstream.seek(0)
    return fstream


def lower_or_upper(config, param, default=None):
    res = config.get(param.lower(), default)
    if not res:
        res = config.get(param.upper(), default)
    return res


def create_context(dir_path, config, **kwargs):
    _fname = lower_or_upper(config, "server_cert")
    if _fname:
        _cert_file = "{}/{}".format(dir_path, _fname)
    else:
        return None
    _fname = lower_or_upper(config, "server_key")
    if _fname:
        _key_file = "{}/{}".format(dir_path, _fname)
    else:
        return None

    context = ssl.SSLContext(**kwargs)  # PROTOCOL_TLS by default

    _verify_user = lower_or_upper(config, "verify_user")
    if _verify_user:
        if _verify_user == "optional":
            context.verify_mode = ssl.CERT_OPTIONAL
        elif _verify_user == "required":
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            sys.exit("Unknown verify_user specification: '{}'".format(_verify_user))
        _ca_bundle = lower_or_upper(config, "ca_bundle")
        if _ca_bundle:
            context.load_verify_locations(_ca_bundle)
    else:
        context.verify_mode = ssl.CERT_NONE

    try:
        context.load_cert_chain(_cert_file, _key_file)
    except Exception as e:
        sys.exit("Error starting server. Missing cert or key. Details: {}".format(e))

    return context
