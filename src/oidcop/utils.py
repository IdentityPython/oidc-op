import io
import json
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
