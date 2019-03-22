import json
import yaml


def load_json(file_name):
    with open(file_name) as fp:
        js = json.load(fp)
    return js


def load_yaml_config(file):
    with open(file) as fp:
        c = yaml.load(fp)
    return c
