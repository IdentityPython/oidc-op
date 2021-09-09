#! /usr/bin/env python3
import json
import sys

import yaml

"""Load a YAML configuration file."""
with open(sys.argv[1], "rt", encoding='utf-8') as file:
    config_dict = yaml.safe_load(file)

print(json.dumps(config_dict))
