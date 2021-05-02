import os

import pytest

from oidcop.configure import Configuration
from oidcop.configure import OPConfiguration
from oidcop.configure import create_from_config_file

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


def test_op_configure():
    configuration = create_from_config_file(OPConfiguration, full_path("op_config.json"),
                                            base_path=BASEDIR, domain="127.0.0.1", port=443)
    assert configuration
    assert 'add_on' in configuration
    authz_conf = configuration["authz"]
    assert set(authz_conf.keys()) == {"kwargs", "class"}
    id_token_conf = configuration.get("id_token")
    assert set(id_token_conf.keys()) == {"kwargs", "class"}

    with pytest.raises(KeyError):
        _ = configuration["foobar"]

    assert configuration.get("foobar", {}) == {}
    userinfo_conf = configuration.get("userinfo")
    assert userinfo_conf["kwargs"]["db_file"].startswith(BASEDIR)


def test_op_configure_default():
    configuration = create_from_config_file(OPConfiguration, full_path("op_config_defaults.py"),
                                            base_path=BASEDIR,domain="127.0.0.1", port=443)
    assert configuration
    assert 'add_on' in configuration
    authz = configuration["authz"]
    assert set(authz.keys()) == {"kwargs", "class"}
    id_token_conf = configuration.get("id_token", {})
    assert set(id_token_conf.keys()) == {'kwargs', 'class'}
    assert id_token_conf["kwargs"] == {}


def test_server_configure():
    configuration = create_from_config_file(Configuration, full_path("srv_config.yaml"),
                                            base_path=BASEDIR)
    assert configuration
    assert 'logger' in configuration
    assert 'op' in configuration
    op_conf = configuration["op"]
    assert 'add_on' in op_conf
    authz = op_conf["authz"]
    assert set(authz.keys()) == {"kwargs", "class"}
    id_token_conf = op_conf.get("id_token", {})
    assert set(id_token_conf.keys()) == {"kwargs", "class"}

    with pytest.raises(KeyError):
        _ = configuration["add_on"]

    assert configuration.get("add_on", {}) == {}

    userinfo_conf = op_conf.get("userinfo")
    assert userinfo_conf["kwargs"]["db_file"].startswith(BASEDIR)
