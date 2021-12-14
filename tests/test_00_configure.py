import json
import os

from oidcmsg.configure import Configuration
from oidcmsg.configure import create_from_config_file
import pytest

from oidcop.configure import OPConfiguration
from oidcop.logging import configure_logging

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


def test_op_configure():
    _str = open(full_path("op_config.json")).read()
    _conf = json.loads(_str)

    configuration = OPConfiguration(conf=_conf, base_path=BASEDIR, domain="127.0.0.1", port=443)
    assert configuration
    assert "add_on" in configuration
    authz_conf = configuration["authz"]
    assert set(authz_conf.keys()) == {"kwargs", "class"}
    id_token_conf = configuration.get("id_token")
    assert set(id_token_conf.keys()) == {"kwargs", "class"}

    with pytest.raises(KeyError):
        _ = configuration["foobar"]

    assert configuration.get("foobar", {}) == {}
    userinfo_conf = configuration.get("userinfo")
    assert userinfo_conf["kwargs"]["db_file"].startswith(BASEDIR)

    args = dict(configuration.items())
    assert "add_on" in args

    assert "session_params" in configuration


def test_op_configure_from_file():
    configuration = create_from_config_file(
        OPConfiguration,
        filename=full_path("op_config.json"),
        base_path=BASEDIR,
        domain="127.0.0.1",
        port=443,
    )

    assert configuration
    assert "add_on" in configuration
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
    _str = open(full_path("op_config.json")).read()
    _conf = json.loads(_str)

    configuration = OPConfiguration(conf=_conf, base_path=BASEDIR, domain="127.0.0.1", port=443)
    assert configuration
    assert "add_on" in configuration
    authz = configuration["authz"]
    assert set(authz.keys()) == {"kwargs", "class"}
    id_token_conf = configuration.get("id_token", {})
    assert set(id_token_conf.keys()) == {"kwargs", "class"}
    assert id_token_conf["kwargs"] == {
        "base_claims": {"email": {"essential": True}, "email_verified": {"essential": True}, }
    }


def test_op_configure_default_from_file():
    configuration = create_from_config_file(
        OPConfiguration,
        filename=full_path("op_config.json"),
        base_path=BASEDIR,
        domain="127.0.0.1",
        port=443,
    )
    assert configuration
    assert "add_on" in configuration
    authz = configuration["authz"]
    assert set(authz.keys()) == {"kwargs", "class"}
    id_token_conf = configuration.get("id_token", {})
    assert set(id_token_conf.keys()) == {"kwargs", "class"}
    assert id_token_conf["kwargs"] == {
        "base_claims": {"email": {"essential": True}, "email_verified": {"essential": True}, }
    }


def test_server_configure():
    configuration = create_from_config_file(
        Configuration,
        entity_conf=[{"class": OPConfiguration, "attr": "op", "path": ["op", "server_info"]}],
        filename=full_path("srv_config.yaml"),
        base_path=BASEDIR,
    )
    assert configuration
    assert "logger" in configuration
    assert "op" in configuration
    op_conf = configuration["op"]
    assert "add_on" in op_conf
    authz = op_conf["authz"]
    assert set(authz.keys()) == {"kwargs", "class"}
    id_token_conf = op_conf.get("id_token", {})
    assert set(id_token_conf.keys()) == {"kwargs", "class"}

    with pytest.raises(KeyError):
        _ = configuration["add_on"]

    assert configuration.get("add_on", {}) == {}

    userinfo_conf = op_conf.get("userinfo")
    assert userinfo_conf["kwargs"]["db_file"].startswith(BASEDIR)


def test_loggin_conf_file():
    logger = configure_logging(filename=full_path("logging.yaml"))
    assert logger


def test_loggin_conf_default():
    logger = configure_logging()
    assert logger


CONF = {
    "version": 1,
    "root": {"handlers": ["default"], "level": "DEBUG"},
    "loggers": {"bobcat": {"level": "DEBUG"}},
    "handlers": {
        "default": {
            "class": "logging.FileHandler",
            "filename": "debug.log",
            "formatter": "default",
        },
    },
    "formatters": {"default": {"format": "%(asctime)s %(name)s %(levelname)s %(message)s"}},
}


def test_loggin_conf_dict():
    logger = configure_logging(config=CONF)
    assert logger
