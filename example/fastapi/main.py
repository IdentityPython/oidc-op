import json
import logging
import os
import uvicorn

from fastapi import Depends
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.logger import logger
from fastapi.openapi.models import Response
from utils import service_endpoint
from models import AuthorizationRequest
from models import WebFingerRequest
from utils import verify

from oidcop.exception import FailedAuthentication
from oidcop.server import Server
from oidcmsg.configure import create_from_config_file
from oidcmsg.configure import Configuration
from oidcop.configure import OPConfiguration

dir_path = os.path.dirname(os.path.realpath(__file__))
config_file = 'config.json'

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

app = FastAPI()
config = create_from_config_file(Configuration,
    entity_conf=[{
        "class": OPConfiguration, "attr": "op",
        "path": ["op", "server_info"]
    }],
    filename=config_file,
    base_path=dir_path)
app.server = Server(config.op, cwd="/oidc")

def get_app():
    return app

@app.get("/.well-known/webfinger")
async def well_known(model: WebFingerRequest = Depends()):
    endpoint = app.server.server_get("endpoint", "discovery")
    args = endpoint.process_request(model.dict())
    response = endpoint.do_response(**args)
    resp = json.loads(response["response"])
    return resp


@app.get("/.well-known/openid-configuration")
async def openid_config():
    endpoint = app.server.server_get("endpoint", "provider_config")
    args = endpoint.process_request()
    response = endpoint.do_response(**args)
    resp = json.loads(response["response"])
    return resp


@app.post('/verify/user', status_code=200)
def verify_user(kwargs: dict, response: Response):
    authn_method = app.server.server_get(
        "endpoint_context").authn_broker.get_method_by_id('user')
    try:
        return verify(app, authn_method, kwargs, response)
    except FailedAuthentication as exc:
        raise HTTPException(404, "Failed authentication")


@app.get('/authorization')
def authorization(model: AuthorizationRequest = Depends()):
    return service_endpoint(app.server.server_get("endpoint", 'authorization'))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)