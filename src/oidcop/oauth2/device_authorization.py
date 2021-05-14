from oidcmsg.oauth2.device_authorization import (
    AuthorizationRequest,
    AuthorizationResponse,
)
from oidcmsg.time_util import utc_time_sans_frac

from oidcop import rndstr
from oidcop.endpoint import Endpoint


class AuthorizationEndpoint(Endpoint):
    request_cls = AuthorizationRequest
    response_cls = AuthorizationResponse
    request_format = "urlencoded"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "device_authorization_endpoint"
    name = "device_authorization"

    def __init__(self, server_get, **kwargs):
        Endpoint.__init__(self, server_get, **kwargs)
        self.verification_uri = kwargs.get("verification_uri")
        self.expires_in = kwargs.get("expires_in", 300)
        self.interval = kwargs.get("interval", 5)

    def process_request(self, request=None, **kwargs):
        """
        Produces a device code and an end-user
        code and provides the end-user verification URI.

        :param request:
        :param kwargs:
        :return:
        """
        _device_code = rndstr(32)
        _user_code = rndstr(8)

        _response = {
            "device_code": _device_code,
            "user_code": _user_code,
            "verification_uri": self.verification_uri,
            "expires_in": self.expires_in,
            "interval": self.interval,
        }
        _info = {
            "device_code": _device_code,
            "user_code": _user_code,
            "exp": utc_time_sans_frac() + self.expires_in,
            "interval": self.interval,
        }

        self.server_get("endpoint_context").dev_auth_db.set(_user_code, _info)
        return {"response_args": _response}

    def verification_endpoint(self, query):
        """
        Where the device's pull query is handled.

        :param query:
        :return:
        """
        _response = {}

        return _response
