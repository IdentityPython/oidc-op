from oidcmsg import oidc
from oidcmsg.oidc import JRD
from oidcmsg.oidc import Link

from oidcop.endpoint import Endpoint

OIC_ISSUER = "http://openid.net/specs/connect/1.0/issuer"


class Discovery(Endpoint):
    request_cls = oidc.DiscoveryRequest
    response_cls = JRD
    request_format = "urlencoded"
    response_format = "json"
    name = "discovery"

    def do_response(self, response_args=None, request=None, **kwargs):
        """
        **Placeholder for the time being**

        :param response_args:
        :param request:
        :param kwargs: request arguments
        :return: Response information
        """

        links = [Link(href=h, rel=OIC_ISSUER) for h in kwargs["hrefs"]]

        _response = JRD(subject=kwargs["subject"], links=links)

        info = {
            "response": _response.to_json(),
            "http_headers": [("Content-type", "application/json")],
        }

        return info

    def process_request(self, request=None, **kwargs):
        return {
            "subject": request["resource"],
            "hrefs": [self.server_get("endpoint_context").issuer],
        }
