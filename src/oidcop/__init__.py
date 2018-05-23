__version__ = '0.1.2'


class OpenIDProvider():
    def __init__(self, issuer, srv_info, httplib):
        self.issuer = issuer
        self.srv_info = srv_info
        self.endpoint = self.srv_info.endpoint

    def provider_info_endpoint(self, request, auth, **kwargs):
        svc = self.endpoint['provider_info']
