import logging

import cherrypy
from cryptojwt import as_bytes
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import ResponseMessage
from oidcendpoint.sdb import AuthnEvent

logger = logging.getLogger(__name__)


class OpenIDProvider(object):
    def __init__(self, config, endpoint_context):
        self.config = config
        self.endpoint_context = endpoint_context

    def do_response(self, endpoint, req_args, **args):
        info = endpoint.do_response(request=req_args, **args)

        for key, value in info['http_headers']:
            cherrypy.response.headers[key] = value

        try:
            _response_placement = info['response_placement']
        except KeyError:
            _response_placement = endpoint.response_placement

        if _response_placement == 'body':
            logger.info('Response: {}'.format(info['response']))
            return as_bytes(info['response'])
        elif _response_placement == 'url':
            logger.info('Redirect to: {}'.format(info['response']))
            raise cherrypy.HTTPRedirect(info['response'])

    @cherrypy.expose
    def service_endpoint(self, name, **kwargs):
        logger.info(kwargs)
        logger.info('At the {} endpoint'.format(name))

        endpoint = self.endpoint_context.endpoint[name]

        try:
            authn = cherrypy.request.headers['Authorization']
        except KeyError:
            pr_args = {}
        else:
            pr_args = {'auth': authn}

        if endpoint.request_placement == 'body':
            if cherrypy.request.process_request_body is True:
                _request = cherrypy.request.body.read()
            else:
                raise cherrypy.HTTPError(400, 'Missing HTTP body')
            if not _request:
                _request = kwargs

            req_args = endpoint.parse_request(_request, **pr_args)
        else:
            req_args = endpoint.parse_request(kwargs, **pr_args)
        logger.info('request: {}'.format(req_args))

        if isinstance(req_args, ResponseMessage) and 'error' in req_args:
            return as_bytes(req_args.to_json())

        args = endpoint.process_request(req_args)
        if 'http_response' in args:
            return as_bytes(args['http_response'])

        return self.do_response(endpoint, req_args, **args)

    @cherrypy.expose
    def authn_verify(self, url_endpoint, **kwargs):
        """
        Authentication verification

        :param url_endpoint: Which endpoint to use
        :param kwargs: response arguments
        :return: HTTP redirect
        """
        authn_method = self.endpoint_context.endpoint_to_authn_method[
            url_endpoint]

        username = authn_method.verify(**kwargs)
        if not username:
            cherrypy.HTTPError(403, message='Authentication failed')

        auth_args = authn_method.unpack_token(kwargs['token'])
        request = AuthorizationRequest().from_urlencoded(auth_args['query'])

        # uid, salt, valid=3600, authn_info=None, time_stamp=0, authn_time=None,
        # valid_until=None
        authn_event = AuthnEvent(username, 'salt',
                                 authn_info=auth_args['authn_class_ref'],
                                 authn_time=auth_args['iat'])

        endpoint = self.endpoint_context.endpoint['authorization']
        args = endpoint.authz_part2(user=username, request=request,
                                    authn_event=authn_event)

        return self.do_response(endpoint, request, **args)

    def _cp_dispatch(self, vpath):
        # Only get here if vpath != None
        ent = cherrypy.request.remote.ip
        logger.info('ent:{}, vpath: {}'.format(ent, vpath))

        if len(vpath) == 2 and vpath[0] == 'verify':
            a = vpath.pop(0)
            b = vpath.pop(0)
            cherrypy.request.params['url_endpoint'] = '/'.join(['', a, b])
            return self.authn_verify

        for name, instance in self.endpoint_context.endpoint.items():
            if vpath == instance.vpath:
                cherrypy.request.params['name'] = name
                for n in range(len(vpath)):
                    vpath.pop()
                return self.service_endpoint

        return self
