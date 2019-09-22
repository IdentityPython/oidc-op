import base64
import logging
import json
import os

from django.conf import settings
from django.http import (HttpResponse,
                         HttpResponseBadRequest,
                         HttpResponseRedirect,
                         JsonResponse)
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, render_to_response
from django.urls import reverse
from django.utils.translation import gettext as _
from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.exception import FailedAuthentication
from oidcendpoint.oidc.token import AccessToken
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from urllib import parse as urlib_parse
from urllib.parse import urlparse

from oidc_op import oidcendpoint_app


logger = logging.getLogger(__name__)


def _add_cookie(resp, cookie_spec):
    for key, _morsel in cookie_spec.items():
        kwargs = {'value': _morsel.value}
        for param in ['expires', 'path', 'comment', 'domain', 'max-age',
                      'secure',
                      'version']:
            if _morsel[param]:
                kwargs[param] = _morsel[param]
        resp.set_cookie(key, **kwargs)


def add_cookie(resp, cookie_spec):
    if isinstance(cookie_spec, list):
        for _spec in cookie_spec:
            _add_cookie(resp, _spec)


def do_response(endpoint, req_args, error='', **args):
    info = endpoint.do_response(request=req_args, error=error, **args)

    logger = oidcendpoint_app.srv_config.logger
    logger.debug('do_response: {}'.format(info))

    try:
        _response_placement = info['response_placement']
    except KeyError:
        _response_placement = endpoint.response_placement

    logger.debug('response_placement: {}'.format(_response_placement))

    if error:
        if _response_placement == 'body':
            logger.info('Error Response: {}'.format(info['response']))
            resp = HttpResponse(info['response'], status=400)
        else:  # _response_placement == 'url':
            logger.info('Redirect to: {}'.format(info['response']))
            resp = HttpResponseRedirect(info['response'])
    else:
        if _response_placement == 'body':
            logger.info('Response: {}'.format(info['response']))
            resp = HttpResponse(info['response'], status=200)
        else:  # _response_placement == 'url':
            logger.info('Redirect to: {}'.format(info['response']))
            resp = HttpResponseRedirect(info['response'])

    for key, value in info['http_headers']:
        # set response headers
        resp[key] = value

    if 'cookie' in info:
        add_cookie(resp, info['cookie'])

    return resp


def service_endpoint(request, endpoint):
    """
    TODO: documentation here
    """
    logger = oidcendpoint_app.srv_config.logger
    logger.info('At the "{}" endpoint'.format(endpoint.endpoint_name))

    # if hasattr(request, 'debug') and request.debug:
        # import pdb; pdb.set_trace()

    authn = request.headers.get('Authorization', {})
    pr_args = {'auth': authn}
    if authn:
        logger.debug('request.headers["Authorization"] => {}'.format(pr_args))

    if request.method == 'GET':
        data = {k:v for k,v in request.GET.items()}
    elif request.body:
        data = request.body \
               if isinstance(request.body, str) else \
               request.body.decode()
        #<oidcendpoint.oidc.token.AccessToken object at 0x7fd626329d68>
        if authn:
            data = {k:v[0] for k,v in urlib_parse.parse_qs(data).items()}
    else:
        data = {k:v for k,v in request.POST.items()}

    # for .well-known resources like provider-config no data are submitted
    # if not data:
    #   ... not possible in this implementation

    logger.debug('Request arguments [{}]: {}'.format(request.method, data))
    try:
        req_args = endpoint.parse_request(data, **pr_args)
    except Exception as err:
        logger.error(err)
        return JsonResponse(json.dumps({
            'error': 'invalid_request',
            'error_description': str(err),
            'method': request.method
            }), status=400)

    logger.info('request: {}'.format(req_args))
    if isinstance(req_args, ResponseMessage) and 'error' in req_args:
        return JsonResponse(req_args.__dict__, status=400)

    if request.COOKIES:
        logger.debug(request.COOKIES)
        # TODO: cookie
        kwargs = {'cookie': request.COOKIES}
    else:
        kwargs = {}

    try:
        if isinstance(endpoint, AccessToken):
            args = endpoint.process_request(AccessTokenRequest(**req_args),
                                            **kwargs)
        else:
            args = endpoint.process_request(req_args, **kwargs)
    except Exception as err:
        message = '{}'.format(err)
        logger.error(message)
        return JsonResponse(json.dumps({
            'error': 'invalid_request',
            'error_description': str(err)
            }), status=400)

    logger.info('Response args: {}'.format(args))
    if 'redirect_location' in args:
        return HttpResponseRedirect(args['redirect_location'])
    if 'http_response' in args:
        return HttpResponse(args['http_response'], status=200)

    return do_response(endpoint, req_args, **args)


def well_known(request, service):
    """
    /.well-known/<service>
    """
    if service == 'openid-configuration':
        _endpoint = oidcendpoint_app.endpoint_context.endpoint['provider_info']
    # if service == 'openid-federation':
    #     _endpoint = oidcendpoint_app.endpoint_context.endpoint['provider_info']
    elif service == 'webfinger':
        _endpoint = oidcendpoint_app.endpoint_context.endpoint['webfinger']
    else:
        return HttpResponseBadRequest('Not supported', status=400)

    return service_endpoint(request, _endpoint)


@csrf_exempt
def registration(request):
    logger.info('registration request')
    _endpoint = oidcendpoint_app.endpoint_context.endpoint['registration']
    return service_endpoint(request, _endpoint)


def authorization(request):
    _endpoint = oidcendpoint_app.endpoint_context.endpoint['authorization']
    return service_endpoint(request, _endpoint)


@csrf_exempt
def verify_user(request):
    """csrf is not needed because it uses oidc token in the post
    """
    token = request.POST.get('token')
    if not token:
        return HttpResponse('Access forbidden: invalid token.', status=403)

    authn_method = oidcendpoint_app.endpoint_context.\
                   authn_broker.get_method_by_id('user')

    kwargs = dict([(k, v) for k, v in request.POST.items()])
    user = authn_method.verify(**kwargs)
    if not user:
        return HttpResponse('Authentication failed', status=403)

    auth_args = authn_method.unpack_token(kwargs['token'])
    authz_request = AuthorizationRequest().from_urlencoded(auth_args['query'])

    # salt size can be customized in settings.OIDC_OP_AUTHN_SALT_SIZE
    salt_size = getattr(settings, 'OIDC_OP_AUTHN_SALT_SIZE', 4)
    authn_event = create_authn_event(
        uid=user.username,
        salt=base64.b64encode(os.urandom(salt_size)).decode(),
        authn_info=auth_args['authn_class_ref'],
        authn_time=auth_args['iat'])

    endpoint = oidcendpoint_app.endpoint_context.endpoint['authorization']
    args = endpoint.authz_part2(user=user.username, request=authz_request,
                                authn_event=authn_event)

    if isinstance(args, ResponseMessage) and 'error' in args:
        return HttpResponse(args.to_json(), status=400)

    response = do_response(endpoint, request, **args)
    return response


@csrf_exempt
def token(request):
    logger.info('token request')
    _endpoint = oidcendpoint_app.endpoint_context.endpoint['token']
    return service_endpoint(request, _endpoint)


@csrf_exempt
def userinfo(request):
    logger.info('userinfo request')
    _endpoint = oidcendpoint_app.endpoint_context.endpoint['userinfo']
    # if not hasattr(request, 'debug'):
        # request.debug = 0
    # request.debug +=1
    return service_endpoint(request, _endpoint)


########
# LOGOUT
########
def session_endpoint(request):
    return service_endpoint(request,
        oidcendpoint_app.endpoint_context.endpoint['end_session'])

@csrf_exempt
def rp_logout(request):
    _endp = oidcendpoint_app.endpoint_context.endpoint['end_session']
    _info = _endp.unpack_signed_jwt(request.POST['sjwt'])
    alla = request.POST.get('logout')

    _iframes = _endp.do_verified_logout(alla=alla, **_info)
    if _iframes:
        d = dict(frames=" ".join(_iframes),
                 size=len(_iframes),
                 timeout=5000,
                 postLogoutRedirectUri=_info['redirect_uri'])
        res = render_to_response('frontchannel_logout.html', d)

    else:
        res = HttpResponseRedirect(_info['redirect_uri'])
        _kakor = _endp.kill_cookies()
        _add_cookie(res, _kakor)

    return res

def verify_logout(request):
    part = urlparse(oidcendpoint_app.endpoint_context.issuer)
    d = dict(op=part.hostname,
             do_logout='rp_logout',
             sjwt=request.GET['sjwt'] or request.POST['sjwt'])
    return render_to_response('logout.html', d)


def post_logout(request):
    return render_to_response('post_logout.html')
