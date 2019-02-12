import json
import logging
import os
import sys
import traceback

import werkzeug
from flask import Blueprint
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask.helpers import make_response
from flask.helpers import send_from_directory
from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.oidc.token import AccessToken
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest

logger = logging.getLogger(__name__)

oidc_op_views = Blueprint('oidc_rp', __name__, url_prefix='')


def add_cookie(resp, cookie_spec):
    for key, _morsel in cookie_spec.items():
        kwargs = {'value': _morsel.value}
        for param in ['expires', 'path', 'comment', 'domain', 'max-age',
                      'secure',
                      'version']:
            if _morsel[param]:
                kwargs[param] = _morsel[param]
        resp.set_cookie(key, **kwargs)


@oidc_op_views.route('/static/<path:path>')
def send_js(path):
    return send_from_directory('static', path)


@oidc_op_views.route('/keys/<jwks>')
def keys(jwks):
    fname = os.path.join('static', jwks)
    return open(fname).read()


@oidc_op_views.route('/')
def index():
    return render_template('index.html')


def do_response(endpoint, req_args, error='', **args):
    info = endpoint.do_response(request=req_args, error=error, **args)

    logger.debug('do_response: {}'.format(info))

    try:
        _response_placement = info['response_placement']
    except KeyError:
        _response_placement = endpoint.response_placement

    logger.debug('response_placement: {}'.format(_response_placement))

    if error:
        if _response_placement == 'body':
            logger.info('Error Response: {}'.format(info['response']))
            resp = make_response(info['response'], 400)
        else:  # _response_placement == 'url':
            logger.info('Redirect to: {}'.format(info['response']))
            return redirect(info['response'])
    else:
        if _response_placement == 'body':
            logger.info('Response: {}'.format(info['response']))
            resp = make_response(info['response'], 200)
        else:  # _response_placement == 'url':
            logger.info('Redirect to: {}'.format(info['response']))
            return redirect(info['response'])

    for key, value in info['http_headers']:
        resp.headers[key] = value

    if 'cookie' in info:
        add_cookie(resp, info['cookie'])

    return resp


@oidc_op_views.route('/verify/<method>', methods=['POST'])
def authn_verify(method):
    """
    Authentication verification

    :param url_endpoint: Which endpoint to use
    :param kwargs: response arguments
    :return: HTTP redirect
    """
    url_endpoint = '/verify/{}'.format(method)
    authn_method = current_app.endpoint_context.endpoint_to_authn_method[
        url_endpoint]

    kwargs = dict([(k, v) for k, v in request.form.items()])
    username = authn_method.verify(**kwargs)
    if not username:
        return make_response('Authentication failed', 403)

    auth_args = authn_method.unpack_token(kwargs['token'])
    authz_request = AuthorizationRequest().from_urlencoded(auth_args['query'])

    authn_event = create_authn_event(
        uid=username, salt='salt',
        authn_info=auth_args['authn_class_ref'],
        authn_time=auth_args['iat'])

    endpoint = current_app.endpoint_context.endpoint['authorization']
    args = endpoint.authz_part2(user=username, request=authz_request,
                                authn_event=authn_event)

    if isinstance(args, ResponseMessage) and 'error' in args:
        return make_response(args.to_json(), 400)

    return do_response(endpoint, request, **args)


@oidc_op_views.route('/.well-known/<service>')
def well_known(service):
    # if service == 'openid-configuration':
    #     _endpoint = current_app.endpoint_context.endpoint['provider_info']
    if service == 'openid-federation':
        _endpoint = current_app.endpoint_context.endpoint['provider_info']
    elif service == 'webfinger':
        _endpoint = current_app.endpoint_context.endpoint['webfinger']
    else:
        return make_response('Not supported', 400)

    return service_endpoint(_endpoint)


@oidc_op_views.route('/provider_info', methods=['GET'])
def registration():
    return service_endpoint(
        current_app.endpoint_context.endpoint['provider_info'])


@oidc_op_views.route('/authorization')
def authorization():
    return service_endpoint(
        current_app.endpoint_context.endpoint['authorization'])


@oidc_op_views.route('/token', methods=['GET', 'POST'])
def token():
    return service_endpoint(
        current_app.endpoint_context.endpoint['token'])


@oidc_op_views.route('/userinfo', methods=['GET', 'POST'])
def userinfo():
    return service_endpoint(
        current_app.endpoint_context.endpoint['userinfo'])


def service_endpoint(endpoint):
    logger.info('At the "{}" endpoint'.format(endpoint.endpoint_name))

    try:
        authn = request.headers['Authorization']
    except KeyError:
        pr_args = {}
    else:
        pr_args = {'auth': authn}

    if request.method == 'GET':
        req_args = endpoint.parse_request(request.args.to_dict(), **pr_args)
    else:
        if request.data:
            req_args = request.data
        else:
            req_args = dict([(k, v) for k, v in request.form.items()])
        req_args = endpoint.parse_request(req_args, **pr_args)

    logger.info('request: {}'.format(req_args))
    if isinstance(req_args, ResponseMessage) and 'error' in req_args:
        return make_response(req_args.to_json(), 400)

    try:
        if request.cookies:
            kwargs = {'cookie': request.cookies}
        else:
            kwargs = {}

        if isinstance(endpoint, AccessToken):
            args = endpoint.process_request(AccessTokenRequest(**req_args),
                                            **kwargs)
        else:
            args = endpoint.process_request(req_args, **kwargs)
    except Exception:
        message = traceback.format_exception(*sys.exc_info())
        # cherrypy.response.headers['Content-Type'] = 'text/html'
        return make_response(json.dumps({
            'error': 'server_error',
            'error_description': message
        }, sort_keys=True, indent=4), 400)

    logger.info('Response args: {}'.format(args))

    if 'http_response' in args:
        return make_response(args['http_response'], 200)

    return do_response(endpoint, req_args, **args)


@oidc_op_views.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return 'bad request!', 400
