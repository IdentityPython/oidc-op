import json
import os
import sys
import traceback
from urllib.parse import urlparse

from cryptojwt import as_unicode
from flask import Blueprint
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask.helpers import make_response
from flask.helpers import send_from_directory
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
import werkzeug

from oidcop.exception import FailedAuthentication
from oidcop.exception import InvalidClient
from oidcop.exception import UnknownClient
from oidcop.oidc.token import Token

# logger = logging.getLogger(__name__)

oidc_op_views = Blueprint('oidc_rp', __name__, url_prefix='')


def _add_cookie(resp, cookie_spec):
    kwargs = {'value': cookie_spec["value"]}
    for param in ['expires', 'max-age']:
        if param in cookie_spec:
            kwargs[param] = cookie_spec[param]
    kwargs["path"] = "/"
    resp.set_cookie(cookie_spec["name"], **kwargs)


def add_cookie(resp, cookie_spec):
    if isinstance(cookie_spec, list):
        for _spec in cookie_spec:
            _add_cookie(resp, _spec)
    elif isinstance(cookie_spec, dict):
        _add_cookie(resp, cookie_spec)

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


def add_headers_and_cookie(resp, info):
    return resp


def do_response(endpoint, req_args, error='', **args):
    info = endpoint.do_response(request=req_args, error=error, **args)
    _log = current_app.logger
    _log.debug('do_response: {}'.format(info))

    try:
        _response_placement = info['response_placement']
    except KeyError:
        _response_placement = endpoint.response_placement

    _log.debug('response_placement: {}'.format(_response_placement))

    if error:
        if _response_placement == 'body':
            _log.info('Error Response: {}'.format(info['response']))
            resp = make_response(info['response'], 400)
        else:  # _response_placement == 'url':
            _log.info('Redirect to: {}'.format(info['response']))
            resp = redirect(info['response'])
    else:
        if _response_placement == 'body':
            _log.info('Response: {}'.format(info['response']))
            resp = make_response(info['response'], 200)
        else:  # _response_placement == 'url':
            _log.info('Redirect to: {}'.format(info['response']))
            resp = redirect(info['response'])

    for key, value in info['http_headers']:
        resp.headers[key] = value

    if 'cookie' in info:
        add_cookie(resp, info['cookie'])

    return resp


def verify(authn_method):
    """
    Authentication verification

    :param url_endpoint: Which endpoint to use
    :param kwargs: response arguments
    :return: HTTP redirect
    """

    kwargs = dict([(k, v) for k, v in request.form.items()])
    username = authn_method.verify(**kwargs)
    if not username:
        return make_response('Authentication failed', 403)

    auth_args = authn_method.unpack_token(kwargs['token'])
    authz_request = AuthorizationRequest().from_urlencoded(auth_args['query'])

    endpoint = current_app.server.server_get("endpoint", 'authorization')
    _session_id = endpoint.create_session(authz_request, username, auth_args['authn_class_ref'],
                                          auth_args['iat'], authn_method)

    args = endpoint.authz_part2(request=authz_request, session_id=_session_id)

    if isinstance(args, ResponseMessage) and 'error' in args:
        return make_response(args.to_json(), 400)

    return do_response(endpoint, request, **args)


@oidc_op_views.route('/verify/user', methods=['GET', 'POST'])
def verify_user():
    authn_method = current_app.server.server_get(
        "endpoint_context").authn_broker.get_method_by_id('user')
    try:
        return verify(authn_method)
    except FailedAuthentication as exc:
        return render_template("error.html", title=str(exc))


@oidc_op_views.route('/verify/user_pass_jinja', methods=['GET', 'POST'])
def verify_user_pass_jinja():
    authn_method = current_app.server.server_get(
        "endpoint_context").authn_broker.get_method_by_id('user')
    try:
        return verify(authn_method)
    except FailedAuthentication as exc:
        return render_template("error.html", title=str(exc))


@oidc_op_views.route('/.well-known/<service>')
def well_known(service):
    if service == 'openid-configuration':
        _endpoint = current_app.server.server_get("endpoint", 'provider_config')
    elif service == 'webfinger':
        _endpoint = current_app.server.server_get("endpoint", 'discovery')
    else:
        return make_response('Not supported', 400)

    return service_endpoint(_endpoint)


@oidc_op_views.route('/registration', methods=['GET', 'POST'])
def registration():
    return service_endpoint(
        current_app.server.server_get("endpoint", 'registration'))


@oidc_op_views.route('/registration_api', methods=['GET'])
def registration_api():
    return service_endpoint(
        current_app.server.server_get("endpoint", 'registration_read'))


@oidc_op_views.route('/authorization')
def authorization():
    return service_endpoint(
        current_app.server.server_get("endpoint", 'authorization'))


@oidc_op_views.route('/token', methods=['GET', 'POST'])
def token():
    return service_endpoint(
        current_app.server.server_get("endpoint", 'token'))


@oidc_op_views.route('/userinfo', methods=['GET', 'POST'])
def userinfo():
    return service_endpoint(
        current_app.server.server_get("endpoint", 'userinfo'))


@oidc_op_views.route('/session', methods=['GET'])
def session_endpoint():
    return service_endpoint(
        current_app.server.server_get("endpoint", 'session'))


IGNORE = ["cookie", "user-agent"]


def service_endpoint(endpoint):
    _log = current_app.logger
    _log.info('At the "{}" endpoint'.format(endpoint.name))

    http_info = {
        "headers": {k: v for k, v in request.headers.items(lower=True) if k not in IGNORE},
        "method": request.method,
        "url": request.url,
        # name is not unique
        "cookie": [{"name": k, "value": v} for k, v in request.cookies.items()]
    }

    if request.method == 'GET':
        try:
            req_args = endpoint.parse_request(request.args.to_dict(), http_info=http_info)
        except (InvalidClient, UnknownClient) as err:
            _log.error(err)
            return make_response(json.dumps({
                'error': 'unauthorized_client',
                'error_description': str(err)
            }), 400)
        except Exception as err:
            _log.error(err)
            return make_response(json.dumps({
                'error': 'invalid_request',
                'error_description': str(err)
            }), 400)
    else:
        if request.data:
            if isinstance(request.data, str):
                req_args = request.data
            else:
                req_args = request.data.decode()
        else:
            req_args = dict([(k, v) for k, v in request.form.items()])
        try:
            req_args = endpoint.parse_request(req_args, http_info=http_info)
        except Exception as err:
            _log.error(err)
            err_msg = ResponseMessage(error='invalid_request', error_description=str(err))
            return make_response(err_msg.to_json(), 400)

    _log.info('request: {}'.format(req_args))
    if isinstance(req_args, ResponseMessage) and 'error' in req_args:
        return make_response(req_args.to_json(), 400)

    try:
        if isinstance(endpoint, Token):
            args = endpoint.process_request(AccessTokenRequest(**req_args), http_info=http_info)
        else:
            args = endpoint.process_request(req_args, http_info=http_info)
    except Exception as err:
        message = traceback.format_exception(*sys.exc_info())
        _log.error(message)
        err_msg = ResponseMessage(error='invalid_request', error_description=str(err))
        return make_response(err_msg.to_json(), 400)

    _log.info('Response args: {}'.format(args))

    if 'redirect_location' in args:
        return redirect(args['redirect_location'])
    if 'http_response' in args:
        return make_response(args['http_response'], 200)

    response = do_response(endpoint, req_args, **args)
    return response


@oidc_op_views.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return 'bad request!', 400


@oidc_op_views.route('/check_session_iframe', methods=['GET', 'POST'])
def check_session_iframe():
    if request.method == 'GET':
        req_args = request.args.to_dict()
    else:
        if request.data:
            req_args = json.loads(as_unicode(request.data))
        else:
            req_args = dict([(k, v) for k, v in request.form.items()])

    if req_args:
        _context = current_app.server.server_get("endpoint_context")
        # will contain client_id and origin
        if req_args['origin'] != _context.issuer:
            return 'error'
        if req_args['client_id'] != _context.cdb:
            return 'error'
        return 'OK'

    current_app.logger.debug(
        'check_session_iframe: {}'.format(req_args))
    doc = open('templates/check_session_iframe.html').read()
    return doc


@oidc_op_views.route('/verify_logout', methods=['GET', 'POST'])
def verify_logout():
    part = urlparse(current_app.server.server_get("endpoint_context").issuer)
    page = render_template('logout.html', op=part.hostname,
                           do_logout='rp_logout', sjwt=request.args['sjwt'])
    return page


@oidc_op_views.route('/rp_logout', methods=['GET', 'POST'])
def rp_logout():
    _endp = current_app.server.server_get("endpoint", 'session')
    _info = _endp.unpack_signed_jwt(request.form['sjwt'])
    try:
        request.form['logout']
    except KeyError:
        alla = False
    else:
        alla = True

    _iframes = _endp.do_verified_logout(alla=alla, **_info)

    if _iframes:
        res = render_template('frontchannel_logout.html',
                              frames=" ".join(_iframes), size=len(_iframes),
                              timeout=5000,
                              postLogoutRedirectUri=_info['redirect_uri'])
    else:
        res = redirect(_info['redirect_uri'])

        # rohe are you sure that _kakor is the right word? :)
        _kakor = _endp.kill_cookies()
        for cookie in _kakor:
            _add_cookie(res, cookie)

    return res


@oidc_op_views.route('/post_logout', methods=['GET'])
def post_logout():
    page = render_template('post_logout.html')
    return page
