import json

from fastapi import HTTPException
from fastapi import status
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import ResponseMessage


def do_response(endpoint, req_args, response, error='', **args):
    info = endpoint.do_response(request=req_args, error=error, **args)

    try:
        _response_placement = info['response_placement']
    except KeyError:
        _response_placement = endpoint.response_placement

    if error:
        if _response_placement == 'body':
            raise HTTPException(400, info['response'])
        else:  # _response_placement == 'url':
            response.status_code = status.HTTP_307_TEMPORARY_REDIRECT
            resp = json.loads(info['response'])
    else:
        if _response_placement == 'body':
            resp = json.loads(info['response'])
        else:  # _response_placement == 'url':
            response.status_code = status.HTTP_307_TEMPORARY_REDIRECT
            resp = json.loads(info['response'])

    for key, value in info['http_headers']:
        response.headers[key] = value

    if 'cookie' in info:
        for d in info["cookie"]:
            response.set_cookie(key=d["name"], value=d["value"])

    return resp


def verify(app, authn_method, kwargs, response):
    """
    Authentication verification

    :param kwargs: response arguments
    :return: HTTP redirect
    """

    #kwargs = dict([(k, v) for k, v in request.form.items()])
    username = authn_method.verify(**kwargs)
    if not username:
        raise HTTPException(403, "Authentication failed")

    auth_args = authn_method.unpack_token(kwargs['token'])
    authz_request = AuthorizationRequest().from_urlencoded(auth_args['query'])

    endpoint = app.server.server_get("endpoint", 'authorization')
    _session_id = endpoint.create_session(authz_request, username, auth_args['authn_class_ref'],
                                          auth_args['iat'], authn_method)

    args = endpoint.authz_part2(request=authz_request, session_id=_session_id)

    if isinstance(args, ResponseMessage) and 'error' in args:
        raise HTTPException(400, args.to_json())

    return do_response(endpoint, kwargs, response, **args)


IGNORE = ["cookie", "user-agent"]


def service_endpoint(app, endpoint):
    _log = app.srv_config.logger
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
