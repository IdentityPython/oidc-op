"""
Implements JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)
as specified in
https://bitbucket.org/openid/fapi/src/master/Financial_API_JWT_Secured_Authorization_Response_Mode.md

"""
from typing import Optional
from typing import Union

from cryptojwt import JWT
from oidcmsg.message import Message

from oidcop.constant import DEFAULT_TOKEN_LIFETIME


def create_response(
        response_args: Union[Message, dict],
        request: Optional[Union[Message, dict]] = None,
        **kwargs
) -> dict:
    """
    Construct the response argument

    :param response_args:
    :param request:
    :param kwargs:
    :return:
    """
    _context = kwargs.get("endpoint_context")
    jarm_args = _context.add_on["jarm"]
    alg_dict = {}
    for key, attr in {"signed_response_alg": "sign_alg",
                      "encrypted_response_alg": "enc_alg",
                      "encrypted_response_enc": "enc_enc"}.items():
        _alg = jarm_args.get(key)
        if _alg:
            alg_dict[attr] = _alg

    lifetime = kwargs.get("lifetime", DEFAULT_TOKEN_LIFETIME)

    _jwt = JWT(_context.keyjar, iss=_context.issuer, lifetime=lifetime, **alg_dict)
    # return only one attribute in the response
    jarm_response = _jwt.pack(response_args, recv=request["client_id"])
    # _keys =
    for key in list(response_args.keys()):
        del response_args[key]
    response_args["response"] = jarm_response
    response_args.lax = True
    return response_args


def post_construct(
        response_args: Union[Message, dict],
        request: Optional[Union[Message, dict]] = None,
        **kwargs
) -> dict:
    """
    Construct the response argument

    :param response_args:
    :param request:
    :param kwargs:
    :return:
    """
    _response_mode = request.get("response_mode")
    if _response_mode and _response_mode in ['query.jwt', 'fragment.jwt', 'form_post.jwt', 'jwt']:
        return create_response(response_args, request, **kwargs)
    else:
        return response_args


def add_support(endpoint, **kwargs):
    """
    authorization_signed_response_alg,
    authorization_encrypted_response_alg and
    authorization_encrypted_response_enc
    are represented in kwargs as
    signed_response_alg, encrypted_response_alg and encrypted_response_enc.

    """

    _auth_endp = endpoint["authorization"]
    _auth_endp.post_construct.append(post_construct)
    _endpoint_context = _auth_endp.server_get("endpoint_context")
    _endpoint_context.add_on["jarm"] = kwargs

    for key, attr in {'signed_response_alg': 'authorization_signed_response_alg',
                     'encrypted_response_alg': 'authorization_encrypted_response_alg',
                     'encrypted_response_enc': 'authorization_encrypted_response_enc'}.items():
        _val = kwargs.get(key)
        if _val:
            _endpoint_context.provider_info[attr] = _val
