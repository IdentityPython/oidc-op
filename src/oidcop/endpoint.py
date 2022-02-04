import json
import logging
from typing import Callable
from typing import Optional
from typing import Union
from urllib.parse import urlparse

from oidcmsg.exception import MissingRequiredAttribute
from oidcmsg.exception import MissingRequiredValue
from oidcmsg.message import Message
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import RegistrationRequest

from oidcop import sanitize
from oidcop.client_authn import client_auth_setup
from oidcop.client_authn import verify_client
from oidcop.construct import construct_endpoint_info
from oidcop.endpoint_context import EndpointContext
from oidcop.exception import UnAuthorizedClient
from oidcop.util import OAUTH2_NOCACHE_HEADERS

__author__ = "Roland Hedberg"

LOGGER = logging.getLogger(__name__)

"""
method call structure for Endpoints:

parse_request
    - client_authentication (*)
    - post_parse_request (*)

process_request

do_response
    - response_info
        - construct
            - pre_construct (*)
            - _parse_args
            - post_construct (*)
    - update_http_args

do_response returns a dictionary that can look like this::

    {
      'response':
        _response as a string or as a Message instance_
      'http_headers': [
        ('Content-type', 'application/json'),
        ('Pragma', 'no-cache'),
        ('Cache-Control', 'no-store')
      ],
      'cookie': _list of cookies_,
      'response_placement': 'body'
    }

"response" MUST be present
"http_headers" MAY be present
"cookie": MAY be present
"response_placement": If absent defaults to the endpoints response_placement
parameter value or if that is also missing 'url'
"""


def set_content_type(headers, content_type):
    if ("Content-type", content_type) in headers:
        return headers

    _headers = [h for h in headers if h[0] != "Content-type"]
    _headers.append(("Content-type", content_type))
    return _headers


def fragment_encoding(return_type):
    if return_type == ["code"]:
        return False
    else:
        return True


class Endpoint(object):
    request_cls = Message
    response_cls = Message
    error_cls = ResponseMessage
    endpoint_name = ""
    endpoint_path = ""
    name = ""
    request_format = "urlencoded"
    request_placement = "query"
    response_format = "json"
    response_placement = "body"
    client_authn_method = ""
    default_capabilities = None

    def __init__(self, server_get: Callable, **kwargs):
        self.server_get = server_get
        self.pre_construct = []
        self.post_construct = []
        self.post_parse_request = []
        self.kwargs = kwargs
        self.full_path = ""

        for param in [
            "request_cls",
            "response_cls",
            "request_format",
            "request_placement",
            "response_format",
            "response_placement",
        ]:
            _val = kwargs.get(param)
            if _val:
                setattr(self, param, _val)

        _methods = kwargs.get("client_authn_method")
        self.client_authn_method = []
        if _methods:
            self.client_authn_method = client_auth_setup(_methods, server_get)
        elif _methods is not None:  # [] or '' or something not None but regarded as nothing.
            self.client_authn_method = [None]  # Ignore default value
        elif self.default_capabilities:
            _methods = self.default_capabilities.get("client_authn_method")
            if _methods:
                self.client_authn_method = client_auth_setup(_methods, server_get)
        self.endpoint_info = construct_endpoint_info(self.default_capabilities, **kwargs)

        # This is for matching against aud in JWTs
        # By default the endpoint's endpoint URL is an allowed target
        self.allowed_targets = [self.name]
        self.client_verification_method = []

    def process_verify_error(self, exception):
        _error = "invalid_request"
        return self.error_cls(error=_error, error_description="%s" % exception)

    def parse_request(
        self, request: Union[Message, dict, str], http_info: Optional[dict] = None, **kwargs
    ):
        """

        :param request: The request the server got
        :param http_info: HTTP information in connection with the request.
            This is a dictionary with keys: headers, url, cookies.
        :param kwargs: extra keyword arguments
        :return:
        """
        LOGGER.debug("- {} -".format(self.endpoint_name))
        LOGGER.info("Request: %s" % sanitize(request))

        _context = self.server_get("endpoint_context")

        if http_info is None:
            http_info = {}

        if request:
            if isinstance(request, (dict, Message)):
                req = self.request_cls(**request)
            else:
                _cls_inst = self.request_cls()
                if self.request_format == "jwt":
                    req = _cls_inst.deserialize(
                        request,
                        "jwt",
                        keyjar=_context.keyjar,
                        verify=_context.httpc_params["verify"],
                        **kwargs
                    )
                elif self.request_format == "url":
                    parts = urlparse(request)
                    scheme, netloc, path, params, query, fragment = parts[:6]
                    req = _cls_inst.deserialize(query, "urlencoded")
                else:
                    req = _cls_inst.deserialize(request, self.request_format)
        else:
            req = self.request_cls()

        # Verify that the client is allowed to do this
        auth_info = self.client_authentication(req, http_info, endpoint=self, **kwargs)

        if "client_id" in auth_info:
            req["client_id"] = auth_info["client_id"]
            _client_id = auth_info["client_id"]
        else:
            _client_id = req.get("client_id")

        keyjar = _context.keyjar

        # verify that the request message is correct
        try:
            req.verify(keyjar=keyjar, opponent_id=_client_id)
        except (MissingRequiredAttribute, ValueError, MissingRequiredValue) as err:
            return self.process_verify_error(err)
            _error = "invalid_request"
            if isinstance(err, ValueError) and self.request_cls == RegistrationRequest:
                if len(err.args) > 1:
                    if err.args[1] == "initiate_login_uri":
                        _error = "invalid_client_metadata"

            return self.error_cls(error=_error, error_description="%s" % err)

        LOGGER.info("Parsed and verified request: %s" % sanitize(req))

        # Do any endpoint specific parsing
        return self.do_post_parse_request(
            request=req, client_id=_client_id, http_info=http_info, **kwargs
        )

    def client_authentication(self, request: Message, http_info: Optional[dict] = None, **kwargs):
        """
        Do client authentication

        :param request: Parsed request, a self.request_cls class instance
        :param http_info: HTTP headers, URL used and cookies.
        :return: client_id or raise an exception
        """

        if "endpoint" not in kwargs:
            kwargs["endpoint"] = self

        authn_info = verify_client(
            endpoint_context=self.server_get("endpoint_context"),
            request=request,
            http_info=http_info,
            get_client_id_from_token=getattr(self, "get_client_id_from_token", None),
            **kwargs
        )

        LOGGER.debug("authn_info: %s", authn_info)
        if authn_info == {} and self.client_authn_method and len(self.client_authn_method):
            LOGGER.debug("client_authn_method: %s", self.client_authn_method)
            raise UnAuthorizedClient("Authorization failed")

        return authn_info

    def do_post_parse_request(
        self, request: Message, client_id: Optional[str] = "", **kwargs
    ) -> Message:
        _context = self.server_get("endpoint_context")
        for meth in self.post_parse_request:
            if isinstance(request, self.error_cls):
                break
            request = meth(request, client_id, endpoint_context=_context, **kwargs)
        return request

    def do_pre_construct(
        self, response_args: dict, request: Optional[Union[Message, dict]] = None, **kwargs
    ) -> dict:
        _context = self.server_get("endpoint_context")
        for meth in self.pre_construct:
            response_args = meth(response_args, request, endpoint_context=_context, **kwargs)

        return response_args

    def do_post_construct(
        self,
        response_args: Union[Message, dict],
        request: Optional[Union[Message, dict]] = None,
        **kwargs
    ) -> dict:
        _context = self.server_get("endpoint_context")
        for meth in self.post_construct:
            response_args = meth(response_args, request, endpoint_context=_context, **kwargs)

        return response_args

    def process_request(
        self,
        request: Optional[Union[Message, dict]] = None,
        http_info: Optional[dict] = None,
        **kwargs
    ):
        """

        :param http_info: Information on the HTTP request
        :param request: The request, can be in a number of formats
        :return: Arguments for the do_response method
        """
        return {}

    def construct(
        self,
        response_args: Optional[dict] = None,
        request: Optional[Union[Message, dict]] = None,
        **kwargs
    ):
        """
        Construct the response

        :param response_args: response arguments
        :param request: The parsed request, a self.request_cls class instance
        :param kwargs: Extra keyword arguments
        :return: An instance of the self.response_cls class
        """
        response_args = self.do_pre_construct(response_args, request, **kwargs)

        # LOGGER.debug("kwargs: %s" % sanitize(kwargs))
        response = self.response_cls(**response_args)

        return self.do_post_construct(response, request, **kwargs)

    def response_info(
        self,
        response_args: Optional[dict] = None,
        request: Optional[Union[Message, dict]] = None,
        **kwargs
    ) -> dict:
        return self.construct(response_args, request, **kwargs)

    def do_response(
        self,
        response_args: Optional[dict] = None,
        request: Optional[Union[Message, dict]] = None,
        error: Optional[str] = "",
        **kwargs
    ) -> dict:
        """
        :param response_args: Information to use when constructing the response
        :param request: The original request
        :param error: Possible error encountered while processing the request
        """
        do_placement = True
        content_type = "text/html"
        _resp = {}
        _response_placement = None
        if response_args is None:
            response_args = {}

        LOGGER.debug("do_response kwargs: %s", kwargs)

        resp = None
        if error:
            _response = ResponseMessage(error=error)
            for attr in ["error_description", "error_uri", "state"]:
                if attr in kwargs:
                    _response[attr] = kwargs[attr]
        elif "response_msg" in kwargs:
            resp = kwargs["response_msg"]
            _response_placement = kwargs.get("response_placement")
            do_placement = False
            _response = ""
            content_type = kwargs.get("content_type")
            if content_type is None:
                if self.response_format == "json":
                    content_type = "application/json"
                elif self.response_format in ["jws", "jwe", "jose"]:
                    content_type = "application/jose"
                else:
                    content_type = "application/x-www-form-urlencoded"
        else:
            _response = self.response_info(response_args, request, **kwargs)

        if do_placement:
            content_type = kwargs.get("content_type")
            if content_type is None:
                if self.response_placement == "body":
                    if self.response_format == "json":
                        content_type = "application/json; charset=utf-8"
                        if isinstance(_response, Message):
                            resp = _response.to_json()
                        else:
                            resp = json.dumps(_response)
                    elif self.response_format in ["jws", "jwe", "jose"]:
                        content_type = "application/jose; charset=utf-8"
                        resp = _response
                    else:
                        content_type = "application/x-www-form-urlencoded"
                        resp = _response.to_urlencoded()
                elif self.response_placement == "url":
                    content_type = "application/x-www-form-urlencoded"
                    fragment_enc = kwargs.get("fragment_enc")
                    if not fragment_enc:
                        _ret_type = kwargs.get("return_type")
                        if _ret_type:
                            fragment_enc = fragment_encoding(_ret_type)
                        else:
                            fragment_enc = False

                    if fragment_enc:
                        resp = _response.request(kwargs["return_uri"], True)
                    else:
                        resp = _response.request(kwargs["return_uri"])
                else:
                    raise ValueError(
                        "Don't know where that is: '{}".format(self.response_placement)
                    )

        if content_type:
            try:
                http_headers = set_content_type(kwargs["http_headers"], content_type)
            except KeyError:
                http_headers = [("Content-type", content_type)]
        else:
            try:
                http_headers = kwargs["http_headers"]
            except KeyError:
                http_headers = []

        if _response_placement:
            _resp["response_placement"] = _response_placement

        http_headers.extend(OAUTH2_NOCACHE_HEADERS)

        _resp.update({"response": resp, "http_headers": http_headers})

        try:
            _resp["cookie"] = kwargs["cookie"]
        except KeyError:
            pass

        try:
            _resp["response_code"] = kwargs["response_code"]
        except KeyError:
            pass

        return _resp

    def allowed_target_uris(self):
        res = []
        _context = self.server_get("endpoint_context")
        for t in self.allowed_targets:
            if t == "":
                res.append(_context.issuer)
            else:
                res.append(self.server_get("endpoint", t).full_path)
        return set(res)
