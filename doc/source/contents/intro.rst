***************************
The OpenID Connect Provider
***************************

============
Introduction
============

This documentation are here to show you how to 'build' an OP using the
classes and functions provided by oidcop.

OAuth2 and thereby OpenID Connect (OIDC) are built on a request-response paradigm.
The RP issues a request and the OP returns a response.

The OIDC core standard defines a set of such request-responses.
This is a basic list of request-responses and the normal sequence in which they
occur:

1. Provider discovery (WebFinger)
2. Provider Info Discovery
3. Client registration
4. Authorization/Authentication
5. Access token
6. User info

If you are just going to build a standard OP you only have to write the
configuration file and of course add authentication and user consent services.
If you want to add or replace functionality this document should be able to
tell you how.

Setting up an OP means making a number if decisions. Like, should the OP support
WebFinger_ , `dynamic discovery`_ and/or `dynamic client registration`_ .

All these are services you can access at endpoints. The total set of endpoints
that this package supports are

- webfinger
- provider_info
- registration
- authorization
- token
- refresh_token
- userinfo
- end_session

.. _WebFinger: https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
.. _dynamic discovery: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
.. _dynamic client registration: https://openid.net/specs/openid-connect-registration-1_0.html

===============
Endpoint layout
===============

When an endpoint receives a request it has to do a number of things:

- Verify that the client can issue the request (client authentication/authorization)
- Verify that the request is correct and that it contains the necessary information.
- Process the request, which includes applying server policies and gathering information.
- Construct the response

I should note at this point that this package is expected to work within the
confines of a web server framework such that the actual receiving and sending
of the HTTP messages are dealt with by the framework.

Based on the actions an endpoint has to perform a method call structure
has been constructed. It looks like this:

1. parse_request

    - client_authentication (*)
    - post_parse_request (*)

2. process_request

3. do_response

    - response_info
        - construct
            - pre_construct (*)
            - _parse_args
            - post_construct (*)
    - update_http_args

Steps marked with '*' are places where extensions can be applied.

*parse_request* expects as input the request itself in a number of formats and
also, if available, information about client authentication. The later is
normally the authorization element of the HTTP header.

*do_response* returns a dictionary that can look like this::

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

cookie
    MAY be present
http_headers
    MAY be present
http_response
    Already clear and formatted HTTP response
response
    MUST be present
response_placement
    If absent defaults to the endpoints response_placement parameter value or
    if that is also missing 'url'
redirect_location
    Where to send a redirect
