.. _oidcop:

***************************
The OpenID Connect Provider
***************************

============
Introduction
============

This documentation are here to show you how to 'build' an OP using the
classes and functions provided by oidcendpoint.

If you are just going to build a standard OP you only have to write the
configuration file. If you want to add or replace functionality this document
should be able to tell you how.

Setting up an OP means making a number if decisions. Like, should the OP support
Web Finger (https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery),
dynamic discovery (https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig)
and dynamic client registration (https://openid.net/specs/openid-connect-registration-1_0.html).

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


========================
Configuration directives
========================

------
issuer
------

The issuer ID of the OP.

------------
capabilities
------------

This covers most of the basic functionality of the OP. The key words are the
same as defined in
https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata .
A couple of things are defined else where. Like the endpoints, issuer id,
jwks_uri and the authentication methods at the token endpoint.

An example::

    response_types_supported:
        - code
        - token
        - id_token
        - "code token"
        - "code id_token"
        - "id_token token"
        - "code id_token token"
        - none
      response_modes_supported:
        - query
        - fragment
        - form_post
      subject_types_supported:
        - public
        - pairwise
      grant_types_supported:
        - authorization_code
        - implicit
        - urn:ietf:params:oauth:grant-type:jwt-bearer
        - refresh_token
      claim_types_supported:
        - normal
        - aggregated
        - distributed
      claims_parameter_supported: True
      request_parameter_supported: True
      request_uri_parameter_supported: True
      frontchannel_logout_supported: True
      frontchannel_logout_session_supported: True
      backchannel_logout_supported: True
      backchannel_logout_session_supported: True
      check_session_iframe: https://127.0.0.1:5000/check_session_iframe


--------
id_token
--------

Defines which class that handles creating an ID Token and possibly also
arguments used when initiating that class.
An example::

    id_token:
      class: oidcendpoint.id_token.IDToken
      kwargs:
        default_claims:
          email:
            essential: True
          email_verified:
            essential: True


