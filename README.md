# oidc-op

![CI build](https://github.com/IdentityPython/oidc-op/workflows/oidc-op/badge.svg)
![pypi](https://img.shields.io/pypi/v/oidcop.svg)
[![Downloads total](https://pepy.tech/badge/oidcop)](https://pepy.tech/project/oidcop)
[![Downloads week](https://pepy.tech/badge/oidcop/week)](https://pepy.tech/project/oidcop)
![License](https://img.shields.io/badge/license-Apache%202-blue.svg)
![Documentation Status](https://readthedocs.org/projects/oidcop/badge/?version=latest)
![Python version](https://img.shields.io/badge/python-3.7%20%7C%203.8%20%7C%203.9-blue.svg)

This project is a Python implementation of an **OIDC Provider** on top of [jwtconnect.io](https://jwtconnect.io/) that shows to you how to 'build' an OP using the classes and functions provided by oidc-op.

If you want to add or replace functionality the official documentation should be able to tell you how.
If you are just going to build a standard OP you only have to understand how to write your configuration file.
In `example/` folder you'll find some complete examples based on flask and django.

Idpy OIDC-op implements the following standards:

* [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)
* [Web Finger](https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery)
* [OpenID Connect Discovery 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-discovery-1_0.html)
* [OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-registration-1_0.html)
* [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html)
* [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
* [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)
* [OAuth2 Token introspection](https://tools.ietf.org/html/rfc7662)

It also comes with the following `add_on` modules.

* Custom scopes, that extends [OIDC standard ScopeClaims](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
* [Proof Key for Code Exchange by OAuth Public Clients (PKCE)](https://tools.ietf.org/html/rfc7636)
* [OAuth2 PAR](https://datatracker.ietf.org/doc/html/rfc9126)
* [OAuth2 RAR](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar)
* [OAuth2 DPoP](https://tools.ietf.org/id/draft-fett-oauth-dpop-04.html)
* [OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/draft-ietf-oauth-iss-auth-resp)

The entire project code is open sourced and therefore licensed under the [Apache 2.0](https://en.wikipedia.org/wiki/Apache_License)

For any futher information please read the [Official Documentation](https://oidcop.readthedocs.io/en/latest/).

# Certifications
[![OIDC Certification](https://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm-300x157.png)](https://www.certification.openid.net/plan-detail.html?public=true&plan=7p3iPQmff6Ohv)


# Contribute

[Join in](https://idpy.org/contribute/).


# Authors

- Roland Hedberg
