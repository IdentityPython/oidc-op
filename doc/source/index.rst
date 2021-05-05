Welcome to Idpy OIDC-op Documentation
======================================

This project is a Python implementation of an **OIDC Provider** on top of `jwtconnect.io <https://jwtconnect.io/>`_
that shows you how to 'build' an OP using the classes and functions provided by oidc-op.

If you are just going to build a standard OP you only have to write the configuration file. If you want to add or replace functionality this documentation
should be able to tell you how.

Idpy OIDC-op implements the following standards:

* `OpenID Connect Core 1.0 incorporating errata set 1 <https://openid.net/specs/openid-connect-core-1_0.html>`_
* `Web Finger <https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery>`_
* `OpenID Connect Discovery 1.0 incorporating errata set 1 <https://openid.net/specs/openid-connect-discovery-1_0.html>`_
* `OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1 <https://openid.net/specs/openid-connect-registration-1_0.html>`_
* `OpenID Connect Session Management 1.0 <https://openid.net/specs/openid-connect-session-1_0.html>`_
* `OpenID Connect Back-Channel Logout 1.0 <https://openid.net/specs/openid-connect-backchannel-1_0.html>`_
* `OpenID Connect Front-Channel Logout 1.0 <https://openid.net/specs/openid-connect-frontchannel-1_0.html>`_
* `OAuth2 Token introspection <https://tools.ietf.org/html/rfc7662>`_

It also comes with the following `add_on` modules.

* Custom scopes, that extends `[OIDC standard ScopeClaims] <https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims>`_
* `Proof Key for Code Exchange by OAuth Public Clients (PKCE) <https://tools.ietf.org/html/rfc7636>`_

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

The entire project code is open sourced and therefore licensed
under the `Apache 2.0 <https://en.wikipedia.org/wiki/Apache_License>`_.


.. toctree::
   :maxdepth: 2
   :caption: Introduction

   contents/intro.rst

.. toctree::
   :maxdepth: 2
   :caption: Setup

   contents/setup.rst

.. toctree::
   :maxdepth: 2
   :caption: Configuration

   contents/conf.rst

.. toctree::
   :maxdepth: 2
   :caption: Usage

   contents/usage.md

.. toctree::
   :maxdepth: 2
   :caption: Session management

   contents/session_management.rst

.. toctree::
   :maxdepth: 2
   :caption: Developer's

   contents/developers.md

.. toctree::
   :maxdepth: 2
   :caption: FAQ

   contents/faq.md
