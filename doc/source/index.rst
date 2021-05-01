Welcome to Idpy OIDC-op Documentation
======================================

A Python implementation of an **OIDC Provider** on top of `jwtconnect.io <https://jwtconnect.io/>`_ with the following features:

* `OpenID Connect Core 1.0 incorporating errata set 1 <https://openid.net/specs/openid-connect-core-1_0.html>`_
* `OpenID Connect Discovery 1.0 incorporating errata set 1 <https://openid.net/specs/openid-connect-discovery-1_0.html>`_
* `OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1 <https://openid.net/specs/openid-connect-registration-1_0.html>`_
* `OpenID Connect Session Management 1.0 <https://openid.net/specs/openid-connect-session-1_0.html>`_
* `OpenID Connect Back-Channel Logout 1.0 <https://openid.net/specs/openid-connect-backchannel-1_0.html>`_
* `OpenID Connect Front-Channel Logout 1.0 <https://openid.net/specs/openid-connect-frontchannel-1_0.html>`_
* `OAuth2 Token introspection <https://tools.ietf.org/html/rfc7662>`_


It also supports the followings `add_ons` modules.

* Custom scopes, that extends `[OIDC standard ScopeClaims] <https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims>`_
* `Proof Key for Code Exchange by OAuth Public Clients (PKCE) <https://tools.ietf.org/html/rfc7636>`_


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
