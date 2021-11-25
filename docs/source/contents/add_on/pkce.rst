.. _pkce:

***************************
Proof Key for Code Exchange
***************************

------------
Introduction
------------

OAuth 2.0 public clients utilizing the Authorization Code Grant are
susceptible to the authorization code interception attack.  `RFC7636`_
describes the attack as well as a technique to mitigate
against the threat through the use of Proof Key for Code Exchange
(PKCE, pronounced "pixy").

-------------
Configuration
-------------

You can set *code_challenge_methods* and *essential*.
Both has defaults:

- code_challenge_methods: ["plain","S256","S384","S512"]
- essential: False

*S256* is mandatory to implement.
*plain* should only be used when you can rely on the operating system and transport
security not to disclose the request to an attacker.

-------
Example
-------

.. code:: python

    "add_on": {
        "pkce": {
            "function": "oidcrp.oauth2.add_on.pkce.add_support",
            "kwargs": {
                "code_challenge_methods": ["S256"],
                "essential": True
            }
        }
    }

.. _RFC7636: https://datatracker.ietf.org/doc/html/rfc7636