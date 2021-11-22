********************
The clients database
********************

Information kept about clients in the client database are to begin with the
client metadata as defined in
https://openid.net/specs/openid-connect-registration-1_0.html .

To that we have the following additions specified in OIDC extensions.

* https://openid.net/specs/openid-connect-rpinitiated-1_0.html
    + post_logout_redirect_uri
* https://openid.net/specs/openid-connect-frontchannel-1_0.html
    + frontchannel_logout_uri
    + frontchannel_logout_session_required
* https://openid.net/specs/openid-connect-backchannel-1_0.html#Backchannel
    + backchannel_logout_uri
    + backchannel_logout_session_required
* https://openid.net/specs/openid-connect-federation-1_0.html#rfc.section.3.1
    + client_registration_types
    + organization_name
    + signed_jwks_uri

And finally we add a number of parameters that are OidcOP specific.
These are described in this document.

--------------
allowed_scopes
--------------

Which scopes that can be returned to a client. This is used to filter
the set of scopes a user can authorize release of.

-----------------
token_usage_rules
-----------------

There are usage rules for tokens. Rules are set per token type (the basic set is
authorization_code, refresh_token, access_token and id_token).
The possible rules are:

+ how many times they can be used
+ if other tokens can be minted based on this token
+ how fast they expire

A typical example (this is the default) would be::

    "token_usage_rules": {
        "authorization_code": {
            "max_usage": 1
            "supports_minting": ["access_token", "refresh_token"],
            "expires_in": 600,
        },
        "refresh_token": {
            "supports_minting": ["access_token"],
            "expires_in": -1
        },
    }

This then means that access_tokens can be used any number of times,
can not be used to mint other tokens and will expire after 300 seconds
which is the default for any token. An authorization_code can only used once
and it can be used to mint access_tokens and refresh_tokens. Note that normally
an authorization_code is used to mint an access_token and a refresh_token at
the same time. Such a dual minting is counted as one usage.
And lastly an refresh_token can be used to mint access_tokens any number of
times. An *expires_in* of -1 means that the token will never expire.

If token_usage_rules are defined in the client metadata then it will be used
whenever a token is minted unless circumstances makes the OP modify the rules.

Also this does not mean that what is valid for a token can not be changed
during run time.


