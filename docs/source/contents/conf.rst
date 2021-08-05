========================
Configuration directives
========================

------
issuer
------

The issuer ID of the OP, a unique value in URI format.


--------------
session params
--------------

Configuration parameters used by session manager::

    "session_params": {
      "password": "__password_used_to_encrypt_access_token_sid_value",
      "salt": "salt involved in session sub hash ",
      "sub_func": {
        "public": {
          "class": "oidcop.session.manager.PublicID",
          "kwargs": {
            "salt": "sdfsdfdsf"
          }
        },
        "pairwise": {
          "class": "oidcop.session.manager.PairWiseID",
          "kwargs": {
            "salt": "sdfsdfsdf"
          }
        }
     }
    },


password
########

Optional. Encryption key used to encrypt the SessionID (sid) in access_token.
If unset it will be random.


salt
####

Optional. Salt, value or filename, used in sub_funcs (pairwise, public) for creating the opaque hash of *sub* claim.


sub_funcs
#########

Optional. Functions involved in *sub*ject value creation.

------
add_on
------

An example::

    "add_on": {
        "pkce": {
          "function": "oidcop.oidc.add_on.pkce.add_pkce_support",
          "kwargs": {
            "essential": false,
            "code_challenge_method": "S256 S384 S512"
          }
        },
        "claims": {
          "function": "oidcop.oidc.add_on.custom_scopes.add_custom_scopes",
          "kwargs": {
            "research_and_scholarship": [
              "name",
              "given_name",
              "family_name",
              "email",
              "email_verified",
              "sub",
              "iss",
              "eduperson_scoped_affiliation"
            ]
          }
        }
      }

The provided add-ons can be seen in the following sections.

pkce
####

The pkce add on is activated using the ``oidcop.oidc.add_on.pkce.add_pkce_support``
function. The possible configuration options can be found below.

essential
---------

Whether pkce is mandatory, authentication requests without a ``code_challenge``
will fail if this is True. This option can be overridden per client by defining
``pkce_essential`` in the client metadata.

code_challenge_method
---------------------

The allowed code_challenge methods. The supported code challenge methods are:
``plain, S256, S384, S512``

--------------
authentication
--------------

An example::

    "authentication": {
        "user": {
          "acr": "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword",
          "class": "oidcop.user_authn.user.UserPassJinja2",
          "kwargs": {
            "verify_endpoint": "verify/user",
            "template": "user_pass.jinja2",
            "db": {
              "class": "oidcop.util.JSONDictDB",
              "kwargs": {
                "filename": "passwd.json"
              }
            },
            "page_header": "Testing log in",
            "submit_btn": "Get me in!",
            "user_label": "Nickname",
            "passwd_label": "Secret sauce"
          }
        }
      },

------------
capabilities
------------

This covers most of the basic functionality of the OP. The key words are the
same as defined in `OIDC Discovery <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>`_.
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

---------
client_db
---------

If you're running an OP with static client registration you want to keep the
registered clients in a database separate from the session database since
it will change independent of the OP process. In this case you need this.
If you are on the other hand only allowing dynamic client registration then
keeping registered clients in the session database makes total sense.

The class you reference in the specification MUST be a subclass of
oidcmsg.storage.DictType and have some of the methods a dictionary has.

Note also that this class MUST support the dump and load methods as defined
in :py:class:`oidcmsg.impexp.ImpExp`.

An example::

    client_db: {
        "class": 'oidcmsg.abfile.AbstractFileSystem',
        "kwargs": {
            'fdir': full_path("afs"),
            'value_conv': 'oidcmsg.util.JSON'
        }
    }

--------------
cookie_handler
--------------

An example::

      "cookie_handler": {
        "class": "oidcop.cookie_handler.CookieHandler",
        "kwargs": {
          "keys": {
            "private_path": f"{OIDC_JWKS_PRIVATE_PATH}/cookie_jwks.json",
            "key_defs": [
              {"type": "OCT", "use": ["enc"], "kid": "enc"},
              {"type": "OCT", "use": ["sig"], "kid": "sig"}
            ],
            "read_only": False
          },
          "flags": {
              "samesite": "None",
              "httponly": True,
              "secure": True,
          },
          "name": {
            "session": "oidc_op",
            "register": "oidc_op_rp",
            "session_management": "sman"
          }
        }
    },

--------
endpoint
--------

An example::

      "endpoint": {
        "webfinger": {
          "path": ".well-known/webfinger",
          "class": "oidcop.oidc.discovery.Discovery",
          "kwargs": {
            "client_authn_method": null
          }
        },
        "provider_info": {
          "path": ".well-known/openid-configuration",
          "class": "oidcop.oidc.provider_config.ProviderConfiguration",
          "kwargs": {
            "client_authn_method": null
          }
        },
        "registration": {
          "path": "registration",
          "class": "oidcop.oidc.registration.Registration",
          "kwargs": {
            "client_authn_method": None,
            "client_secret_expiration_time": 432000,
            "client_id_generator": {
               "class": 'oidcop.oidc.registration.random_client_id',
               "kwargs": {
                    "seed": "that-optional-random-value"
               }
           }
          }
        },
        "registration_api": {
          "path": "registration_api",
          "class": "oidcop.oidc.read_registration.RegistrationRead",
          "kwargs": {
            "client_authn_method": [
              "bearer_header"
            ]
          }
        },
        "introspection": {
          "path": "introspection",
          "class": "oidcop.oauth2.introspection.Introspection",
          "kwargs": {
            "client_authn_method": [
              "client_secret_post",
              "client_secret_basic",
              "client_secret_jwt",
              "private_key_jwt"
            ]
            "release": [
              "username"
            ]
          }
        },
        "authorization": {
          "path": "authorization",
          "class": "oidcop.oidc.authorization.Authorization",
          "kwargs": {
            "client_authn_method": null,
            "claims_parameter_supported": true,
            "request_parameter_supported": true,
            "request_uri_parameter_supported": true,
            "response_types_supported": [
              "code",
              "token",
              "id_token",
              "code token",
              "code id_token",
              "id_token token",
              "code id_token token",
              "none"
            ],
            "response_modes_supported": [
              "query",
              "fragment",
              "form_post"
            ]
          }
        },
        "token": {
          "path": "token",
          "class": "oidcop.oidc.token.Token",
          "kwargs": {
            "client_authn_method": [
              "client_secret_post",
              "client_secret_basic",
              "client_secret_jwt",
              "private_key_jwt"
            ]
          }
        },
        "userinfo": {
          "path": "userinfo",
          "class": "oidcop.oidc.userinfo.UserInfo",
          "kwargs": {
            "claim_types_supported": [
              "normal",
              "aggregated",
              "distributed"
            ]
          }
        },
        "end_session": {
          "path": "session",
          "class": "oidcop.oidc.session.Session",
          "kwargs": {
            "logout_verify_url": "verify_logout",
            "post_logout_uri_path": "post_logout",
            "signing_alg": "ES256",
            "frontchannel_logout_supported": true,
            "frontchannel_logout_session_supported": true,
            "backchannel_logout_supported": true,
            "backchannel_logout_session_supported": true,
            "check_session_iframe": "check_session_iframe"
          }
        }
      }

You can specify which algoritms are supported, for example in userinfo_endpoint::

    "userinfo_signing_alg_values_supported": OIDC_SIGN_ALGS,
    "userinfo_encryption_alg_values_supported": OIDC_ENC_ALGS,

Or in authorization endpoint::

    "request_object_encryption_alg_values_supported": OIDC_ENC_ALGS,

------------
httpc_params
------------

Parameters submitted to the web client (python requests).
In this case the TLS certificate will not be verified, to be intended exclusively for development purposes

Example ::

    "httpc_params": {
        "verify": false
      },

----
keys
----

An example::

    "keys": {
        "private_path": "private/jwks.json",
        "key_defs": [
          {
            "type": "RSA",
            "use": [
              "sig"
            ]
          },
          {
            "type": "EC",
            "crv": "P-256",
            "use": [
              "sig"
            ]
          }
        ],
        "public_path": "static/jwks.json",
        "read_only": false,
        "uri_path": "static/jwks.json"
      },

*read_only* means that on each restart the keys will created and overwritten with new ones.
This can be useful during the first time the project have been executed, then to keep them as they are *read_only* would be configured to *True*.

---------------
login_hint2acrs
---------------

OIDC Login hint support, it's optional.
It matches the login_hint paramenter to one or more Authentication Contexts.

An example::

      "login_hint2acrs": {
        "class": "oidcop.login_hint.LoginHint2Acrs",
        "kwargs": {
          "scheme_map": {
            "email": [
              "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"
            ]
          }
        }
      },

oidc-op supports the following authn contexts:

- UNSPECIFIED, urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified
- INTERNETPROTOCOLPASSWORD, urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword
- MOBILETWOFACTORCONTRACT, urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract
- PASSWORDPROTECTEDTRANSPORT, urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
- PASSWORD, urn:oasis:names:tc:SAML:2.0:ac:classes:Password
- TLSCLIENT, urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient
- TIMESYNCTOKEN, urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken


-----
authz
-----

This configuration section refers to the authorization/authentication endpoint behaviour.
Scopes bound to an access token are strictly related to grant management, as part of what that endpoint does.
Regarding grant authorization we should have something like the following example.

If you omit this section from the configuration (thus using some sort of default profile)
you'll have an Implicit grant authorization that leads granting nothing.
Add the below to your configuration and you'll see things changing.


An example::

      "authz": {
        "class": "oidcop.authz.AuthzHandling",
        "kwargs": {
            "grant_config": {
                "usage_rules": {
                    "authorization_code": {
                        "supports_minting": ["access_token", "refresh_token", "id_token"],
                        "max_usage": 1
                    },
                    "access_token": {},
                    "refresh_token": {
                        "supports_minting": ["access_token", "refresh_token"]
                    }
                },
                "expires_in": 43200
            }
        }
      },

------------
template_dir
------------

The HTML Template directory used by Jinja2, used by endpoint context
 template loader, as::

    Environment(loader=FileSystemLoader(template_dir), autoescape=True)

An example::

      "template_dir": "templates"

For any further customization of template here an example of what used in django-oidc-op::

      "authentication": {
        "user": {
          "acr": "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword",
          "class": "oidc_provider.users.UserPassDjango",
          "kwargs": {
            "verify_endpoint": "verify/oidc_user_login/",
            "template": "oidc_login.html",

            "page_header": "Testing log in",
            "submit_btn": "Get me in!",
            "user_label": "Nickname",
            "passwd_label": "Secret sauce"
          }
        }
      },

------------------
token_handler_args
------------------

Token handler is an intermediate interface used by and endpoint to manage
 the tokens' default behaviour, like lifetime and minting policies.
 With it we can create a token that's linked to another, and keep relations between many tokens
 in session and grants management.

An example::

    "token_handler_args": {
        "jwks_def": {
          "private_path": "private/token_jwks.json",
          "read_only": false,
          "key_defs": [
            {
              "type": "oct",
              "bytes": 24,
              "use": [
                "enc"
              ],
              "kid": "code"
            },
            {
              "type": "oct",
              "bytes": 24,
              "use": [
                "enc"
              ],
              "kid": "refresh"
            }
          ]
        },
        "code": {
          "kwargs": {
            "lifetime": 600
          }
        },
        "token": {
          "class": "oidcop.token.jwt_token.JWTToken",
          "kwargs": {
              "lifetime": 3600,
              "add_claims": [
                "email",
                "email_verified",
                "phone_number",
                "phone_number_verified"
              ],
              "add_claim_by_scope": true,
              "aud": ["https://example.org/appl"]
           }
        },
        "refresh": {
            "kwargs": {
                "lifetime": 86400
            }
        }
        "id_token": {
            "class": "oidcop.token.id_token.IDToken",
            "kwargs": {
                "base_claims": {
                    "email": None,
                    "email_verified": None,
            },
        }
      }

jwks_defs can be replaced eventually by `jwks_file`::

    "jwks_file": f"{OIDC_JWKS_PRIVATE_PATH}/token_jwks.json",

You can even select wich algorithms to support in id_token, eg::

    "id_token": {
        "class": "oidcop.token.id_token.IDToken",
        "kwargs": {
            "id_token_signing_alg_values_supported": [
                    "RS256",
                    "RS512",
                    "ES256",
                    "ES512",
                    "PS256",
                    "PS512",
                ],
            "id_token_encryption_alg_values_supported": [
                    "RSA-OAEP",
                    "RSA-OAEP-256",
                    "A192KW",
                    "A256KW",
                    "ECDH-ES",
                    "ECDH-ES+A128KW",
                    "ECDH-ES+A192KW",
                    "ECDH-ES+A256KW",
                ],
            "id_token_encryption_enc_values_supported": [
                    'A128CBC-HS256',
                    'A192CBC-HS384',
                    'A256CBC-HS512',
                    'A128GCM',
                    'A192GCM',
                    'A256GCM'
                ],
        }
    }

--------
userinfo
--------

An example::

    "userinfo": {
        "class": "oidcop.user_info.UserInfo",
        "kwargs": {
          "db_file": "users.json"
        }
    }

This is somethig that can be customized.
For example in the django-oidc-op implementation is used something like
the following::

    "userinfo": {
        "class": "oidc_provider.users.UserInfo",
        "kwargs": {
            "claims_map": {
                "phone_number": "telephone",
                "family_name": "last_name",
                "given_name": "first_name",
                "email": "email",
                "verified_email": "email",
                "gender": "gender",
                "birthdate": "get_oidc_birthdate",
                "updated_at": "get_oidc_lastlogin"
            }
        }
    }
