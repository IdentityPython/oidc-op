OIDCOP_CONF = {
  "port": 8000,
  "domain": "127.0.0.1",
  "server_name": "{domain}:{port}",
  "base_url": "https://{domain}:{port}",
  "key_def": [
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
  "OIDC_KEYS": {
    "private_path": "data/oidc_op/private/jwks.json",
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
    "public_path": "data/static/jwks.json",
    "read_only": False,
    "uri_path": "static/jwks.json"
  },
  "op": {
    # "seed": "CHANGE-THIS-RANDOMNESS!!!",
    "server_info": {
      "add_on": {
        "pkce": {
          "function": "oidcop.oidc.add_on.pkce.add_pkce_support",
          "kwargs": {
            "essential": False,
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
      },
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
      "authentication": {
        "user": {
          "acr": "oidcop.user_authn.authn_context.INTERNETPROTOCOLPASSWORD",
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
      "capabilities": {
        "subject_types_supported": [
          "public",
          "pairwise"
        ],
        "grant_types_supported": [
          "authorization_code",
          "implicit",
          "urn:ietf:params:oauth:grant-type:jwt-bearer",
          "refresh_token"
        ],
        # indicates that unknow/unavailable scopes requested by a RP
        # would get a 403 error message instead of be declined implicitly.
        # If False the op will only release the available scopes and ignoring the missings.
        # Default to False
        #deny_unknown_scopes: True
      },
      "cookie_handler": {
        "class": "oidcop.cookie_handler.CookieHandler",
        "kwargs": {
          "keys": {
            "private_path": "data/oidc_op/private/cookie_jwks.json",
            "key_defs": [
              {"type": "OCT", "use": ["enc"], "kid": "enc"},
              {"type": "OCT", "use": ["sig"], "kid": "sig"}
            ],
            "read_only": False
          },
          "name": {
            "session": "oidc_op",
            "register": "oidc_op_rp",
            "session_management": "sman"
          }
        }
      },
      "endpoint": {
        "webfinger": {
          "path": ".well-known/webfinger",
          "class": "oidcop.oidc.discovery.Discovery",
          "kwargs": {
            "client_authn_method": None
          }
        },
        "provider_info": {
          "path": ".well-known/openid-configuration",
          "class": "oidcop.oidc.provider_config.ProviderConfiguration",
          "kwargs": {
            "client_authn_method": None
          }
        },
        "registration": {
          "path": "registration",
          "class": "oidcop.oidc.registration.Registration",
          "kwargs": {
            "client_authn_method": None,
            "client_secret_expiration_time": 432000
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
              "client_secret_post"
            ],
            "release": [
              "username"
            ]
          }
        },
        "authorization": {
          "path": "authorization",
          "class": "oidcop.oidc.authorization.Authorization",
          "kwargs": {
            "client_authn_method": None,
            "claims_parameter_supported": True,
            "request_parameter_supported": True,
            "request_uri_parameter_supported": True,
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
            "frontchannel_logout_supported": True,
            "frontchannel_logout_session_supported": True,
            "backchannel_logout_supported": True,
            "backchannel_logout_session_supported": True,
            "check_session_iframe": "check_session_iframe"
          }
        }
      },
      "httpc_params": {
        "verify": False
      },
      "issuer": "https://{domain}:{port}",
      "keys": {
        "private_path": "data/oidc_op/private/jwks.json",
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
        "public_path": "data/static/jwks.json",
        "read_only": False,
        "uri_path": "static/jwks.json"
      },
      "login_hint2acrs": {
        "class": "oidcop.login_hint.LoginHint2Acrs",
        "kwargs": {
          "scheme_map": {
            "email": [
              "oidcop.user_authn.authn_context.INTERNETPROTOCOLPASSWORD"
            ]
          }
        }
      },
      "session_key": {
        "filename": "data/oidc_op/private/session_jwk.json",
        "type": "OCT",
        "use": "sig"
      },
      "template_dir": "templates",
      "token_handler_args": {
        "jwks_def": {
          "private_path": "data/oidc_op/private/token_jwks.json",
          "read_only": False,
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
            "add_claim_by_scope": True,
            "aud": [
              "https://example.org/appl"
            ]
          }
        },
        "refresh": {
          "kwargs": {
            "lifetime": 86400
          }
        }
      },
      "userinfo": {
        "class": "oidc_provider.users.UserInfo",
        "kwargs": {
            # map claims to django user attributes here:
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
    }
  }

}
