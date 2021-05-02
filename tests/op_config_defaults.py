CONFIG = {
    "authentication": {
        "user": {
            "acr": "oidcop.user_authn.authn_context.INTERNETPROTOCOLPASSWORD",
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
        ]
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
    "token_handler_args": {
        "jwks_def": {
            "private_path": "private/token_jwks.json",
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
        "class": "oidcop.user_info.UserInfo",
        "kwargs": {
            "filename": "users.json"
        }
    }
}
