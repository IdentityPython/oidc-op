# Provider discovery

````
endpoint
http_info
req_args.__dict__['_dict']
current_app.server.endpoint_context.cdb
current_app.server.endpoint_context.session_manager.dump()

<oidcop.oidc.provider_config.ProviderConfiguration object at 0x7f7aab78f6a0>
{'db': {}, 'salt': 'P3e1EPrBvoml1VDE8hBHXzALYI0AsMUP'}
````

# useful hints ...
- http_info
- req_args.to_json()
- req_args.__dict__['_dict']


# Registration

Dynamic client registration endpoint

````
endpoint
http_info
req_args.__dict__['_dict']
current_app.server.endpoint_context.cdb
current_app.server.endpoint_context.session_manager.dump()

<oidcop.oidc.registration.Registration object at 0x7f7aab78f7c0>


{'86M1io6O2Vdy':
    {'client_id': '86M1io6O2Vdy',
     'client_salt': 'ehXmVjYE',
     'registration_access_token': 'lRail9TKK3Cj4kZdSt3KDorKVxyQvVGL',
     'registration_client_uri': 'https://127.0.0.1:5000/registration_api?client_id=86M1io6O2Vdy',
     'client_id_issued_at': 1619384394,
     'client_secret': '9f9a5b6dc23daca606c3766a1c6a0de29a2009b007be3d1da7ff8ca5',
     'client_secret_expires_at': 1621976394,
     'application_type': 'web',
     'response_types': ['code'],
     'contacts': ['ops@example.com'],
     'token_endpoint_auth_method': 'client_secret_basic',
     'post_logout_redirect_uris': [('https://127.0.0.1:8090/session_logout/local', '')],
     'jwks_uri': 'https://127.0.0.1:8090/static/jwks.json',
     'frontchannel_logout_uri': 'https://127.0.0.1:8090/fc_logout/local',
     'frontchannel_logout_session_required': True,
     'backchannel_logout_uri': 'https://127.0.0.1:8090/bc_logout/local',
     'grant_types': ['authorization_code'],
     'redirect_uris': [('https://127.0.0.1:8090/authz_cb/local', {})]
    }
}



{'db': {}, 'salt': 'P3e1EPrBvoml1VDE8hBHXzALYI0AsMUP'}
````

# Authorization endpont

````
http_info

endpoint; current_app.server.endpoint_context.session_manager.dump()

<oidcop.oidc.authorization.Authorization object at 0x7f7aab79f520>

````


Session dump
````
{'eWM0Hi7tcdJ5': {'client_id': 'eWM0Hi7tcdJ5', 'client_salt': 'mb45L2cF', 'registration_access_token': 'Tob3Jw0hZ29yqd2HMJj7VhdF98G6jnqu', 'registration_client_uri': 'https://127.0.0.1:5000/registration_api?client_id=eWM0Hi7tcdJ5', 'client_id_issued_at': 1619260359, 'client_secret': 'a7439bd659c5058dbe667a1a5f6c837336f31102d35d435e9f090a2e', 'client_secret_expires_at': 1621852359, 'application_type': 'web', 'response_types': ['code'], 'contacts': ['ops@example.com'], 'token_endpoint_auth_method': 'client_secret_basic', 'post_logout_redirect_uris': [('https://127.0.0.1:8090/session_logout/local', '')], 'jwks_uri': 'https://127.0.0.1:8090/static/jwks.json', 'frontchannel_logout_uri': 'https://127.0.0.1:8090/fc_logout/local', 'frontchannel_logout_session_required': True, 'backchannel_logout_uri': 'https://127.0.0.1:8090/bc_logout/local', 'grant_types': ['authorization_code'], 'redirect_uris': [('https://127.0.0.1:8090/authz_cb/local', {})]}}

{'db': {}, 'salt': 'P3e1EPrBvoml1VDE8hBHXzALYI0AsMUP'}
````

# Token endpoint

````
http_info

endpoint; current_app.server.endpoint_context.session_manager.dump()
<oidcop.oidc.token.Token object at 0x7f7aab79f9a0>
# current_app.server.endpoint_context.cdb not changes from the previous ...

# session dump
{
  "db": {
    "diana": [
      "oidcop.session.info.UserSessionInfo",
      {
        "subordinate": [
          "86M1io6O2Vdy"
        ],
        "revoked": false,
        "type": "UserSessionInfo",
        "extra_args": {},
        "user_id": "diana"
      }
    ],
    "diana;;86M1io6O2Vdy": [
      "oidcop.session.info.ClientSessionInfo",
      {
        "subordinate": [
          "fcc1c962a60911eb9d4d57d896f78a5d"
        ],
        "revoked": false,
        "type": "ClientSessionInfo",
        "extra_args": {},
        "client_id": "86M1io6O2Vdy"
      }
    ],
    "diana;;86M1io6O2Vdy;;fcc1c962a60911eb9d4d57d896f78a5d": [
      "oidcop.session.grant.Grant",
      {
        "expires_at": 1619427939,
        "issued_at": 1619384739,
        "not_before": 0,
        "revoked": false,
        "usage_rules": {
          "authorization_code": {
            "supports_minting": [
              "access_token",
              "refresh_token",
              "id_token"
            ],
            "max_usage": 1
          },
          "access_token": {},
          "refresh_token": {
            "supports_minting": [
              "access_token",
              "refresh_token"
            ]
          }
        },
        "used": 2,
        "authentication_event": {
          "oidcop.authn_event.AuthnEvent": {
            "uid": "diana",
            "authn_info": "oidcop.user_authn.authn_context.INTERNETPROTOCOLPASSWORD",
            "authn_time": 1619384739,
            "valid_until": 1619388339
          }
        },
        "authorization_request": {
          "oidcmsg.oidc.AuthorizationRequest": {
            "redirect_uri": "https://127.0.0.1:8090/authz_cb/local",
            "scope": "openid profile email address phone",
            "response_type": "code",
            "nonce": "TXwiaGM9I8kEB4BbC4nqHNWc",
            "state": "uKZM2ciKxWbg4x4xtsltzoy4PvjoQf4T",
            "code_challenge": "WYVBXCNsPiDTe0lClNPG69qRB_yl6mJ2Lwop9XWjhYA",
            "code_challenge_method": "S256",
            "client_id": "86M1io6O2Vdy"
          }
        },
        "claims": {
          "userinfo": {
            "sub": null,
            "name": null,
            "given_name": null,
            "family_name": null,
            "middle_name": null,
            "nickname": null,
            "profile": null,
            "picture": null,
            "website": null,
            "gender": null,
            "birthdate": null,
            "zoneinfo": null,
            "locale": null,
            "updated_at": null,
            "preferred_username": null,
            "email": null,
            "email_verified": null,
            "address": null,
            "phone_number": null,
            "phone_number_verified": null
          },
          "introspection": {},
          "id_token": {},
          "access_token": {}
        },
        "issued_token": [
          {
            "expires_at": 0,
            "issued_at": 1619384739,
            "not_before": 0,
            "revoked": false,
            "usage_rules": {
              "supports_minting": [
                "access_token",
                "refresh_token",
                "id_token"
              ],
              "max_usage": 1
            },
            "used": 1,
            "claims": {},
            "id": "fcc1c963a60911eb9d4d57d896f78a5d",
            "name": "AuthorizationCode",
            "resources": [],
            "scope": [],
            "type": "authorization_code",
            "value": "Z0FBQUFBQmdoZG1qdTlNZ0hzNGZzcVhZNnRJTXE2bkZZNGlVeXZTaDYwWlV4Vm1yMnFQWUZSSVFmb25HQjluQy1ZVWNXTWJlZ082OE03dVB1NmdBVG8xbkwxV1BWRTBZVkIzYXctY0xhTDB6c2hXUzhmeTRBNE9Ua3RxVVlmU0dDSElPeUJRb1VHQndtT21PR25nRWx3QXdoSG1DdklFM0REdjhWa2I2bWNtQzhFazdrRzBybWd4VV9oX19hcEt4MDZ3Uk5lNGpvbXllMVVmNkt4VXNRaW1FVHRTdS13ajVxczVibmtaXzRhXzhMcW9DOEFXVGtZND0="
          },
          {
            "expires_at": 0,
            "issued_at": 1619384739,
            "not_before": 0,
            "revoked": false,
            "usage_rules": {},
            "used": 0,
            "based_on": "Z0FBQUFBQmdoZG1qdTlNZ0hzNGZzcVhZNnRJTXE2bkZZNGlVeXZTaDYwWlV4Vm1yMnFQWUZSSVFmb25HQjluQy1ZVWNXTWJlZ082OE03dVB1NmdBVG8xbkwxV1BWRTBZVkIzYXctY0xhTDB6c2hXUzhmeTRBNE9Ua3RxVVlmU0dDSElPeUJRb1VHQndtT21PR25nRWx3QXdoSG1DdklFM0REdjhWa2I2bWNtQzhFazdrRzBybWd4VV9oX19hcEt4MDZ3Uk5lNGpvbXllMVVmNkt4VXNRaW1FVHRTdS13ajVxczVibmtaXzRhXzhMcW9DOEFXVGtZND0=",
            "claims": {},
            "id": "fcc4fc72a60911eb9d4d57d896f78a5d",
            "name": "AccessToken",
            "resources": [],
            "scope": [],
            "type": "access_token",
            "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6IlNWUXpPV1ZVUm1oNWIxcHVVVmx1UlY4dGVVUlpVVlZTZFhkcFdVUTJTbTVMY1U0M01EWm1WV2REVlEifQ.eyJzY29wZSI6IFsib3BlbmlkIiwgInByb2ZpbGUiLCAiZW1haWwiLCAiYWRkcmVzcyIsICJwaG9uZSJdLCAiYXVkIjogWyI4Nk0xaW82TzJWZHkiXSwgInNpZCI6ICJkaWFuYTs7ODZNMWlvNk8yVmR5OztmY2MxYzk2MmE2MDkxMWViOWQ0ZDU3ZDg5NmY3OGE1ZCIsICJ0dHlwZSI6ICJUIiwgImlzcyI6ICJodHRwczovLzEyNy4wLjAuMTo1MDAwIiwgImlhdCI6IDE2MTkzODQ3MzksICJleHAiOiAxNjE5Mzg4MzM5fQ.Brva_I8bBM5z_1ZxFBWSRFN3U95y_YQxnLG5-51NrUmu862M-KSj4kd5v5vFGHiHF0iFvBuDLD6pSZL1RHXHCg"
          }
        ],
        "resources": [
          "86M1io6O2Vdy"
        ],
        "scope": [
          "openid",
          "profile",
          "email",
          "address",
          "phone"
        ],
        "sub": "93be77e1b212f1643e0ee9dd5e477e2a2a231dc6ca22dd3273345e63eb156a23"
      }
    ],
    "8ea62b28f57646fe8db31b4bdea0e262": [
      "oidcop.session.info.SessionInfo",
      {
        "subordinate": [],
        "revoked": false,
        "type": "",
        "extra_args": {}
      }
    ]
  },
  "salt": "1Kih63fBe5ympYSWi5z2aVXXCVKxqMvN"
}

````

# Userinfo endpoint

````
<oidcop.oidc.userinfo.UserInfo object at 0x7f7aab79fb80>
{'db': {'diana': ['oidcop.session.info.UserSessionInfo', {'subordinate': ['eWM0Hi7tcdJ5'], 'revoked': False, 'type': 'UserSessionInfo', 'extra_args': {}, 'user_id': 'diana'}], 'diana;;eWM0Hi7tcdJ5': ['oidcop.session.info.ClientSessionInfo', {'subordinate': ['c75b0e0ea4e811eba57a51f2252cef26'], 'revoked': False, 'type': 'ClientSessionInfo', 'extra_args': {}, 'client_id': 'eWM0Hi7tcdJ5'}], 'diana;;eWM0Hi7tcdJ5;;c75b0e0ea4e811eba57a51f2252cef26': ['oidcop.session.grant.Grant', {'expires_at': 0, 'issued_at': 1619260524, 'not_before': 0, 'revoked': False, 'usage_rules': {}, 'used': 2, 'authentication_event': {'oidcop.authn_event.AuthnEvent': {'uid': 'diana', 'authn_info': 'oidcop.user_authn.authn_context.INTERNETPROTOCOLPASSWORD', 'authn_time': 1619260524, 'valid_until': 1619264124}}, 'authorization_request': {'oidcmsg.oidc.AuthorizationRequest': {'redirect_uri': 'https://127.0.0.1:8090/authz_cb/local', 'scope': 'openid profile email address phone', 'response_type': 'code', 'nonce': 'xgR3dwSaW6s2q7sJ7Ar5KGEJ', 'state': 'AxNY1bnoRd5xCmTYDQIGRlq3XUCMEXoP', 'code_challenge': 'tfXn2btZVqbzkrSkyPUw1jAjtQXH2M2fUgLyqSMS0ak', 'code_challenge_method': 'S256', 'client_id': 'eWM0Hi7tcdJ5'}}, 'claims': {}, 'issued_token': [{'expires_at': 0, 'issued_at': 1619260524, 'not_before': 0, 'revoked': False, 'usage_rules': {'supports_minting': ['access_token', 'refresh_token'], 'max_usage': 1}, 'used': 1, 'claims': {}, 'id': 'c75b0e0fa4e811eba57a51f2252cef26', 'name': 'AuthorizationCode', 'resources': [], 'scope': [], 'type': 'authorization_code', 'value': 'Z0FBQUFBQmdnX1JzTEZ0ZDV0LWpic1RvYm95cEUtNG1BTV9XTzZyaFV1RW1rM2ppMnNCVThzb3RfemVMQ0hSd296Y1VyVF9OUXBXNGVRNjVjYkRqMl9leF9sQ2xnY3h3ZWh4X1FFeXFLMlhDZE9NTWtEcFZkU3RXNURTbTRrZ1Q5dEh5TWZrVlhmYnU2N0dwenBlM2J1WlNpYzY4cWRjTHUzYXZvWEc2TG0zSEtnY3ZKMGlvOFF4X19pWks0Zl9DUTRuU09ndnRNRTdJRmtNZ2NqU09aWDcxUlhjdl8tZmd6Z1NNcWViS1FjQjdnMGlZN21xcVJnRT0='}, {'expires_at': 0, 'issued_at': 1619260756, 'not_before': 0, 'revoked': False, 'usage_rules': {}, 'used': 0, 'based_on': 'Z0FBQUFBQmdnX1JzTEZ0ZDV0LWpic1RvYm95cEUtNG1BTV9XTzZyaFV1RW1rM2ppMnNCVThzb3RfemVMQ0hSd296Y1VyVF9OUXBXNGVRNjVjYkRqMl9leF9sQ2xnY3h3ZWh4X1FFeXFLMlhDZE9NTWtEcFZkU3RXNURTbTRrZ1Q5dEh5TWZrVlhmYnU2N0dwenBlM2J1WlNpYzY4cWRjTHUzYXZvWEc2TG0zSEtnY3ZKMGlvOFF4X19pWks0Zl9DUTRuU09ndnRNRTdJRmtNZ2NqU09aWDcxUlhjdl8tZmd6Z1NNcWViS1FjQjdnMGlZN21xcVJnRT0=', 'claims': {}, 'id': '519d54e6a4e911eba57a51f2252cef26', 'name': 'AccessToken', 'resources': [], 'scope': [], 'type': 'access_token', 'value': 'eyJhbGciOiJFUzI1NiIsImtpZCI6IlNWUXpPV1ZVUm1oNWIxcHVVVmx1UlY4dGVVUlpVVlZTZFhkcFdVUTJTbTVMY1U0M01EWm1WV2REVlEifQ.eyJzY29wZSI6IFtdLCAiYXVkIjogW10sICJzaWQiOiAiZGlhbmE7O2VXTTBIaTd0Y2RKNTs7Yzc1YjBlMGVhNGU4MTFlYmE1N2E1MWYyMjUyY2VmMjYiLCAidHR5cGUiOiAiVCIsICJpc3MiOiAiaHR0cHM6Ly8xMjcuMC4wLjE6NTAwMCIsICJpYXQiOiAxNjE5MjYwNzU2LCAiZXhwIjogMTYxOTI2NDM1Nn0.j-YSAF7M6naaq2w8ntPOi-55shCIpWWFKmluYS18wkPrp5L5NFViuhmhLRY1CHr_xtbWv944Ud06m0RKP7Gd0Q'}], 'resources': [], 'scope': [], 'sub': '8fb4f8ee2bad3d54e58fcc2bb4f56200391427fb587bbcb95ca535cd818fd914'}], 'c6171c52f7dd4dcfa51e28f9af5833fd': ['oidcop.session.info.SessionInfo', {'subordinate': [], 'revoked': False, 'type': '', 'extra_args': {}}]}, 'salt': 'P3e1EPrBvoml1VDE8hBHXzALYI0AsMUP'}
````
