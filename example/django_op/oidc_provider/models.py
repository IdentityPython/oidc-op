import datetime
import json
import logging
import pytz

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone
from oidcop.utils import load_yaml_config


from . exceptions import InconsinstentSessionDump


logger = logging.getLogger(__name__)


OIDC_RESPONSE_TYPES = settings.OIDCOP_CONFIG['op']['server_info'][
    'endpoint']['authorization']['kwargs']['response_types_supported']

OIDC_TOKEN_AUTHN_METHODS = settings.OIDCOP_CONFIG['op']['server_info'][
    'endpoint']['token']['kwargs']['client_authn_method']

OIDC_GRANT_TYPES = settings.OIDCOP_CONFIG[
            'op']['server_info']['capabilities']['grant_types_supported']

TIMESTAMP_FIELDS = ['client_id_issued_at', 'client_secret_expires_at']


def get_client_by_id(client_id):
    client = OidcRelyingParty.objects.filter(
                            client_id = client_id,
                            is_active = True

    )
    if client:
        return client.last()


class TimeStampedModel(models.Model):
    """
    An abstract base class model that provides self-updating
    ``created`` and ``modified`` fields.
    """
    created = models.DateTimeField(auto_now_add=True, editable=False)
    modified = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        abstract = True


class OidcRelyingParty(TimeStampedModel):
    """
    See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata

    {
        'client_id': '86M1io6O2Vdy',
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


    """
    _TOKEN_AUTH_CHOICES = ((i, i) for i in OIDC_TOKEN_AUTHN_METHODS)

    client_id = models.CharField(
        max_length=255, blank=False, null=False, unique=True
    )
    client_salt = models.CharField(
        max_length=255, blank=True, null=True
    )
    registration_access_token = models.CharField(
        max_length=255, blank=True, null=True
    )
    registration_client_uri = models.URLField(
        max_length=255, blank=True, null=True
    )
    client_id_issued_at = models.DateTimeField(blank=True, null=True)
    client_secret = models.CharField(
        max_length=255,
        blank=True, null=True,
        help_text=('It is not needed for Clients '
                   'selecting a token_endpoint_auth_method '
                   'of private_key_jwt')
    )
    client_secret_expires_at = models.DateTimeField(
        blank=True, null=True,
        help_text=('REQUIRED if client_secret is issued')
    )
    application_type = models.CharField(
        max_length=255, blank=True,
        null=True, default='web'
    )
    token_endpoint_auth_method = models.CharField(
        choices=_TOKEN_AUTH_CHOICES,
        max_length=33,
        blank=True, null=True,
        default="client_secret_basic"
    )
    jwks_uri = models.URLField(max_length=255, blank=True, null=True)
    post_logout_redirect_uris = models.CharField(
        max_length=254, blank=True, null=True
    )
    redirect_uris = models.CharField(
        max_length=254, blank=True, null=True
    )
    is_active = models.BooleanField(('active'), default=True)
    last_seen = models.DateTimeField(blank=True, null=True)

    @property
    def allowed_scopes(self):
        scopes = self.oidcrpscope_set.filter(client=self)
        if scopes:
            return [i.scope for i in scopes]
        else:
            return None

    @allowed_scopes.setter
    def allowed_scopes(self, values):
        if not values:
            values = None
        for i in values:
            data = dict(client=self, scope=i)
            if not self.oidcrpscope_set.filter(**data):
                scope = self.oidcrpscope_set.create(**data)

    @property
    def contacts(self):
        return [
            elem.contact
            for elem in self.oidcrpcontact_set.filter(client=self)
        ]

    @contacts.setter
    def contacts(self, values):
        old = self.oidcrpcontact_set.filter(client=self)
        old.delete()
        if isinstance(values, str):
            value = [values]
        for value in values:
            data = dict(client=self, contact=value)
            if not self.oidcrpcontact_set.filter(**data):
                self.oidcrpcontact_set.create(**data)

    @property
    def grant_types(self):
        return [elem.grant_type
                for elem in
                self.oidcrpgranttype_set.filter(client=self)]

    @grant_types.setter
    def grant_types(self, values):
        old = self.oidcrpgranttype_set.filter(client=self)
        old.delete()
        if isinstance(values, str):
            value = [values]
        for value in values:
            data = dict(client=self, grant_type=value)
            if not self.oidcrpgranttype_set.filter(**data):
                self.oidcrpgranttype_set.create(**data)

    @property
    def response_types(self):
        return [
            elem.response_type
            for elem in
            self.oidcrpresponsetype_set.filter(client=self)
        ]

    @response_types.setter
    def response_types(self, values):
        old = self.oidcrpresponsetype_set.filter(client=self)
        old.delete()
        if isinstance(values, str):
            value = [values]
        for value in values:
            data = dict(client=self, response_type=value)
            if not self.oidcrpresponsetype_set.filter(**data):
                self.oidcrpresponsetype_set.create(**data)

    @property
    def post_logout_redirect_uris(self):
        l = []
        for elem in self.oidcrpredirecturi_set.\
                filter(client=self, type='post_logout_redirect_uris'):
            l.append((elem.uri, json.loads(elem.values)))
        return l

    @post_logout_redirect_uris.setter
    def post_logout_redirect_uris(self, values):
        old = self.oidcrpredirecturi_set.filter(client=self)
        old.delete()
        for value in values:
            args = json.dumps(value[1] if value[1] else [])
            data = dict(
                client=self,
                uri=value[0],
                values=args,
                type='post_logout_redirect_uris'
            )
            for i in self.oidcrpredirecturi_set.filter(**data):
                self.oidcrpredirecturi_set.create(**data)

    @property
    def redirect_uris(self):
        l = []
        for elem in self.oidcrpredirecturi_set.filter(
                client=self, type='redirect_uris'):
            l.append((elem.uri, json.loads(elem.values)))
        return l

    @redirect_uris.setter
    def redirect_uris(self, values):
        old = self.oidcrpredirecturi_set.filter(client=self)
        old.delete()
        for value in values:
            data = dict(client=self,
                        uri=value[0],
                        values=json.dumps(value[1]),
                        type='redirect_uris')
            if not self.oidcrpredirecturi_set.filter(**data):
                self.oidcrpredirecturi_set.create(**data)

    class Meta:
        verbose_name = ('Relying Party')
        verbose_name_plural = ('Relying Parties')

    @classmethod
    def import_from_cdb(cls, cdb):
        for client_id in cdb:
            if cls.objects.filter(client_id = client_id):
                continue
            client = cls.objects.create(client_id = client_id)
            for k,v in cdb[client_id].items():
                if k in ('client_secret_expires_at', 'client_id_issued_at'):
                    v = datetime.datetime.fromtimestamp(v)
                setattr(client, k, v)
            client.save()

    def serialize(self):
        """
            Compability with rohe approach based on dictionaries
        """
        data = {k: v for k, v in self.__dict__.items() if k[0] != '_'}
        disabled = ('created', 'modified', 'is_active', 'last_seen', 'id')
        for dis in disabled:
            data.pop(dis)
        for key in TIMESTAMP_FIELDS:
            if data.get(key):
                data[key] = int(datetime.datetime.timestamp(data[key]))

        data['contacts'] = self.contacts
        data['grant_types'] = self.grant_types
        data['response_types'] = self.response_types
        data['post_logout_redirect_uris'] = self.post_logout_redirect_uris
        data['redirect_uris'] = self.redirect_uris
        if self.allowed_scopes:
            # without allowed scopes set it will return all availables
            # configure allowed_scopes to filter only which one MUST allowed
            data['allowed_scopes'] = self.allowed_scopes

        return data

    def __str__(self):
        return '{}'.format(self.client_id)


class OidcRPResponseType(TimeStampedModel):
    client = models.ForeignKey(OidcRelyingParty, on_delete=models.CASCADE)
    response_type = models.CharField(choices=[(i, i) for i in OIDC_RESPONSE_TYPES],
                                     max_length=60)

    class Meta:
        verbose_name = ('Relying Party Response Type')
        verbose_name_plural = ('Relying Parties Response Types')
        unique_together = ('client', 'response_type')

    def __str__(self):
        return '{}, [{}]'.format(self.client, self.response_type)


class OidcRPGrantType(TimeStampedModel):
    client = models.ForeignKey(OidcRelyingParty,
                               on_delete=models.CASCADE)
    grant_type = models.CharField(choices=[(i, i)
                                           for i in OIDC_GRANT_TYPES],
                                  max_length=60)

    class Meta:
        verbose_name = ('Relying Party GrantType')
        verbose_name_plural = ('Relying Parties GrantTypes')
        unique_together = ('client', 'grant_type')

    def __str__(self):
        return '{}, [{}]'.format(self.client, self.grant_type)


class OidcRPContact(TimeStampedModel):
    client = models.ForeignKey(OidcRelyingParty,
                               on_delete=models.CASCADE)
    contact = models.CharField(max_length=254,
                               blank=True, null=True,)

    class Meta:
        verbose_name = ('Relying Party Contact')
        verbose_name_plural = ('Relying Parties Contacts')
        unique_together = ('client', 'contact')

    def __str__(self):
        return '{}, [{}]'.format(self.client, self.contact)


class OidcRPRedirectUri(TimeStampedModel):
    client = models.ForeignKey(OidcRelyingParty,
                               on_delete=models.CASCADE)
    uri = models.CharField(max_length=254,
                           blank=True, null=True)
    values = models.CharField(max_length=254,
                              blank=True, null=True)
    type = models.CharField(choices=(('redirect_uris', 'redirect_uris'),
                                     ('post_logout_redirect_uris',
                                      'post_logout_redirect_uris')),
                            max_length=33)

    class Meta:
        verbose_name = ('Relying Party URI')
        verbose_name_plural = ('Relying Parties URIs')

    def __str__(self):
        return '{} [{}] {}'.format(self.client, self.uri, self.type)


class OidcRPScope(TimeStampedModel):
    client = models.ForeignKey(OidcRelyingParty,
                               on_delete=models.CASCADE)
    scope = models.CharField(max_length=254,
                             blank=True, null=True,)

    class Meta:
        verbose_name = ('Relying Party Scope')
        verbose_name_plural = ('Relying Parties Scopes')
        unique_together = ('client', 'scope')

    def __str__(self):
        return '{}, [{}]'.format(self.client, self.scope)


def _aware_dt_from_timestamp(timestamp):
    dt = datetime.datetime.fromtimestamp(timestamp)
    return pytz.timezone("UTC").localize(dt, is_dst=None)


class OidcSession(TimeStampedModel):
    """
    Store UserSessionInfo, ClientSessionInfo and Grant

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
    """

    user_uid = models.CharField(max_length=120, blank=True, null=True)
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE,
                             blank=True, null=True)
    client = models.ForeignKey(OidcRelyingParty, on_delete=models.CASCADE,
                               blank=True, null=True)

    user_sessioninfo = models.TextField(default='{}')
    client_sessioninfo = models.TextField(default='{}')

    grant_sessioninfo = models.TextField()
    grant_uid = models.CharField(max_length=254, blank=True, null=True)
    expires_at = models.DateTimeField(blank=True, null=True)
    revoked = models.BooleanField(default=False)

    session_info = models.TextField(default='{}', blank=True, null=True)
    sub = models.CharField(max_length=254, blank=True, null=True)
    sid = models.CharField(max_length=254, unique=True, blank=True, null=True)
    sid_encrypted = models.CharField(max_length=254, blank=True, null=True)

    key = models.CharField(max_length=254, blank=True, null=True)
    salt = models.CharField(max_length=254, blank=True, null=True)

    class Meta:
        verbose_name = ('SSO Session')
        verbose_name_plural = ('SSO Sessions')

    @property
    def user_session_info(self):
        return json.loads(self.user_sessioninfo)

    @property
    def client_session_info(self):
        return json.loads(self.client_sessioninfo)

    @property
    def grant(self):
        return json.loads(self.grant_sessioninfo)

    @classmethod
    def load(cls, ses_man_dump:dict)->dict:
        if 'db' not in ses_man_dump:
            ses_man_dump

        attr_map = {
            'oidcop.session.info.UserSessionInfo': 'user_sessioninfo',
            'oidcop.session.info.ClientSessionInfo': 'client_sessioninfo',
            'oidcop.session.grant.Grant': 'grant_sessioninfo'
        }
        data = dict()
        for k,v in ses_man_dump['db'].items():

            # TODO: ask roland to have something more precise
            if len(k) > 128 and k not in attr_map.values():
                data['sid_encrypted'] = k
                continue

            classname = v[0]
            attr = getattr(cls, attr_map[classname])
            field_name = attr.field.name
            data[field_name] = json.dumps(v[1])
            if field_name == 'user_sessioninfo':
                user_id = v[1]['user_id']
                client_id = v[1]['subordinate'][0]
                data['user_uid'] = user_id
                data['user'] = get_user_model().objects.get(username=user_id)
                data['client'] = OidcRelyingParty.objects.get(client_id=client_id)
            elif field_name == 'client_sessioninfo':
                data['grant_uid'] = v[1]['subordinate'][0]
            elif field_name == 'grant_sessioninfo':
                data['expires_at'] = _aware_dt_from_timestamp(v[1]['expires_at'])
                data['revoked'] = v[1]['revoked']
                data['sub'] = v[1]['sub']
                data['sid'] = f"{user_id};;{client_id};;{data['grant_uid']}"

        data['key'] = ses_man_dump['key']
        data['salt'] = ses_man_dump['salt']

        session = cls.objects.filter(sid=data['sid'])
        if not session:
            session = cls.objects.create(**data)
        else:
            session.update(**data)
            session = session.first()
        OidcIssuedToken.load(session)

        if session.serialize() != ses_man_dump:
            logger.critical(ses_man_dump, session)
            raise InconsinstentSessionDump(
                'Serialized session differs from the dumped one'
            )
        return session

    def serialize(self):
        user_label = self.user_uid
        ses_label = f"{user_label};;{self.client.client_id}"
        grant_label = f"{ses_label};;{self.grant_uid}"

        return dict(
            db = {
                user_label : [
                    'oidcop.session.info.UserSessionInfo',
                    self.user_session_info
                ],
                ses_label: [
                    'oidcop.session.info.ClientSessionInfo',
                    self.client_session_info
                ],
                grant_label: [
                    'oidcop.session.grant.Grant',
                    self.grant
                ],
                self.sid_encrypted : [
                    'oidcop.session.grant.Grant', self.grant]
            },
            salt = self.salt,
            key = self.key
        )

    def __str__(self):
        return f'{self.user.username};;{self.client.client_id};;{self.grant_uid}'


class OidcIssuedToken(TimeStampedModel):
    """
    Stores issued token
    """
    TT_CHOICES = (
        ('authorization_code', 'authorization_code'),
        ('access_token','access_token'),
        ('id_token', 'id_token'),
    )

    uid = models.CharField(max_length=128, blank=True, null=True)
    type = models.CharField(choices = TT_CHOICES,
                            max_length=32,
                            blank=False, null=False)

    issued_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    not_before = models.DateTimeField(null=True, blank=True)

    revoked = models.BooleanField(default=False)
    value = models.TextField(unique=True)

    usage_rules = models.TextField()
    used = models.IntegerField(default=0)
    based_on = models.TextField(blank=True, null=True)

    session = models.ForeignKey(OidcSession, on_delete=models.CASCADE)

    class Meta:
        verbose_name = ('Issued Token')
        verbose_name_plural = ('Issued Tokens')
        indexes = [
           models.Index(fields=['value',]),
        ]

    def serialize(self):
        return {
            "type": self.type,
            "issued_at": self.issued_at.timestamp(),
            "expires_at": self.expires_at.timestamp(),
            "not_before": self.not_before.timestamp() if self.not_before else 0,
            "revoked": self.revoked,
            "value": self.value,
            "usage_rules": self.usage_rules,
            "used": self.used,
            "based_on": self.based_on,
            "id": self.uid
       }

    @classmethod
    def load(cls, session:OidcSession)->None:
        for token in session.grant['issued_token']:
            token = token[list(token.keys())[0]]
            # {'oidcop.session.token.AuthorizationCode': {'expires_at': 0, 'issued_at': 16209 ...

            if token.get('not_before'):
                nbt = datetime.datetime.fromtimestamp(token['not_before'])
            else:
                nbt = None
            data = dict(
                session = session,
                type = token['type'],
                issued_at = _aware_dt_from_timestamp(token['issued_at']),
                expires_at = _aware_dt_from_timestamp(token['expires_at']),
                not_before = nbt,
                revoked = token['revoked'],
                value = token['value'],
                usage_rules = json.dumps(token['usage_rules'],),
                used = token['used'],
                based_on = token.get('based_on'),
                uid = token['id'],
            )

            obj = cls.objects.filter(
                session=session, value=data['value']
            )
            if not obj:
                obj = cls.objects.create(**data)
            else:
                obj.update(**data)

    def __str__(self):
        return f'{self.type} {self.session}'
