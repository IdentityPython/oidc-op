import datetime
import logging
import json
import random
import string
import pytz

from django.test import TestCase
from oidc_provider.db_interfaces import OidcClientDatabase
from oidc_provider.models import TIMESTAMP_FIELDS, OidcRelyingParty


logger = logging.getLogger('django_test')


def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


CLIENT_ID = randomString()
CLIENT_TEST = {'client_id': '{}'.format(CLIENT_ID),
               'client_salt': '6flfsj0Z',
               'registration_access_token': 'z3PCMmC1HZ1QmXeXGOQMJpWQNQynM4xY',
               'registration_client_uri': 'https://127.0.0.1:8000/registration_api?client_id={}'.format(CLIENT_ID),
               'client_id_issued_at': 1575460012,
               'client_secret': '19cc69b70d0108f630e52f72f7a3bd37ba4e11678ad1a7434e9818e1',
               'client_secret_expires_at': 1575892012,
               'application_type': 'web',
               'contacts': ['ops@example.com'],
               'token_endpoint_auth_method': 'client_secret_basic',
               'jwks_uri': 'https://127.0.0.1:8099/static/jwks.json',
               'redirect_uris': [('https://127.0.0.1:8099/authz_cb/django_oidc_op', {})],
               'post_logout_redirect_uris': [('https://127.0.0.1:8099', None)],
               'response_types': ['code'],
               'grant_types': ['authorization_code']
               }


class TestRP(TestCase):
    rp = randomString().upper()
    cdb = OidcClientDatabase()
    now = pytz.utc.localize(datetime.datetime.utcnow())

    def setUp(self):
        self.client_obj = OidcRelyingParty.objects.create(client_id=self.rp,
                                                          client_secret_expires_at=self.now,
                                                          client_id_issued_at=self.now,
                                                          is_active=True)
        self.client = self.cdb[self.rp]
        print('Created and fetched RP: {}'.format(self.client))

    def test_get_set_client_db(self):
        for key in TIMESTAMP_FIELDS:
            value = self.client[key]
            assert isinstance(value, int) or \
                isinstance(value, float)

        # test_set_timestamp
        for key in TIMESTAMP_FIELDS:
            dt_value = self.now+datetime.timedelta(minutes=-60)
            self.client[key] = datetime.datetime.timestamp(dt_value)
            assert isinstance(self.client[key], int) or \
                isinstance(self.client[key], float)

        # contacts
        vt = ['testami@ora.it']
        self.client['contacts'] = vt
        assert self.client['contacts'] == vt
        # self.client_obj.contacts == vt

        # grant_types
        vt = ['authorization_code']
        self.client['grant_types'] = vt
        assert self.client['grant_types'] == vt
        # self.client_obj.grant_type == vt

        # response_types
        vt = ['code']
        self.client['response_types'] = vt
        assert self.client['response_types'] == vt
        # self.client_obj.response_types == vt

        # post_logout_redirect_uris
        vt = [('https://127.0.0.1:8099', None)]
        self.client['post_logout_redirect_uris'] = vt
        assert self.client['post_logout_redirect_uris'] == vt
        # self.client_obj.post_logout_redirect_uris == vt

        # redirect_uris
        vt = [('https://127.0.0.1:8099/authz_cb/django_oidc_op', {})]
        self.client['redirect_uris'] = vt
        assert self.client['redirect_uris'] == vt
        # self.client_obj.redirect_uris == vt

        logger.info(json.dumps(self.client.copy(), indent=2))

    def test_create_as_dict(self):
        logger.info('Test creare ad Dict')
        self.cdb[CLIENT_ID] = CLIENT_TEST
        logger.info(json.dumps(self.cdb[CLIENT_ID], indent=2))
