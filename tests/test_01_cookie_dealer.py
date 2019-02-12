import pytest
from cryptojwt.key_jar import init_key_jar
from oidcendpoint import rndstr

from oidcop.cookie import CookieDealer

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

KEYJAR = init_key_jar('public.jwks', 'private.jwks', KEYDEFS)


class TestCookieDealer(object):
    @pytest.fixture(autouse=True)
    def create_cookie_dealer(self):
        # conf = {
        #     "issuer": "https://example.com/",
        #     "password": "mycket hemligt",
        #     "token_expires_in": 600,
        #     "grant_expires_in": 300,
        #     "refresh_token_expires_in": 86400,
        #     "verify_ssl": False,
        #     "endpoint": {},
        #     "authentication": [{
        #         'acr': INTERNETPROTOCOLPASSWORD,
        #         'name': 'NoAuthn',
        #         'kwargs': {'user': 'diana'}
        #         }],
        #     'template_dir': 'template'
        #     }
        # endpoint_context = EndpointContext(conf, keyjar=KEYJAR)
        cookie_conf = {
            'symkey': 'ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch',
            'cookie': {
                'name': 'oidc_op',
                'domain': "127.0.0.1",
                'path': '/',
                'max_age': 3600
            }
        }

        self.cookie_dealer = CookieDealer(**cookie_conf)

    def test_init(self):
        assert self.cookie_dealer

    def test_create_cookie(self):
        _cookie = self.cookie_dealer.create_cookie('value', 'sso')
        assert _cookie

    def test_read_created_cookie(self):
        _cookie = self.cookie_dealer.create_cookie('value', 'sso')
        _value = self.cookie_dealer.get_cookie_value(_cookie)
        assert len(_value) == 3
        assert _value[0] == 'value'
        assert _value[2] == 'sso'

    def test_delete_cookie(self):
        _cookie = self.cookie_dealer.delete_cookie('openid')
        _morsel = _cookie['openid']
        assert _morsel['expires']
        _value = self.cookie_dealer.get_cookie_value(_cookie, 'openid')
        assert _value[0] == ''
        assert _value[2] == ''

    def test_mult_cookie(self):
        _cookie = self.cookie_dealer.create_cookie('value', 'sso')
        _cookie = self.cookie_dealer.append_cookie(_cookie, 'session',
                                                   'session_state', 'session')
        assert len(_cookie) == 2
        _value = self.cookie_dealer.get_cookie_value(_cookie, 'session')
        assert _value[0] == 'session_state'
        assert _value[2] == 'session'
        _value = self.cookie_dealer.get_cookie_value(_cookie, 'oidc_op')
        assert _value[0] == 'value'
        assert _value[2] == 'sso'

