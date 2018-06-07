import pytest
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcmsg.key_jar import init_key_jar

from oidcop.cookie import CookieDealer

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
    ]

KEYJAR = init_key_jar('public.jwks', 'private.jwks', KEYDEFS)


class TestCookieDealer(object):
    @pytest.fixture(autouse=True)
    def create_cookie_dealer(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "endpoint": {},
            "authentication": [{
                'acr': INTERNETPROTOCOLPASSWORD,
                'name': 'NoAuthn',
                'kwargs': {'user': 'diana'}
                }],
            'template_dir': 'template'
            }
        endpoint_context = EndpointContext(conf, keyjar=KEYJAR)

        self.cookie_dealer = CookieDealer(endpoint_context, 'kaka',
                                          'https://example.com', 'op')

    def test_init(self):
        assert self.cookie_dealer

    def test_create_cookie(self):
        _cookie = self.cookie_dealer.create_cookie('value', 'sso')
        assert _cookie

    def test_read_created_cookie(self):
        _cookie = self.cookie_dealer.create_cookie('value', 'sso')
        _value = self.cookie_dealer.get_cookie_value(_cookie[1])
        assert len(_value) == 3
        assert _value[0] == 'value'
        assert _value[2] == 'sso'

    def test_delete_cookie(self):
        _cookie = self.cookie_dealer.delete_cookie('openid')
        assert 'expires=' in _cookie[1]
        _value = self.cookie_dealer.get_cookie_value(_cookie[1], 'openid')
        assert _value[0] == ''
        assert _value[2] == ''
