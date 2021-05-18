import os
import pytest


from oidcop.exception import ConfigurationError
from oidcop.session.manager import PairWiseID
from oidcop.session.manager import PublicID
from oidcop.session.manager import SessionManager
from oidcop.token.handler import TokenHandler


class TestSessionManagerPairWiseID:
    def test_paiwise_id(self):
        # as param
        pw = PairWiseID(salt='salt')
        pw('diana', 'that-sector')

        # as file
        pw = PairWiseID(filename='salt.txt')
        pw('diana', 'that-sector')

        # prune
        os.remove('salt.txt')

        # again to test if a preexistent file going ot be used ...
        pw = PairWiseID(filename='salt.txt')

        try:
            pw = PairWiseID(filename='/tmp')
        except ConfigurationError:
            pass # that's ok

        # as random
        pw = PairWiseID()
        pw('diana', 'that-sector')

        self.cleanup()

    def cleanup(self):
        if os.path.isfile('salt.txt'):
            os.remove('salt.txt')


class TestSessionManagerPublicID:
        pw = PublicID()
        pw('diana', 'that-sector')


class TestSessionManagerConf:
        sman = SessionManager(
            handler = TokenHandler(),
            conf={'password': 'hola!'}
        )
