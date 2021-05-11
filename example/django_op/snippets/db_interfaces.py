import datetime
import json
import logging
import pytz

from django.contrib.auth import get_user_model
from django.utils import timezone
from oidcop.session.database import Database
from oidcop.session.info import UserSessionInfo
from . models import (OidcRelyingParty,
                      OidcRPResponseType,
                      OidcRPGrantType,
                      OidcRPContact,
                      OidcRPRedirectUri,
                      OidcSession,
                      OidcSessionSso,
                      TIMESTAMP_FIELDS,
                      is_state,
                      is_sid,
                      is_sub,
                      is_code)


logger = logging.getLogger(__name__)


class OidcClientDb(object):
    """
    Adaptation of a Django model as if it were a dict
    """
    model = OidcRelyingParty

    def __init__(self, *args, **kwargs):
        pass

    def __contains__(self, key):
        if self.model.objects.filter(client_id=key).first():
            return 1

    def __iter__(self):
        values = self.model.objects.all().values_list('client_id')
        self.clients = [cid[0] for cid in values]
        for value in (self.clients):
            yield value

    def get(self, key, excp=None, as_obj=False):
        client = self.model.objects.filter(client_id=key,
                                           is_active=True).first()
        if not client:
            return excp

        # set last_seen
        client.last_seen = timezone.localtime()
        client.save()
        if as_obj:
            return client
        return client.copy()

    def __getitem__(self, key):
        value = self.get(key)
        if not value:
            raise KeyError
        return value

    def keys(self):
        return self.model.objects.values_list('client_id', flat=True)

    def __setitem__(self, key, value):
        return self.set(key, value)

    def set(self, key, value):
        dv = value.copy()

        for k, v in dv.items():
            if isinstance(v, int) or isinstance(v, float):
                if k in TIMESTAMP_FIELDS:
                    dt = datetime.datetime.fromtimestamp(v)
                    dv[k] = pytz.utc.localize(dt)

        client = None
        # if the client already exists
        if dv.get('id'):
            client = self.model.objects.\
                filter(pk=dv['id']).first()

        if dv.get('client_id'):
            client = self.model.objects.\
                filter(client_id=dv['client_id']).first()

        if not client:
            client_id = dv.pop('client_id')
            client = self.model.objects.create(client_id=client_id)

        for k, v in dv.items():
            setattr(client, k, v)

        client.save()

    def __str__(self):
        return self.__dict__


class OidcSessionDb(Database):
    """
    Adaptation of a Django model as if it were a dict

    This class acts like a NoSQL storage but stores informations
    into a pure Django DB model
    """

    def __init__(self, conf_db=None, session_db=None, sso_db=None, cdb=None):
        self.conf_db = conf_db
        self.db = session_db or OidcSession
        self.sso_db = sso_db or OidcSessionSso
        self.cdb = cdb or OidcClientDb()

    def get_valid_sessions(self):
        return self.db.objects.filter().exclude(valid_until__lte=timezone.localtime())

    def get_by_sid(self, value):
        session = self.db.get_by_sid(value)
        if session:
            return session

    def get_by_state(self, value):
        session = self.get_valid_sessions().filter(state=value)
        if session:
            return session.last()

    def create_by_state(self, state):
        return self.db.objects.create(state=state)

    def __iter__(self):
        self.elems = self.keys()
        for value in (self.elems):
            yield value

    def __getitem__(self, *args, **kwargs):
        return self.get(*args, **kwargs)

    def get(self, key, excp=None):
        if is_sid(key):
            elem = self.db.get_by_sid(key)
        elif is_code(key):
            elem = self.get_valid_sessions().filter(code=key).last()
        else:
            # state is unpredictable, it's client side.
            # elem = self.get_valid_sessions().filter(state=key).last()
            elem = self.get_valid_sessions().filter(uid=key).last()

        if not elem:
            return
        elif elem.sid and elem.sid == key:
            return json.loads(elem.session_info)
        # elif elem.state == key:
        elif elem.uid == key:
            return elem.sso.sid

    def set_session_info(self, info_dict):
        # info_dict = {'user_id': 'wert', 'subordinate': [], 'revoked': False, 'type': 'UserSessionInfo'}

        session = self.get_valid_sessions().get(
            state=info_dict['authn_req']['state'])
        session.session_info = json.dumps(info_dict)
        session.code = info_dict.get('code')
        authn_event = info_dict.get('authn_event')
        valid_until = authn_event.get('valid_until')
        if valid_until:
            dt = datetime.datetime.fromtimestamp(valid_until)
            session.valid_until = pytz.utc.localize(dt)

        client_id = info_dict.get('client_id')
        session.client = self.cdb.get(key=client_id, as_obj=True)
        session.save()

    def set(self, key, value):
        if is_sid(key):
            # info_dict = {'code': 'Z0FBQUFBQmZESFowazFBWWJteTNMOTZQa25KZmV0N1U1VzB4VEZCVEN3SThQVnVFRWlSQ2FrODhpb3Yyd3JMenJQT01QWGpuMnJZQmQ4YVh3bF9sbUxqMU43VG1RQ01BbW9JdV8tbTNNSzREMUk2U2N4YXVwZ3ZWQ1ZvbXdFanRsbWJIaWQyVWZON0N5LU9mUlhZUGgwdFRDQkpRZ3dSR0lVQjBBT0s4OHc3REJOdUlPUGVOUU9ZRlZvU3FBdVU2LThUUWNhRDVocl9QWEswMmo3Y2VtLUNvWklsX0ViN1NfWFRJWksxSXhxNVVNQW9ySngtc2RCST0=', 'oauth_state': 'authz', 'client_id': 'Mz2LUfvqCbRQ', 'authn_req': {'redirect_uri': 'https://127.0.0.1:8099/authz_cb/django_oidc_op', 'scope': 'openid profile email address phone', 'response_type': 'code', 'nonce': 'mpuLL5IxgDvFDGAqlE05LwHO', 'state': 'eOzFkkGFHLT16zO6SqpOmc2rv6DZmf3g', 'code_challenge': 'lAs7I04g1Qh8mhTG8wxV0BfmrhzrSrl1ASp04C3Zmog', 'code_challenge_method': 'S256', 'client_id': 'Mz2LUfvqCbRQ'}, 'authn_event': {'uid': 'wert', 'salt': 'fc7AGQ==', 'authn_info': 'oidcop.user_authn.authn_context.INTERNETPROTOCOLPASSWORD', 'authn_time': 1594652276, 'valid_until': 1594655876}}
            info_dict = value
            self.set_session_info(info_dict)
        logger.debug('Session DB - set - {}'.format(session.copy()))

    def __setitem__(self, sid, instance):
        if is_sid(sid):
            try:
                instance.to_json()
            except ValueError:
                json.dumps(instance)
            except AttributeError:
                # it's a dict
                pass

            self.set_session_info(instance)

        elif isinstance(instance, UserSessionInfo):
            # {'_dict': {'user_id': 'wert', 'subordinate': [], 'revoked': False, 'type': 'UserSessionInfo'}, 'lax': False, 'jwt': None, 'jws_header': None, 'jwe_header': None, 'verify_ssl': True}
            self.set_session_info(instance.__dict__['_dict'])

        else:
            logger.error('{} tries __setitem__ {} in {}'.format(sid,
                                                                instance,
                                                                self.__class__.__name__))

    def __delitem__(self, key):
        if is_sid(key):
            ses = self.db.get_by_sid(key)
            if ses:
                ses.sso.delete()
                ses.delete()


class OidcSsoDb(object):
    """
    Adaptation of a Django model as if it were a dict

    This class acts like a NoSQL storage but stores informations
    into a pure Django DB model
    """

    def __init__(self, db_conf={}, db=None, session_handler=None):
        self._db = db or OidcSessionSso
        self._db_conf = db_conf
        self.session_handler = session_handler or db_conf.get(
            'session_hanlder') or OidcSessionDb()

    def _get_or_create(self, sid):
        sso = self._db.objects.filter(sid=sid).first()
        if not sso:
            sso = self._db.objects.create(sid=sid)
        return sso

    def __setitem__(self, k, value):
        if isinstance(value, dict):
            if value.get('state'):
                session = self.session_handler.create_by_state(k)
                session.sid = value['state'][0] \
                    if isinstance(value['state'], list) else value
                sso = self._db.objects.create()
                session.sso = sso
                session.save()
        else:
            # it would be quite useless for this implementation ...
            # k = '81c58c4037ab1939423ab4fb8b472fdd5fc3a3939e4debc81f52ed37'
            # value = <OidcSessionSso: user: wert - sub: None>
            pass


    def set(self, k, v):
        logging.info('{}:{} - already there'.format(k, v))


    def get(self, k, default):
        session = self.session_handler.get_by_state(k)
        if session:
            return session

        if is_sub(k):
            # sub
            return self._db.objects.filter(sub=k).last() or {}
        elif is_sid(k):
            # sid
            session = self.session_handler.get_by_sid(k)
            return session.sso if session else {}
        else:
            logger.debug(("{} can't find any attribute "
                          "with this name as attribute: {}").format(self, k))
            user = get_user_model().objects.filter(username=k).first()
            if user:
                logger.debug(
                    'Tryng to match to a username: Found {}'.format(user))
                return self._db.objects.filter(user=user).last()
            else:
                return {}

    def __delitem__(self, name):
        self.delete(name)

    def delete(self, name):
        session = self.session_handler.get_by_state(name)

        if is_sid(name):
            session = self.session_handler.get_by_sid(name)
        elif is_sub(name):
            sso = self._db.objects.filter(sub=name)
            sso.delete()
        if session:
            session.delete()
