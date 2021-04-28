import copy

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth import get_user_model
from django.template.loader import render_to_string

from oidcendpoint.util import instantiate
from oidcendpoint.user_authn.user import (create_signed_jwt,
                                          verify_signed_jwt)
from oidcendpoint.user_authn.user import UserAuthnMethod


class UserPassDjango(UserAuthnMethod):
    """
    see oidcendpoint.authn_context
        oidcendpoint.endpoint_context
        https://docs.djangoproject.com/en/2.2/ref/templates/api/#rendering-a-context
    """

    # TODO: get this though settings conf
    url_endpoint = "/verify/user_pass_django"


    def __init__(self,
                 # template_handler=render_to_string,
                 template="oidc_login.html",
                 endpoint_context=None, verify_endpoint='', **kwargs):
        """
        template_handler is only for backwards compatibility
        it will be always replaced by Django's default
        """
        super(UserPassDjango, self).__init__(endpoint_context=endpoint_context)

        self.kwargs = kwargs
        self.kwargs.setdefault("page_header", "Log in")
        self.kwargs.setdefault("user_label", "Username")
        self.kwargs.setdefault("passwd_label", "Password")
        self.kwargs.setdefault("submit_btn", "Log in")
        self.kwargs.setdefault("tos_uri", "")
        self.kwargs.setdefault("logo_uri", "")
        self.kwargs.setdefault("policy_uri", "")
        self.kwargs.setdefault("tos_label", "")
        self.kwargs.setdefault("logo_label", "")
        self.kwargs.setdefault("policy_label", "")

        # TODO this could be taken from args
        self.template_handler = render_to_string
        self.template = template

        self.action = verify_endpoint or self.url_endpoint
        self.kwargs['action'] = self.action


    def __call__(self, **kwargs):
        _ec = self.endpoint_context
        # Stores information need afterwards in a signed JWT that then
        # appears as a hidden input in the form
        jws = create_signed_jwt(_ec.issuer, _ec.keyjar, **kwargs)

        self.kwargs['token'] = jws

        _kwargs = self.kwargs.copy()
        for attr in ['policy', 'tos', 'logo']:
            _uri = '{}_uri'.format(attr)
            try:
                _kwargs[_uri] = kwargs[_uri]
            except KeyError:
                pass
            else:
                _label = '{}_label'.format(attr)
                _kwargs[_label] = LABELS[_uri]

        return self.template_handler(self.template, _kwargs)

    def verify(self, *args, **kwargs):
        username = kwargs["username"]
        password = kwargs["password"]

        user = authenticate(username=username, password=password)

        if username:
            return user
        else:
            raise FailedAuthentication()


class UserInfo(object):
    """ Read only interface to a user info store """

    def __init__(self, *args, **kwargs):
        self.claims_map = kwargs.get('claims_map', {})

    def filter(self, user, user_info_claims=None):
        """
        Return only those claims that are asked for.
        It's a best effort task; if essential claims are not present
        no error is flagged.

        :param userinfo: A dictionary containing the available info for one user
        :param user_info_claims: A dictionary specifying the asked for claims
        :return: A dictionary of filtered claims.
        """
        result = {}
        if not user.is_active:
            return result

        if user_info_claims is None:
            return copy.copy(user.__dict__)
        else:
            missing = []
            optional = []
            for key, restr in user_info_claims.items():
                if key in self.claims_map:
                    # manage required and optional: TODO extends this approach
                    if not hasattr(user, self.claims_map[key]) and restr == {"essential": True}:
                        missing.append(key)
                        continue
                    else:
                        optional.append(key)
                    #
                    uattr = getattr(user, self.claims_map[key], None)
                    if not uattr: continue
                    result[key] = uattr() if callable(uattr) else uattr
            return result

    def __call__(self, user_id, client_id, user_info_claims=None, **kwargs):
        """
        user_id = username
        client_id = client id, ex: 'mHwpZsDeWo5g'
        """
        user = get_user_model().objects.filter(username=user_id).first()
        if not user:
            # Todo: raise exception here, this wouldn't be possible.
            return {}

        try:
            return self.filter(user, user_info_claims)
        except KeyError:
            return {}

    def search(self, **kwargs):
        for uid, args in self.db.items():
            if dict_subset(kwargs, args):
                return uid

        raise KeyError('No matching user')
