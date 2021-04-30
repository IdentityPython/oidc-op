from django.http import HttpResponse, Http404, HttpResponseRedirect, HttpResponseNotFound

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from .models import *
from .forms import *

from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ValidationError

from django.template import RequestContext
from django.core.urlresolvers import reverse

from django.contrib.auth import authenticate, login, logout
# from dal import autocomplete
# 
# class UserAutocomplete(autocomplete.Select2QuerySetView):
    # def get_queryset(self):
        # if not self.request.user.is_authenticated():
            # return User.objects.none()
        # qs = User.objects.all()
        # if self.q:
            # qs = qs.filter(  
                             # username__icontains=self.q 
                          # )
        # return qs
