from django import forms
from django.contrib import admin

from .models import *

class PersistentIdInline(admin.TabularInline):
	 model = PersistentId
	 extra = 0
