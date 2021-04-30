import logging

from django import forms
from django.contrib import admin
from django.contrib.sessions.models import Session
from django.utils.safestring import mark_safe

from . models import *
from . utils import decode_token


logger = logging.getLogger(__name__)


class OidcRPContactModelForm(forms.ModelForm):
    class Meta:
        model = OidcRPContact
        fields = ('__all__')


class OidcRPContactInline(admin.TabularInline):
    model = OidcRPContact
    form = OidcRPContactModelForm
    extra = 0


class OidcRPRedirectUriModelForm(forms.ModelForm):
    class Meta:
        model = OidcRPRedirectUri
        fields = ('__all__')


class OidcRPRedirectUriInline(admin.TabularInline):
    model = OidcRPRedirectUri
    form = OidcRPRedirectUriModelForm
    extra = 0


class OidcRPGrantTypeModelForm(forms.ModelForm):
    class Meta:
        model = OidcRPGrantType
        fields = ('__all__')


class OidcRPGrantTypeInline(admin.TabularInline):
    model = OidcRPGrantType
    form = OidcRPGrantTypeModelForm
    extra = 0


class OidcRPResponseTypeModelForm(forms.ModelForm):
    class Meta:
        model = OidcRPResponseType
        fields = ('__all__')


class OidcRPResponseTypeInline(admin.TabularInline):
    model = OidcRPResponseType
    form = OidcRPResponseTypeModelForm
    extra = 0


class OidcRPScopeModelForm(forms.ModelForm):
    class Meta:
        model = OidcRPScope
        fields = ('__all__')


class OidcRPScopeInline(admin.TabularInline):
    model = OidcRPScope
    form = OidcRPScopeModelForm
    extra = 0


@admin.register(OidcRelyingParty)
class OidcRelyingPartyAdmin(admin.ModelAdmin):
    list_filter = ('created', 'modified', 'is_active')
    list_display = ('client_id', 'created',
                    'last_seen', 'is_active')
    search_fields = ('client_id',)
    list_editable = ('is_active',)
    inlines = (OidcRPScopeInline,
               OidcRPResponseTypeInline,
               OidcRPGrantTypeInline,
               OidcRPContactInline,
               OidcRPRedirectUriInline)
    fieldsets = (
        (None, {
            'fields': (
                ('client_id', 'client_secret',),
                ('client_salt', 'jwks_uri'),
                ('registration_client_uri',),
                ('registration_access_token',),
                ('application_type',
                 'token_endpoint_auth_method'),
                ('is_active', )
            )
        },
        ),
        ('Temporal values',
         {
             'fields': (
                 (('client_id_issued_at',
                   'client_secret_expires_at',
                   'last_seen')),

             ),

         },
         ),
    )

    # def save_model(self, request, obj, form, change):
    # res = False
    # msg = ''
    # try:
    # json.dumps(obj.as_pysaml2_mdstore_row())
    # res = obj.validate()
    # super(MetadataStoreAdmin, self).save_model(request, obj, form, change)
    # except Exception as excp:
    # obj.is_valid = False
    # obj.save()
    # msg = str(excp)

    # if not res:
    # messages.set_level(request, messages.ERROR)
    # _msg = _("Storage {} is not valid, if 'mdq' at least a "
    # "valid url must be inserted. "
    # "If local: at least a file or a valid path").format(obj.name)
    # if msg: _msg = _msg + '. ' + msg
    # messages.add_message(request, messages.ERROR, _msg)


@admin.register(Session)
class SessionAdmin(admin.ModelAdmin):
    def _session_data(self, obj):
        return obj.get_decoded()
    list_display = ['session_key', '_session_data', 'expire_date']


@admin.register(OidcSession)
class OidcSessionAdmin(admin.ModelAdmin):
    list_filter = ('created', 'modified', 'valid_until')
    list_display = ('client', 'state', 'sso', 'created')
    search_fields = ('state', 'sso__user__username')
    readonly_fields = ('sid', 'client', 'sso', 'state', 'valid_until', 'info_session_preview',
                       'access_token_preview', 'id_token_preview')

    fieldsets = (
        (None, {
            'fields': (
                ('client', ),
                ('sso', ),
                ('state',),
                ('sid',),
                ('valid_until',),
            )
        },
        ),
        ('Session info',
         {
             'classes': ('collapse',),
             'fields': ('info_session_preview',),
         }
         ),

        ('Token previews',
         {
             'classes': ('collapse',),
             'fields': (
                 ('access_token_preview'),
                 ('id_token_preview'),
             )

         },
         ),
    )

    def info_session_preview(self, obj):
        msg = json.loads(obj.session_info or '{}')
        dumps = json.dumps(msg, indent=2)
        return mark_safe(dumps.replace('\n', '<br>').replace('\s', '&nbsp'))
    info_session_preview.short_description = 'Info Session preview'

    def access_token_preview(self, obj):
        try:
            msg = decode_token(obj.session_info or {}, 'access_token')
            dumps = json.dumps(msg.to_dict(), indent=2)
            return mark_safe(dumps.replace('\n', '<br>').replace('\s', '&nbsp'))
        except Exception as e:
            logger.tracelog(e)
    access_token_preview.short_description = 'Access Token preview'

    def id_token_preview(self, obj):
        try:
            msg = decode_token(obj.session_info or {}, 'id_token')
            dumps = json.dumps(msg.to_dict(), indent=2)
            return mark_safe(dumps.replace('\n', '<br>').replace('\s', '&nbsp'))
        except Exception as e:
            logger.tracelog(e)
    id_token_preview.short_description = 'ID Token preview'

    class Media:
        js = ('js/textarea_autosize.js',)
        # css = {'default': ('css/textarea_large.css',)}


@admin.register(OidcSessionSso)
class OidcSessionSsoAdmin(admin.ModelAdmin):
    list_filter = ('created', 'modified')
    list_display = ('user',
                    'sub', 'created')
    search_fields = ('user',)
    readonly_fields = ('sub', 'user')
