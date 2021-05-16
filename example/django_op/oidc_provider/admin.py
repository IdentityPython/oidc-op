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


@admin.register(OidcIssuedToken)
class OidcIssuedTokenAdmin(admin.ModelAdmin):
    list_display = ['session', 'type', 'created']
    readonly_fields = (
        "type",
        "issued_at",
        "expires_at",
        "not_before",
        "revoked",
        "value",
        "usage_rules",
        "used",
        "based_on",
        "session",
        "uid"
    )


@admin.register(OidcSession)
class OidcSessionAdmin(admin.ModelAdmin):
    list_filter = ('created', 'modified', 'expires_at')
    list_display = ('user', 'user_uid', 'client',
                    'grant_uid', 'created', 'expires_at')
    search_fields = ('user__username', 'client__client_id')
    readonly_fields = ('user_uid', 'user', 'client',
                       'sub',
                       'created', 'expires_at',
                       'user_session_info_preview',
                       'client_session_info_preview',
                       'grant_preview',
                       'session_info_preview'
    )

    fieldsets = (
        (None, {
            'fields': (
                ('client', ),
                ('user_uid',),
                ('sub', ),
                ('created',),
                ('expires_at',),
            )
        },
        ),
        ('Session info',
         {
             # 'classes': ('collapse',),
             'fields': ('session_info_preview',),
         }
         ),

        ('User session info',
         {
             # 'classes': ('collapse',),
             'fields': (
                 ('user_session_info_preview'),
             )

         },
         ),

        ('Client session info',
         {
             # 'classes': ('collapse',),
             'fields': (
                 ('client_session_info_preview'),
             )

         },
         ),

        ('Grant session info',
         {
             # 'classes': ('collapse',),
             'fields': (
                 ('grant_preview'),
             )
         },
         ),
    )

    def user_session_info_preview(self, obj):
        dumps = json.dumps(obj.user_session_info, indent=2)
        return mark_safe(dumps.replace('\n', '<br>').replace(r' ', '&nbsp'))
    user_session_info_preview.short_description = 'User Session Info'

    def client_session_info_preview(self, obj):
        dumps = json.dumps(obj.client_session_info, indent=2)
        return mark_safe(dumps.replace('\n', '<br>').replace(r' ', '&nbsp'))
    client_session_info_preview.short_description = 'Client Session Info'

    def grant_preview(self, obj):
        dumps = json.dumps(obj.grant, indent=2)
        return mark_safe(dumps.replace('\n', '<br>').replace(r' ', '&nbsp'))
    grant_preview.short_description = 'Grant'

    def session_info_preview(self, obj):
        dumps = json.dumps(obj.session_info, indent=2)
        return mark_safe(dumps.replace('\n', '<br>').replace(r' ', '&nbsp'))
    session_info_preview.short_description = 'Session Info'

    class Media:
        js = ('js/textarea_autosize.js',)
