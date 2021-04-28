from django.urls import path

from . import views

app_name = 'oidc_provider'


urlpatterns = [
    path('.well-known/<str:service>', views.well_known,
         name="oidc_op_well_known"),
    path('registration', views.registration,
         name="oidc_op_registration"),
    path('registration_api', views.registration_api,
         name="oidc_op_registration_api"),

    path('authorization', views.authorization,
         name="oidc_op_authorization"),

    path('verify/oidc_user_login/', views.verify_user,
         name="oidc_op_verify_user"),
    path('token', views.token, name="oidc_op_token"),
    path('userinfo', views.userinfo, name="oidc_op_userinfo"),


    path('check_session_iframe', views.check_session_iframe,
         name="oidc_op_check_session_iframe"),
    path('session', views.session_endpoint, name="oidc_op_session"),
    # logout
    path('verify_logout', views.verify_logout,
         name="oidc_op_verify_logout"),
    path('post_logout', views.post_logout, name="oidc_op_post_logout"),
    path('rp_logout', views.rp_logout, name="oidc_op_rp_logout"),
]
