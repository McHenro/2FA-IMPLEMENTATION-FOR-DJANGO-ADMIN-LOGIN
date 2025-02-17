from django.urls import path
from . import views


urlpatterns = [
    path("2fa/send/", views.send_2fa, name="send_2fa"),
    path("2fa/verify/", views.verify_2fa, name="verify_2fa"),
    path("2fa/totp/setup/", views.setup_totp, name="setup_totp"),
    path("2fa/totp/disable/", views.disable_totp, name="disable_totp"),
    path("2fa/settings/", views.manage_2fa_settings, name="manage_2fa_settings"),
    path("totp_success/", views.totp_success, name="totp_success"),  # Add this line
    path("totp_disabled/", views.totp_disabled, name="totp_disabled"),
    path("", views.home, name="home"),
] 
