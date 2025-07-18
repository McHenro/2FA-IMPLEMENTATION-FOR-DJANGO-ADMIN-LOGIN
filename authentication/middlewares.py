from authentication.models import TrustedDevice
from django.shortcuts import redirect
from django.urls import reverse

class TwoFactorAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        exempt_paths = [
            reverse("authentication:verify_2fa"),
            reverse("authentication:send_2fa"),
            reverse("authentication:setup_totp"),
            reverse("authentication:disable_totp"),
            reverse("authentication:manage_2fa_settings"),
            reverse("authentication:totp_success"),
            reverse("authentication:totp_disabled"),
            reverse("authentication:request_code"),
            reverse("authentication:logout"),
            "/static/",
            "/admin/login/",
            "/admin/logout/",
        ]

        # Check if the path is exempt from 2FA
        is_exempt = any(request.path.startswith(path) for path in exempt_paths)

        # Only apply 2FA middleware for admin paths that are not exempt
        if request.path.startswith("/admin/") and not is_exempt:
            # If user is not authenticated, redirect to login
            if not request.user.is_authenticated:
                return redirect(reverse("admin:login"))

            try:
                # Check if 2FA is already verified in this session
                if request.session.get('is_2fa_verified'):
                    return self.get_response(request)

                # Get or create TwoFactorAuth record
                from authentication.models import TwoFactorAuth
                two_factor, created = TwoFactorAuth.objects.get_or_create(user=request.user)

                # Check for trusted device
                device_id = request.COOKIES.get("device_id")
                if device_id:
                    trusted_device = TrustedDevice.objects.filter(
                        user=request.user, device_id=device_id, is_active=True
                    ).first()
                    if trusted_device:
                        trusted_device.save()  # Update last_used
                        # Mark as verified in the session
                        request.session['is_2fa_verified'] = True
                        return self.get_response(request)

                # Store the original requested URL in the session
                request.session['next'] = request.path

                # Redirect to 2FA verification
                return redirect(reverse("authentication:verify_2fa"))

            except Exception as e:
                print(f"2FA Middleware error: {e}")
                return redirect(reverse("admin:login"))

        response = self.get_response(request)
        return response
