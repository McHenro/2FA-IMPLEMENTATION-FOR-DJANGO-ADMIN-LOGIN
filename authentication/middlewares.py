from authentication.models import TrustedDevice
from django.shortcuts import redirect
from django.urls import reverse

class TwoFactorAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        exempt_paths = [
            # reverse('login/'),
            reverse("authentication:verify_2fa"),
            reverse("authentication:send_2fa"),
            "/static/",
            "/admin/login/",
        ]

        if request.path.startswith("/admin/") and not any(
            request.path.startswith(path) for path in exempt_paths
        ):
            if not request.user.is_authenticated:
                return redirect("/admin/login/")

            try:
                two_factor = request.user.twofactorauth

                # Check for trusted device
                device_id = request.COOKIES.get("trusted_device")
                if device_id:
                    trusted_device = TrustedDevice.objects.filter(
                        user=request.user, device_id=device_id, is_active=True
                    ).first()
                    if trusted_device:
                        trusted_device.save()  # Update last_used
                        return self.get_response(request)

                if not two_factor.verified:
                    return redirect("authentication:verify_2fa")
            except Exception as e:
                print(e)
                return redirect("/login/")

        response = self.get_response(request)
        return response
    
