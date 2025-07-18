import json
import time
import uuid

import phonenumbers
import pyotp

from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.http import require_http_methods

from .models import TrustedDevice, TwoFactorAuth
from .services import TwoFactorService

two_factor_service = TwoFactorService()


@login_required
def totp_success(request):
    return render(request, "authentication/2fa/totp_success.html")


@login_required
def totp_disabled(request):
    return render(request, "authentication/2fa/totp_disabled.html")


@login_required
def backup_codes(request):
    codes = request.user.twofactorauth.backup_codes
    return render(request, "authentication/2fa/backup_codes.html", {"codes": codes})


@login_required
def home(request):
    two_factor, created = TwoFactorAuth.objects.get_or_create(user=request.user)
    trusted_devices = TrustedDevice.objects.filter(user=request.user, is_active=True)

    context = {
        "two_factor": two_factor,
        "trusted_devices_count": trusted_devices.count(),
        "backup_codes_count": len(two_factor.backup_codes)
        if two_factor.backup_codes
        else 0,
        "recent_devices": trusted_devices.order_by("-last_used")[:3],
        "is_secure": two_factor.totp_enabled
        or two_factor.preferred_method in ["sms", "email", "call"],
    }

    return render(request, "authentication/2fa/home.html", context)


@login_required
@require_http_methods(["POST"])
def send_2fa(request):
    if not request.user.is_authenticated:
        return redirect("admin:login")

    # Get or create TwoFactorAuth record
    two_factor, created = TwoFactorAuth.objects.get_or_create(user=request.user)

    # Use preferred method if not specified
    method = request.POST.get("method", two_factor.preferred_method)

    # Generate and send code
    success, result = two_factor_service.generate_and_send_code(request.user, method)

    if success:
        messages.success(request, result)
    else:
        messages.error(request, result)

    return redirect("authentication:verify_2fa")


@login_required
def verify_2fa(request):
    # Check if already verified in this session
    if request.session.get("is_2fa_verified"):
        return redirect(request.session.get("next", "admin:index"))

    # Check for trusted device
    device_id = request.COOKIES.get("device_id")
    if (
        device_id
        and TrustedDevice.objects.filter(
            user=request.user, device_id=device_id, is_active=True
        ).exists()
    ):
        # Mark as verified in the session
        request.session["is_2fa_verified"] = True
        return redirect(request.session.get("next", "admin:index"))

    # Get or create TwoFactorAuth record
    two_factor, created = TwoFactorAuth.objects.get_or_create(user=request.user)

    # If this is a new user without 2FA setup, send a code automatically
    if created or (not two_factor.totp_enabled and not two_factor.backup_codes):
        try:
            # Generate and send code using preferred method
            success, message = two_factor_service.generate_and_send_code(
                request.user, two_factor.preferred_method
            )
            if success:
                messages.success(request, message)
            else:
                messages.error(request, message)
        except Exception as e:
            messages.error(request, f"Error sending verification code: {str(e)}")

    # Handle form submission
    if request.method == "POST":
        code = request.POST.get("code")
        trust_device = request.POST.get("trust_device") == "on"

        if not code:
            return render(
                request, "authentication/2fa/verify.html", {
                    "error": "Please enter a verification code",
                    "totp_enabled": two_factor.totp_enabled and two_factor.totp_verified,
                    "has_backup_codes": bool(two_factor.backup_codes)
                }
            )

        success = False
        error = None

        # Check verification methods in order

        # 1. Check if it's a backup code
        if two_factor.backup_codes and code in two_factor.backup_codes:
            two_factor.backup_codes.remove(code)
            two_factor.save()
            success = True

        # 2. Check if it's a TOTP code (only if TOTP is enabled)
        elif two_factor.totp_enabled and two_factor.totp_verified:
            totp = pyotp.TOTP(two_factor.secret_key)
            if totp.verify(code):
                success = True

        # 3. Check if it's a code from Redis (email, SMS, etc.)
        else:
            success, error = two_factor_service.redis.verify_code(
                request.user.id, code
            )

        if success:
            # Mark as verified in both session and database
            request.session["is_2fa_verified"] = True
            two_factor.verified = True
            two_factor.save()

            # Redirect to the original URL or admin index
            next_url = request.session.get("next", "admin:index")
            response = redirect(next_url)

            # Handle trusted device
            if trust_device:
                device_id = request.COOKIES.get("device_id")
                if not device_id:
                    device_id = str(uuid.uuid4())
                    response.set_cookie(
                        "device_id",
                        device_id,
                        max_age=30 * 24 * 60 * 60,  # 30 days
                        httponly=True,
                        secure=request.is_secure(),
                        samesite="Lax",
                    )

                # Create or update trusted device
                TrustedDevice.objects.update_or_create(
                    user=request.user,
                    device_id=device_id,
                    defaults={
                        "device_name": request.META.get("HTTP_USER_AGENT", "Unknown Device"),
                        "is_active": True
                    }
                )

            return response
        else:
            return render(
                request, "authentication/2fa/verify.html", {
                    "error": error or "Invalid code",
                    "totp_enabled": two_factor.totp_enabled and two_factor.totp_verified,
                    "has_backup_codes": bool(two_factor.backup_codes)
                }
            )

    # Render the verification form
    return render(request, "authentication/2fa/verify.html", {
        "totp_enabled": two_factor.totp_enabled and two_factor.totp_verified,
        "has_backup_codes": bool(two_factor.backup_codes)
    })


@login_required
def generate_backup_codes(request):
    if request.method == "POST":
        codes = two_factor_service.generate_backup_codes()
        request.user.twofactorauth.backup_codes = codes
        request.user.twofactorauth.save()
        return render(request, "authentication/2fa/backup_codes.html", {"codes": codes})

    return render(request, "authentication/2fa/backup_codes.html")


@login_required
def setup_totp(request):
    two_factor = request.user.twofactorauth

    if request.method == "POST":
        code = request.POST.get("code")

        if two_factor_service.verify_totp_code(two_factor.secret_key, code):
            two_factor.totp_enabled = True
            two_factor.totp_verified = True
            two_factor.save()
            return redirect("authentication:totp_success")
        else:
            return render(
                request,
                "authentication/2fa/setup_totp.html",
                {"error": "Invalid code", "show_qr": True},
            )

    # Generate new QR code for initial setup
    qr_code, provisioning_uri = two_factor_service.generate_totp_qr(request.user)

    return render(
        request,
        "authentication/2fa/setup_totp.html",
        {
            "qr_code": qr_code,
            "secret_key": two_factor.secret_key,
            "provisioning_uri": provisioning_uri,
            "show_qr": not two_factor.totp_verified,
        },
    )


@login_required
def disable_totp(request):
    if request.method == "POST":
        code = request.POST.get("code")
        two_factor = request.user.twofactorauth

        if two_factor_service.verify_totp_code(two_factor.secret_key, code):
            two_factor.totp_enabled = False
            two_factor.totp_verified = False
            two_factor.secret_key = pyotp.random_base32()  # Generate new key
            two_factor.save()
            return redirect("authentication:totp_disabled")

    return render(request, "authentication/2fa/disable_totp.html")


@login_required
def manage_2fa_settings(request):
    two_factor, created = TwoFactorAuth.objects.get_or_create(user=request.user)
    trusted_devices = TrustedDevice.objects.filter(user=request.user, is_active=True)

    if request.method == "POST":
        action = request.POST.get("action")

        if action == "update_preferred_method":
            method = request.POST.get("preferred_method")
            if method in ["sms", "call"]:
                phone = request.POST.get("phone_number")
                try:
                    parsed_number = phonenumbers.parse(phone, None)
                    if not phonenumbers.is_valid_number(parsed_number):
                        raise ValidationError("Invalid phone number")
                    two_factor.phone_number = phonenumbers.format_number(
                        parsed_number, phonenumbers.PhoneNumberFormat.E164
                    )
                except Exception as e:
                    print(e)
                    messages.error(request, "Invalid phone number format")
                    return redirect("manage_2fa_settings")

            two_factor.preferred_method = method
            two_factor.save()
            messages.success(request, "Preferred method updated successfully")

        elif action == "revoke_device":
            device_id = request.POST.get("device_id")
            TrustedDevice.objects.filter(
                user=request.user, device_id=device_id, is_active=True
            ).update(is_active=False)
            messages.success(request, "Device access revoked")

        elif action == "revoke_all_devices":
            TrustedDevice.objects.filter(user=request.user, is_active=True).update(
                is_active=False
            )
            messages.success(request, "All devices revoked")

        elif action == "generate_backup_codes":
            codes = two_factor_service.generate_backup_codes()
            two_factor.backup_codes = codes
            two_factor.save()
            messages.success(request, "New backup codes generated")
            return render(request, "authentication/2fa/backup_codes.html", {"codes": codes})

        return redirect("authentication:manage_2fa_settings")

    qr_code = None
    provisioning_uri = None
    if not two_factor.totp_verified:
        qr_code, provisioning_uri = two_factor_service.generate_totp_qr(request.user)

    context = {
        "two_factor": two_factor,
        "trusted_devices": trusted_devices,
        "qr_code": qr_code,
        "provisioning_uri": provisioning_uri,
        "has_backup_codes": bool(two_factor.backup_codes),
        "phone_number": two_factor.phone_number,
    }

    return render(request, "authentication/2fa/settings.html", context)


@csrf_exempt
@csrf_protect
def request_code(request):
    if not request.user.is_authenticated:
        return JsonResponse({"success": False, "error": "Authentication required"})

    if request.method == "POST":
        try:
            # Handle both JSON and form data
            if request.content_type == 'application/json':
                data = json.loads(request.body)
                method = data.get("method")
            else:
                method = request.POST.get("method")

            # Default to user's preferred method if not specified
            if not method:
                two_factor, created = TwoFactorAuth.objects.get_or_create(user=request.user)
                method = two_factor.preferred_method

            success, result = two_factor_service.generate_and_send_code(request.user, method)

            if success:
                # Store the code request timestamp in the session
                request.session["last_code_request"] = time.time()

                if request.content_type == 'application/json':
                    return JsonResponse({"success": True, "message": result})
                else:
                    messages.success(request, result)
                    return redirect("authentication:verify_2fa")
            else:
                if request.content_type == 'application/json':
                    return JsonResponse({"success": False, "error": result})
                else:
                    messages.error(request, result)
                    return redirect("authentication:verify_2fa")

        except Exception as e:
            error_message = f"Error requesting code: {str(e)}"
            if request.content_type == 'application/json':
                return JsonResponse({"success": False, "error": error_message})
            else:
                messages.error(request, error_message)
                return redirect("authentication:verify_2fa")

    # GET request - show form to request a code
    two_factor, created = TwoFactorAuth.objects.get_or_create(user=request.user)
    return render(request, "authentication/2fa/request_code.html", {
        "preferred_method": two_factor.preferred_method,
        "phone_number": two_factor.phone_number
    })


def custom_logout(request):
    # Reset 2FA verification status if the user has a TwoFactorAuth record
    if request.user.is_authenticated:
        try:
            two_factor = request.user.twofactorauth
            two_factor.verified = False
            two_factor.save()
        except:
            pass

    # Clear session and cookies
    response = redirect("admin:login")
    response.delete_cookie("sessionid")
    if 'is_2fa_verified' in request.session:
        del request.session['is_2fa_verified']

    # Logout the user
    logout(request)
    return response
