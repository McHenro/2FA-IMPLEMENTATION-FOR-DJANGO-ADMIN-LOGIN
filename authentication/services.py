import base64
import io
import random
import string
from urllib.parse import quote

import pyotp
import qrcode

from .redis_manager import RedisManager


class TwoFactorService:
    def __init__(self):
        self.redis = RedisManager()

    def generate_backup_codes(self, count=8):
        """Generate backup codes"""
        return [
            "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
            for _ in range(count)
        ]

    def generate_totp_code(self, secret_key):
        """Generate TOTP code"""
        totp = pyotp.TOTP(secret_key)
        return totp.now()

    def verify_totp_code(self, secret_key, code):
        """Verify TOTP code"""
        totp = pyotp.TOTP(secret_key)
        return totp.verify(code)

    def generate_and_send_code(self, user, method):
        """Generate and send 2FA code through specified method"""
        if not self.redis.check_rate_limit(user.id):
            return False, "Rate limit exceeded. Please try again later"

        if method == "totp":
            code = self.generate_totp_code(user.twofactorauth.secret_key)
        else:
            code = "".join(random.choices(string.digits, k=6))

        self.redis.store_code(user.id, code, method)
        return True, code

    def generate_totp_qr(self, user):
        """Generate QR code for TOTP setup"""
        totp = pyotp.TOTP(user.twofactorauth.secret_key)

        # Create provisioning URI
        issuer = quote("Your App Name")
        username = quote(user.username)
        provisioning_uri = totp.provisioning_uri(name=username, issuer_name=issuer)

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        # Create image
        img_buffer = io.BytesIO()
        qr.make_image(fill_color="black", back_color="white").save(
            img_buffer, format="PNG"
        )
        img_str = base64.b64encode(img_buffer.getvalue()).decode()

        return f"data:image/png;base64,{img_str}", provisioning_uri