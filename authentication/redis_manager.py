import json

import redis

from django.conf import settings


class RedisManager:
    def __init__(self):
        self.redis = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True,
        )
        self.code_expiry = 600  # 10 minutes in seconds
        self.rate_limit_expiry = 1800  # 30 minutes in seconds
        self.max_attempts = 5

    def store_code(self, user_id, code, method):
        """Store 2FA code in Redis with expiration"""
        key = f"2fa:code:{user_id}"
        data = {"code": code, "method": method, "attempts": 0}
        self.redis.setex(key, self.code_expiry, json.dumps(data))

    def verify_code(self, user_id, entered_code):
        """Verify code and handle rate limiting"""
        key = f"2fa:code:{user_id}"
        data = self.redis.get(key)

        if not data:
            return False, "Code expired or not found"

        data = json.loads(data)
        data["attempts"] = data.get("attempts", 0) + 1

        if data["attempts"] > self.max_attempts:
            return False, "Too many attempts. Please request a new code"

        self.redis.setex(key, self.code_expiry, json.dumps(data))

        # Strip whitespace from both codes for comparison
        stored_code = data["code"].strip() if data["code"] else ""
        entered_code = entered_code.strip() if entered_code else ""

        return stored_code == entered_code, None

    def check_rate_limit(self, user_id):
        """Check if user has exceeded rate limit for code generation"""
        key = f"2fa:ratelimit:{user_id}"
        attempts = self.redis.get(key)

        if attempts and attempts.strip() and int(attempts) >= 5:  # Max 5 codes per hour
            return False

        self.redis.incr(key)
        self.redis.expire(key, self.rate_limit_expiry)
        return True
