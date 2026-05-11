"""
Utility helpers — OTP generation, email validation, etc.
"""
import re
import random


def generate_otp() -> str:
    """Generate a 6-digit OTP."""
    return str(random.randint(100000, 999999))


def is_valid_lpu_email(email: str) -> bool:
    """Check if email is a valid LPU college email."""
    lpu_patterns = [
        r"^[a-zA-Z0-9._%+-]+@lpu\.in$",
        r"^[a-zA-Z0-9._%+-]+@students\.lpu\.in$",
        r"^[a-zA-Z0-9._%+-]+@lpu\.co\.in$",
    ]
    for pattern in lpu_patterns:
        if re.match(pattern, email, re.IGNORECASE):
            return True
    return False


def sanitize_string(value: str, max_length: int = 500) -> str:
    """Basic input sanitization — strip whitespace and cap length."""
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_length]
