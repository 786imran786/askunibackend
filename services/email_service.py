"""
Async email sending using background threads.
API endpoints respond immediately instead of blocking on Mailjet HTTP calls.
"""
import threading
import logging
import requests as http_requests

from config import MJ_API_KEY, MJ_SECRET_KEY, MAILJET_SENDER

logger = logging.getLogger(__name__)


def _send_via_mailjet(email: str, otp: str):
    """Blocking Mailjet call — always run inside a thread."""
    url = "https://api.mailjet.com/v3.1/send"
    payload = {
        "Messages": [{
            "From": {"Email": MAILJET_SENDER, "Name": "ASK-UNI"},
            "To": [{"Email": email}],
            "Subject": "Your OTP for ASK-UNI Verification",
            "TextPart": f"Your OTP for ASK-UNI verification is: {otp}",
            "HTMLPart": (
                f'<div style="font-family:Arial,sans-serif;max-width:400px;margin:auto;'
                f'padding:30px;border:1px solid #eee;border-radius:10px;">'
                f'<h2 style="color:#4F46E5;">ASK-UNI Verification</h2>'
                f'<p>Your one-time password is:</p>'
                f'<div style="font-size:32px;font-weight:bold;letter-spacing:6px;'
                f'color:#4F46E5;padding:15px;background:#F5F3FF;border-radius:8px;'
                f'text-align:center;">{otp}</div>'
                f'<p style="color:#666;font-size:13px;margin-top:15px;">'
                f'This code expires in 10 minutes. Do not share it with anyone.</p>'
                f'</div>'
            ),
        }]
    }
    try:
        resp = http_requests.post(url, auth=(MJ_API_KEY, MJ_SECRET_KEY), json=payload, timeout=10)
        if resp.status_code == 200:
            logger.info(f"OTP email sent to {email}")
        else:
            logger.error(f"Mailjet error {resp.status_code}: {resp.text}")
    except Exception as e:
        logger.error(f"Mailjet exception for {email}: {e}")


def send_otp_email(email: str, otp: str):
    """
    Non-blocking OTP email sender.
    Spawns a daemon thread so the API can respond immediately.
    """
    t = threading.Thread(target=_send_via_mailjet, args=(email, otp), daemon=True)
    t.start()


def send_otp_email_sync(email: str, otp: str) -> bool:
    """
    Blocking version for cases where we need to know if it succeeded
    (e.g., college OTP where we clear OTP on failure).
    """
    url = "https://api.mailjet.com/v3.1/send"
    payload = {
        "Messages": [{
            "From": {"Email": MAILJET_SENDER, "Name": "ASK-UNI"},
            "To": [{"Email": email}],
            "Subject": "Your OTP for ASK-UNI Verification",
            "TextPart": f"Your OTP for ASK-UNI verification is: {otp}",
            "HTMLPart": f"<h2>Your OTP is <b>{otp}</b></h2>",
        }]
    }
    try:
        resp = http_requests.post(url, auth=(MJ_API_KEY, MJ_SECRET_KEY), json=payload, timeout=10)
        return resp.status_code == 200
    except Exception as e:
        logger.error(f"Mailjet sync error for {email}: {e}")
        return False
