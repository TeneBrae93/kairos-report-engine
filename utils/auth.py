import streamlit as st
from argon2 import PasswordHasher
from database import operations as db
import secrets
import hmac
import hashlib
import time

# Server-side token lifetime; kept in sync with the cookie max_age in login.py.
# Because the expiry is part of the signed payload, a leaked token stops working
# after this window instead of being valid forever.
TOKEN_TTL_SECONDS = 6 * 3600

ph = PasswordHasher()

def get_cookie_controller():
    if 'cookie_controller' not in st.session_state:
        from streamlit_cookies_controller import CookieController
        st.session_state.cookie_controller = CookieController()
    return st.session_state.cookie_controller

def get_hmac_secret():
    settings = db.get_settings()
    secret = settings.get('session_secret')
    if not secret:
        secret = secrets.token_hex(32)
        db.update_setting('session_secret', secret)
    return secret

def sign_token(username: str) -> str:
    secret = get_hmac_secret().encode()
    expiry = str(int(time.time()) + TOKEN_TTL_SECONDS)
    payload = f"{username}:{expiry}"
    mac = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{mac}"

def verify_token(token: str) -> str:
    # Expected format: username:expiry:mac  (username may itself contain ':')
    if not token or token.count(":") < 2:
        return None
    try:
        payload, mac = token.rsplit(":", 1)
        username, expiry = payload.rsplit(":", 1)
        expected_mac = hmac.new(get_hmac_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected_mac):
            return None
        if int(expiry) < int(time.time()):
            return None  # token expired
        return username
    except Exception:
        return None
