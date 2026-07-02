import streamlit as st
from argon2 import PasswordHasher
from database import operations as db
import secrets
import hmac
import hashlib

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
    mac = hmac.new(secret, username.encode(), hashlib.sha256).hexdigest()
    return f"{username}:{mac}"

def verify_token(token: str) -> str:
    if not token or ":" not in token:
        return None
    try:
        username, mac = token.rsplit(":", 1)
        expected_mac = hmac.new(get_hmac_secret().encode(), username.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(mac, expected_mac):
            return username
    except Exception:
        pass
    return None
