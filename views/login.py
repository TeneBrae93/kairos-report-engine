import streamlit as st
import time
import pyotp
import random
import string
from captcha.image import ImageCaptcha
from database.db import get_user, record_failed_login, reset_failed_logins, get_failed_logins
from utils.auth import ph, get_cookie_controller, sign_token

# Precomputed once so a login attempt for a *nonexistent* user still performs an
# Argon2 verification of the same cost as a real one. Without this, the response
# time (fast reject vs. slow hash) reveals which usernames exist.
_DUMMY_HASH = ph.hash("kairos_constant_time_placeholder")

def show_login():
    st.title("Kairos Login")
    
    if 'mfa_user' in st.session_state:
        st.info("MFA Token Required")
        with st.form("mfa_form"):
            token = st.text_input("6-digit TOTP Token")
            if st.form_submit_button("Verify"):
                user = get_user(st.session_state.mfa_user)
                if not user:
                    st.error("Invalid token.")
                    st.rerun()
                    
                totp = pyotp.TOTP(user['mfa_secret'])
                token_clean = token.replace(" ", "")
                if totp.verify(token_clean, valid_window=1):
                    reset_failed_logins(user['username'])
                    st.session_state.logged_in = True
                    st.session_state.username = user['username']
                    get_cookie_controller().set('kairos_auth_token', sign_token(user['username']), max_age=6*3600)
                    del st.session_state.mfa_user
                    st.rerun()
                else:
                    record_failed_login(user['username'])
                    st.error("Invalid token.")
                    st.rerun()
        return

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Passphrase", type="password")
        
        needs_captcha = (st.session_state.get('captcha_required_for') == username) and username != ""
        captcha_input = ""
        if needs_captcha:
            if 'captcha_text' not in st.session_state or st.session_state.get('captcha_target') != username:
                image = ImageCaptcha(width=280, height=90)
                text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
                st.session_state.captcha_text = text
                st.session_state.captcha_target = username
                st.session_state.captcha_image = image.generate(text).getvalue()
            
            st.image(st.session_state.captcha_image)
            captcha_input = st.text_input("Enter CAPTCHA above")
            
        if st.form_submit_button("Login"):
            if not username:
                st.error("Please enter a username.")
                st.rerun()
                
            failed_attempts = get_failed_logins(username)
            if failed_attempts >= 2:
                if st.session_state.get('captcha_required_for') != username:
                    st.session_state.captcha_required_for = username
                    if 'captcha_text' in st.session_state:
                        del st.session_state['captcha_text']
                    st.error("Too many failed attempts. Please solve the CAPTCHA.")
                    st.rerun()
                else:
                    if not captcha_input or captcha_input.upper() != st.session_state.get('captcha_text', '').upper():
                        if 'captcha_text' in st.session_state:
                            del st.session_state['captcha_text']
                        st.error("Invalid CAPTCHA.")
                        st.rerun()
            
            user = get_user(username)
            if not user:
                try:
                    ph.verify(_DUMMY_HASH, password)
                except Exception:
                    pass
                record_failed_login(username)
                if 'captcha_text' in st.session_state:
                    del st.session_state['captcha_text']
                st.error("Invalid username or password.")
                st.rerun()
            else:
                try:
                    ph.verify(user['password_hash'], password)
                    if user['mfa_enabled']:
                        st.session_state.mfa_user = username
                        st.rerun()
                    else:
                        reset_failed_logins(username)
                        if 'captcha_required_for' in st.session_state:
                            del st.session_state['captcha_required_for']
                        if 'captcha_text' in st.session_state:
                            del st.session_state['captcha_text']
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        get_cookie_controller().set('kairos_auth_token', sign_token(username), max_age=6*3600)
                        st.rerun()
                except Exception:
                    record_failed_login(username)
                    if 'captcha_text' in st.session_state:
                        del st.session_state['captcha_text']
                    st.error("Invalid username or password.")
                    st.rerun()
