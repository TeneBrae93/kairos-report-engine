import streamlit as st
import time
import pyotp
from database.db import get_user
from utils.auth import ph, get_cookie_controller, sign_token

def show_login():
    st.title("Kairos Login")
    
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = 0
    if 'lockout_until' not in st.session_state:
        st.session_state.lockout_until = 0
        
    if time.time() < st.session_state.lockout_until:
        st.error(f"Too many failed attempts. Try again in {int(st.session_state.lockout_until - time.time())} seconds.")
        return
        
    if 'mfa_user' in st.session_state:
        st.info("MFA Token Required")
        with st.form("mfa_form"):
            token = st.text_input("6-digit TOTP Token")
            if st.form_submit_button("Verify"):
                user = get_user(st.session_state.mfa_user)
                totp = pyotp.TOTP(user['mfa_secret'])
                token_clean = token.replace(" ", "")
                if totp.verify(token_clean, valid_window=1):
                    st.session_state.logged_in = True
                    st.session_state.username = user['username']
                    get_cookie_controller().set('kairos_auth_token', sign_token(user['username']), max_age=6*3600)
                    del st.session_state.mfa_user
                    st.session_state.login_attempts = 0
                    st.rerun()
                else:
                    st.error("Invalid token.")
                    st.session_state.login_attempts += 1
                    if st.session_state.login_attempts >= 3:
                        st.session_state.lockout_until = time.time() + 15
                        st.rerun()
        return

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Passphrase", type="password")
        
        if st.form_submit_button("Login"):
            user = get_user(username)
            if not user:
                st.error("Invalid credentials.")
                st.session_state.login_attempts += 1
            else:
                try:
                    ph.verify(user['password_hash'], password)
                    if user['mfa_enabled']:
                        st.session_state.mfa_user = username
                        st.rerun()
                    else:
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        get_cookie_controller().set('kairos_auth_token', sign_token(username), max_age=6*3600)
                        st.session_state.login_attempts = 0
                        st.rerun()
                except Exception:
                    st.error("Invalid credentials.")
                    st.session_state.login_attempts += 1
                    if st.session_state.login_attempts >= 3:
                        st.session_state.lockout_until = time.time() + 15
                        st.rerun()
