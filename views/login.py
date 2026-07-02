import streamlit as st
import time
import pyotp
from database.db import get_user, record_failed_login, reset_failed_logins
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
                
                if user and user.get('lockout_until', 0) > time.time():
                    st.error(f"Account locked. Try again in {int(user['lockout_until'] - time.time())} seconds.")
                    return
                    
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
        
        if st.form_submit_button("Login"):
            user = get_user(username)
            if not user:
                # Burn the same amount of time as a real verify so timing does
                # not disclose whether the username exists.
                try:
                    ph.verify(_DUMMY_HASH, password)
                except Exception:
                    pass
                st.error("Invalid credentials.")
            else:
                if user.get('lockout_until', 0) > time.time():
                    st.error(f"Account locked. Try again in {int(user['lockout_until'] - time.time())} seconds.")
                else:
                    try:
                        ph.verify(user['password_hash'], password)
                        if user['mfa_enabled']:
                            st.session_state.mfa_user = username
                            st.rerun()
                        else:
                            reset_failed_logins(user['username'])
                            st.session_state.logged_in = True
                            st.session_state.username = username
                            get_cookie_controller().set('kairos_auth_token', sign_token(username), max_age=6*3600)
                            st.rerun()
                    except Exception:
                        record_failed_login(username)
                        st.error("Invalid credentials.")
                        st.rerun()
