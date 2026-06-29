import streamlit as st
import pyotp
import qrcode
import io
from database.db import get_user, update_user_mfa, update_user_password
from argon2.exceptions import VerifyMismatchError
from utils.auth import ph

def show_profile():
    st.title("Security Profile")
    st.write(f"Logged in as: **{st.session_state.username}**")
    
    user = get_user(st.session_state.username)
    
    st.subheader("Multi-Factor Authentication (TOTP)")
    if user['mfa_enabled']:
        st.success("MFA is currently ENABLED on your account.")
        with st.form("disable_mfa_form"):
            curr_pw = st.text_input("Current Password", type="password", key="mfa_dis_pw")
            mfa_code = st.text_input("6-digit MFA Code", key="mfa_dis_code")
            if st.form_submit_button("Disable MFA"):
                try:
                    ph.verify(user['password_hash'], curr_pw)
                    totp = pyotp.TOTP(user['mfa_secret'])
                    code_clean = mfa_code.replace(" ", "")
                    if totp.verify(code_clean, valid_window=1):
                        update_user_mfa(st.session_state.username, None, False)
                        st.success("MFA Disabled.")
                        st.rerun()
                    else:
                        st.error("Invalid MFA code.")
                except VerifyMismatchError:
                    st.error("Incorrect current password.")
    else:
        st.warning("MFA is not enabled.")
        if 'mfa_setup_secret' not in st.session_state:
            if st.button("Enable MFA"):
                st.session_state.mfa_setup_secret = pyotp.random_base32()
                st.rerun()
                
        if 'mfa_setup_secret' in st.session_state:
            secret = st.session_state.mfa_setup_secret
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=st.session_state.username, issuer_name="Kairos Report Engine"
            )
            
            qr = qrcode.make(totp_uri)
            img_byte_arr = io.BytesIO()
            qr.save(img_byte_arr, format='PNG')
            img_bytes = img_byte_arr.getvalue()
            
            st.image(img_bytes, caption="Scan with Authenticator App", width=300)
            st.write(f"Manual Entry Code: `{secret}`")
            
            with st.form("verify_mfa_setup"):
                curr_pw = st.text_input("Current Password", type="password", key="mfa_en_pw")
                code = st.text_input("Enter 6-digit code to verify")
                if st.form_submit_button("Verify and Enable"):
                    try:
                        ph.verify(user['password_hash'], curr_pw)
                        totp = pyotp.TOTP(secret)
                        code_clean = code.replace(" ", "")
                        if totp.verify(code_clean, valid_window=1):
                            update_user_mfa(st.session_state.username, secret, True)
                            del st.session_state.mfa_setup_secret
                            st.success("MFA Successfully Enabled!")
                            st.rerun()
                        else:
                            st.error("Invalid code, try again.")
                    except VerifyMismatchError:
                        st.error("Incorrect current password.")

    st.divider()
    st.subheader("Change Password")
    with st.form("change_pw_form"):
        curr_pw = st.text_input("Current Password", type="password")
        mfa_code = ""
        if user['mfa_enabled']:
            mfa_code = st.text_input("MFA Code")
        new_pw = st.text_input("New Passphrase", type="password")
        confirm_pw = st.text_input("Confirm New Passphrase", type="password")
        
        if st.form_submit_button("Update Password"):
            try:
                ph.verify(user['password_hash'], curr_pw)
                mfa_valid = True
                if user['mfa_enabled']:
                    totp = pyotp.TOTP(user['mfa_secret'])
                    code_clean = mfa_code.replace(" ", "")
                    if not totp.verify(code_clean, valid_window=1):
                        mfa_valid = False
                        st.error("Invalid MFA code.")
                
                if mfa_valid:
                    if len(new_pw) < 12:
                        st.error("New passphrase must be at least 12 characters.")
                    elif new_pw != confirm_pw:
                        st.error("New passphrases do not match.")
                    else:
                        new_hash = ph.hash(new_pw)
                        update_user_password(st.session_state.username, new_hash)
                        st.success("Password updated successfully.")
            except VerifyMismatchError:
                st.error("Incorrect current password.")
