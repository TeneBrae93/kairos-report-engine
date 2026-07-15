import streamlit as st
from database.db import add_user, get_user
from argon2.exceptions import VerifyMismatchError
from utils.auth import ph

def show_admin_users():
    # Defense in depth: even though app.py's router should already keep
    # non-admins off this page, never trust a single gate for a
    # privileged action. Refuse outright if the session's account isn't
    # actually flagged as admin.
    current_user = get_user(st.session_state.username)
    if not current_user or not current_user.get('is_admin'):
        st.error("You do not have permission to view this page.")
        return

    st.title("User Management")
    st.write("Create additional accounts for your team.")

    with st.form("add_user_form"):
        admin_pw = st.text_input("Your Current Password (Admin)", type="password")
        st.divider()
        username = st.text_input("New Username")
        password = st.text_input("New User Passphrase", type="password")
        grant_admin = st.checkbox("Grant this user Administrator privileges")

        if st.form_submit_button("Create User"):
            try:
                ph.verify(current_user['password_hash'], admin_pw)
                if len(password) < 12:
                    st.error("Passphrase must be at least 12 characters.")
                else:
                    try:
                        hash_pw = ph.hash(password)
                        add_user(username, hash_pw, is_admin=grant_admin)
                        st.success(f"User {username} created!")
                    except ValueError as e:
                        st.error(str(e))
            except VerifyMismatchError:
                st.error("Incorrect admin password.")