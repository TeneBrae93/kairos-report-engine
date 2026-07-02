import streamlit as st
st.set_page_config(page_title="Kairos Report Engine", page_icon="assets/KairosSecLogo.png", layout="wide")

hide_streamlit_style = """
<style>
#MainMenu {visibility: hidden;}
header {visibility: hidden;}
footer {visibility: hidden;}
</style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

from database.db import init_db, get_user_count
from utils.auth import cookie_controller
from utils.helpers import get_image_base64

from views.dashboard import show_dashboard
from views.manage_projects import show_manage_projects
from views.manage_findings import show_manage_findings
from views.vuln_library import show_vuln_library
from views.generate_report import show_generate_report
from views.templates import show_templates
from views.profile import show_profile
from views.admin import show_admin_users
from views.setup import show_setup
from views.login import show_login

init_db()

def main():
    if st.session_state.get('trigger_logout'):
        cookie_controller.remove('kairos_auth_token')
        st.session_state.clear()
        st.session_state.logged_out = True
        st.info("Securely logging you out...")
        st.markdown('<meta http-equiv="refresh" content="1">', unsafe_allow_html=True)
        return

    auth_token = cookie_controller.get('kairos_auth_token')
    if auth_token and not st.session_state.get('logged_in') and not st.session_state.get('logged_out'):
        from utils.auth import verify_token
        verified_username = verify_token(auth_token)
        if verified_username:
            st.session_state.logged_in = True
            st.session_state.username = verified_username
        else:
            cookie_controller.remove('kairos_auth_token')
        
    if not st.session_state.get('logged_in'):
        if get_user_count() == 0:
            show_setup()
        else:
            show_login()
        return

    logo_b64 = get_image_base64("assets/KairosSecLogo.png")
    st.sidebar.markdown(f'<a href="https://kairos-sec.com" target="_blank"><img src="data:image/png;base64,{logo_b64}" alt="Kairos Sec" width="75%" style="margin-bottom: 20px;"></a>', unsafe_allow_html=True)
    st.sidebar.title("Kairos Report Engine")
    menu = ["Dashboard", "Manage Projects", "Add Findings", "Vuln Library", "Generate Report", "Templates", "Profile", "Admin: Users", "Logout"]
    
    if "nav" not in st.session_state:
        st.session_state.nav = "Dashboard"
        
    choice = st.sidebar.radio("Navigation", menu, index=menu.index(st.session_state.nav))
    if choice != st.session_state.nav:
        if choice == "Logout":
            st.session_state.trigger_logout = True
            st.rerun()
        else:
            st.session_state.nav = choice
            st.rerun()

    if st.session_state.nav == "Dashboard":
        show_dashboard()
    elif st.session_state.nav == "Manage Projects":
        show_manage_projects()
    elif st.session_state.nav == "Add Findings":
        show_manage_findings()
    elif st.session_state.nav == "Vuln Library":
        show_vuln_library()
    elif st.session_state.nav == "Generate Report":
        show_generate_report()
    elif st.session_state.nav == "Templates":
        show_templates()
    elif st.session_state.nav == "Profile":
        show_profile()
    elif st.session_state.nav == "Admin: Users":
        show_admin_users()

if __name__ == "__main__":
    main()
