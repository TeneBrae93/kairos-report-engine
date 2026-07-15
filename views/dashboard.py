import streamlit as st
import os
from database import operations as db
from database.db import get_user

@st.dialog("Restore Deleted Files")
def restore_files_dialog():
    db.cleanup_deleted_items()
    st.write("Items deleted within the last 30 days can be restored here.")
    
    del_clients = db.get_deleted_clients()
    del_projects = db.get_deleted_projects()
    del_findings = db.get_deleted_project_findings()
    
    if not del_clients and not del_projects and not del_findings:
        st.info("The recycle bin is empty.")
        return
        
    if del_clients:
        st.markdown("### Deleted Clients")
        for c in del_clients:
            col1, col2, col3 = st.columns([2, 1, 1])
            col1.write(c['name'])
            if col2.button("Restore", key=f"rc_{c['id']}"):
                db.restore_client(c['id'])
                st.rerun()
            if col3.button("Permanently Delete", key=f"hdc_{c['id']}", type="primary"):
                db.hard_delete_client(c['id'])
                st.rerun()
                
    if del_projects:
        st.markdown("### Deleted Projects")
        for p in del_projects:
            col1, col2, col3 = st.columns([2, 1, 1])
            col1.write(f"{p['name']} ({p.get('client_name', 'Unknown')})")
            if col2.button("Restore", key=f"rp_{p['id']}"):
                db.restore_project(p['id'])
                st.rerun()
            if col3.button("Permanently Delete", key=f"hdp_{p['id']}", type="primary"):
                db.hard_delete_project(p['id'])
                st.rerun()
                
    if del_findings:
        st.markdown("### Deleted Findings")
        for f in del_findings:
            col1, col2, col3 = st.columns([2, 1, 1])
            col1.write(f"{f['title']} ({f.get('project_name', 'Unknown')})")
            if col2.button("Restore", key=f"rf_{f['id']}"):
                db.restore_project_finding(f['id'])
                st.rerun()
            if col3.button("Permanently Delete", key=f"hdf_{f['id']}", type="primary"):
                db.hard_delete_project_finding(f['id'])
                st.rerun()

def show_dashboard():
    st.title("Kairos Report Engine")
    st.write("Welcome to the Kairos Report Engine. Use this dashboard as your central hub to configure firm-wide settings, manage your client roster, and quickly jump into specific client projects.")
    
    clients = db.get_clients()
    projects = db.get_projects()
    vulns = db.get_vuln_library()
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Active Clients", len(clients))
    col2.metric("Total Projects", len(projects))
    col3.metric("Vulns in Library", len(vulns))
    
    st.divider()
    
    st.subheader("Client Overview")
    
    with st.expander("Add New Client"):
        with st.form("dash_add_client"):
            c_name = st.text_input("Client Name")
            c_desc = st.text_area("Description")
            if st.form_submit_button("Add Client") and c_name:
                db.add_client(c_name, c_desc)
                st.success(f"Added client: {c_name}")
                st.rerun()

    clients = db.get_clients()
    if not clients:
        st.info("No clients found. Add a new client above to get started.")
    else:
        client_options = {c['name']: c['id'] for c in clients}
        client_options_list = list(client_options.keys())
        default_index = 0
        if 'active_client_id' not in st.session_state:
            recent_client = db.get_client_with_most_recent_finding()
            if recent_client:
                st.session_state.active_client_id = recent_client
                
        if 'active_client_id' in st.session_state:
            for i, c_name in enumerate(client_options_list):
                if client_options[c_name] == st.session_state.active_client_id:
                    default_index = i
                    break
                    
        selected_client_name = st.selectbox("Active Client", client_options_list, index=default_index)
        client_id = client_options[selected_client_name]
        st.session_state.active_client_id = client_id
        
        client_projects = [p for p in projects if p['client_id'] == client_id]
        
        if client_projects:
            st.markdown(f"**Projects for {selected_client_name}**")
            for cp in client_projects:
                with st.container():
                    col_pn, col_pb1, col_pb2 = st.columns([2, 1, 1])
                    col_pn.write(f"- {cp['name']} ({cp.get('project_type', 'Unknown Type')})")
                    if col_pb1.button("Edit Project", key=f"dash_go_proj_{cp['id']}"):
                        st.session_state.nav = "Manage Projects"
                        st.session_state.edit_project_id = cp['id']
                        st.rerun()
                    if col_pb2.button("Add Findings", key=f"dash_add_find_{cp['id']}"):
                        st.session_state.nav = "Add Findings"
                        st.session_state.manage_findings_project_id = cp['id']
                        st.rerun()
        else:
            st.write(f"*No projects assigned to {selected_client_name} yet.*")

    st.divider()
    
    settings = db.get_settings()
    st.subheader("Firm Settings")
    with st.form("dash_firm_settings"):
        c_f1, c_f2 = st.columns(2)
        firm_name = c_f1.text_input("Firm Name", value=settings.get('firm_name', 'Default Firm'))
        firm_website = c_f2.text_input("Firm Website", value=settings.get('firm_website', ''))
        if st.form_submit_button("Save Firm Settings"):
            db.update_setting('firm_name', firm_name)
            db.update_setting('firm_website', firm_website)
            st.success("Firm Settings updated!")
            st.rerun()

    st.subheader("Testing Team")
    testers = db.get_testers()
    if testers:
        for t in testers:
            with st.expander(f"**{t['name']}**"):
                with st.form(f"edit_tester_{t['id']}"):
                    col_t1, col_t2 = st.columns(2)
                    e_t_name = col_t1.text_input("Name", value=t['name'])
                    e_t_title = col_t2.text_input("Title", value=t.get('title', ''))
                    e_t_bio = st.text_area("Bio/Qualifications", value=t['bio'])
                    if st.form_submit_button("Save Changes"):
                        db.update_tester(t['id'], e_t_name, e_t_title, e_t_bio)
                        st.success("Tester updated.")
                        st.rerun()
                if st.button("Delete Tester", key=f"del_tester_{t['id']}"):
                    db.delete_tester(t['id'])
                    st.rerun()
    else:
        st.write("No testers added yet.")
        
    with st.expander("Add New Tester"):
        with st.form("add_tester"):
            col_t1, col_t2 = st.columns(2)
            t_name = col_t1.text_input("Name")
            t_title = col_t2.text_input("Title")
            t_bio = st.text_area("Bio/Qualifications")
            if st.form_submit_button("Add Tester") and t_name:
                db.add_tester(t_name, t_title, t_bio)
                st.success("Added tester.")
                st.rerun()

    st.divider()
    st.subheader("Data Management")

    current_user = get_user(st.session_state.username)
    is_admin = bool(current_user and current_user.get('is_admin'))

    if not is_admin:
        st.info(
            "Recycle bin recovery is available below. Full database backup "
            "export is restricted to Administrators, since the raw database "
            "file contains password hashes, MFA secrets, and the session "
            "signing key."
        )
        if st.button("Restore Deleted Files", use_container_width=True):
            restore_files_dialog()
    else:
        st.write("Export your entire local database and project assets to a portable ZIP file, or recover accidentally deleted items.")
        st.warning(
            "The backup archive contains the raw `kairos.db` file, including "
            "password hashes, MFA secrets, and the session signing secret. "
            "Handle downloaded backups as highly sensitive credential material."
        )

        col_dm1, col_dm2 = st.columns(2)
        with col_dm1:
            if st.button("Generate Backup Archive", use_container_width=True):
                import shutil
                shutil.make_archive('kairos_backup', 'zip', 'data')
                st.session_state.backup_ready = True
                st.rerun()

            if st.session_state.get('backup_ready'):
                if os.path.exists('kairos_backup.zip'):
                    with open('kairos_backup.zip', 'rb') as f:
                        st.download_button("Download ZIP", data=f, file_name="kairos_backup.zip", mime="application/zip", use_container_width=True)

        with col_dm2:
            if st.button("Restore Deleted Files", use_container_width=True):
                restore_files_dialog()