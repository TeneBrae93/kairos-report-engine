import streamlit as st
import os
from database import operations as db

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
    st.write("Export your entire local database and project assets to a portable ZIP file.")
    if st.button("Generate Backup Archive"):
        import shutil
        shutil.make_archive('kairos_backup', 'zip', 'data')
        st.session_state.backup_ready = True
        st.rerun()
        
    if st.session_state.get('backup_ready'):
        if os.path.exists('kairos_backup.zip'):
            with open('kairos_backup.zip', 'rb') as f:
                st.download_button("Download ZIP", data=f, file_name="kairos_backup.zip", mime="application/zip")
