import streamlit as st
import json
from database import operations as db

def show_manage_projects():
    st.title("Manage Projects")
    st.write("Create and edit penetration testing projects for your active client. Here you can define the project scope, tester details, overall strengths/weaknesses, and the specific tools utilized during the engagement.")
    
    clients = db.get_clients()
    if not clients:
        st.warning("Please create a client on the Dashboard first.")
        return

    client_options = {c['name']: c['id'] for c in clients}
    active_client_id = st.session_state.get('active_client_id')
    if active_client_id not in client_options.values():
        active_client_id = clients[0]['id']
        st.session_state.active_client_id = active_client_id
        
    active_client_name = next(c['name'] for c in clients if c['id'] == active_client_id)
    PROJECT_TYPES = [
        "Web Application Penetration Test",
        "Internal Network Penetration Test",
        "External Network Penetration Test",
        "AI/LLM Penetration Test",
        "Cloud Penetration Test"
    ]
    
    testers = db.get_testers()
    tester_options = {"No Tester": {"name": "", "bio": ""}}
    if testers:
        for t in testers:
            tester_options[t['name']] = t
            
    st.subheader("Add New Project")
    with st.form("add_project"):
        p_name = st.text_input("Project Name")
        p_app_name = st.text_input("Application Name (For Cover Page)")
        st.info(f"Adding new project for **{active_client_name}**")
        p_type = st.selectbox("Project Type", PROJECT_TYPES)
        p_tester = st.selectbox("Assigned Tester", list(tester_options.keys()))
        col_s, col_e, col_r = st.columns(3)
        p_start = col_s.date_input("Start Date").strftime('%Y-%m-%d')
        p_end = col_e.date_input("End Date").strftime('%Y-%m-%d')
        p_report_date = col_r.date_input("Report Date").strftime('%Y-%m-%d')
        
        if st.form_submit_button("Add Project") and p_name:
            settings = db.get_settings()
            selected_tester = tester_options[p_tester]
            db.add_project(
                name=p_name,
                application_name=p_app_name, 
                client_id=active_client_id, 
                project_type=p_type,
                start_date=p_start, 
                end_date=p_end,
                report_date=p_report_date,
                tester_name=selected_tester['name'],
                tester_description=selected_tester['bio'],
                hosts='',
                summary_of_strengths=settings.get('summary_of_strengths', ''),
                summary_of_weaknesses=settings.get('summary_of_weaknesses', ''),
                cvss_mapping=settings.get('cvss_mapping', ''),
                tools_used=settings.get('tools_used', '')
            )
            st.success(f"Added project: {p_name}")
            st.rerun()
            
    st.subheader(f"Existing Projects for {active_client_name}")
    projects = db.get_projects()
    active_client_projects = [p for p in projects if p['client_id'] == active_client_id]
    
    if not active_client_projects:
        st.write("*No projects found for this client.*")
        
    for p in active_client_projects:
        is_expanded = st.session_state.get('edit_project_id') == p['id']
        with st.expander(f"{p['name']} (Client: {p['client_name']})", expanded=is_expanded):
            with st.form(f"edit_proj_{p['id']}"):
                ep_name = st.text_input("Project Name", value=p['name'])
                ep_app_name = st.text_input("Application Name", value=p.get('application_name', ''))
                
                ep_type_idx = PROJECT_TYPES.index(p.get('project_type', 'Web Application Penetration Test')) if p.get('project_type', 'Web Application Penetration Test') in PROJECT_TYPES else 0
                ep_type = st.selectbox("Project Type", PROJECT_TYPES, index=ep_type_idx)
                col_s, col_e, col_r = st.columns(3)
                ep_start = col_s.text_input("Start Date", value=p.get('start_date', ''))
                ep_end = col_e.text_input("End Date", value=p.get('end_date', ''))
                ep_report_date = col_r.text_input("Report Date", value=p.get('report_date', ''))
                
                st.markdown("### Report Details")
                ep_tester_idx = 0
                ep_tester_name = p.get('tester_name', '')
                tester_names = list(tester_options.keys())
                if ep_tester_name in tester_names:
                    ep_tester_idx = tester_names.index(ep_tester_name)
                
                ep_tester = st.selectbox("Assigned Tester", tester_names, index=ep_tester_idx)
                p_hosts = st.text_area("Scope / Hosts", value=p.get('hosts', '') or '')
                s_strengths = st.text_area("Summary of Strengths", value=p.get('summary_of_strengths', '') or '', height=150)
                s_weaknesses = st.text_area("Summary of Weaknesses", value=p.get('summary_of_weaknesses', '') or '', height=150)
                
                st.markdown("#### Tools Used")
                tools_str = p.get('tools_used', '[]')
                try:
                    t_list = json.loads(tools_str)
                    if not isinstance(t_list, list):
                        t_list = [{"Name": "Tool", "Description": tools_str}]
                except Exception:
                    t_list = [{"Name": "Unknown Tool", "Description": tools_str}] if tools_str else []
                    
                if not t_list:
                    t_list = [{"Name": "", "Description": ""}]
                
                edited_t_list = st.data_editor(
                    t_list, 
                    column_config={
                        "Name": st.column_config.TextColumn("Tool Name", width="medium", required=True),
                        "Description": st.column_config.TextColumn("Description", width="large", required=True)
                    },
                    num_rows="dynamic", 
                    use_container_width=True, 
                    key=f"te_{p['id']}"
                )
                
                save_as_default = st.checkbox("Save these report details as Firm Defaults for future projects", key=f"sad_{p['id']}")
                
                if st.form_submit_button("Save Project details"):
                    cleaned_t_list = [t for t in edited_t_list if t.get("Name") or t.get("Description")]
                    t_used_json = json.dumps(cleaned_t_list)
                    selected_tester = tester_options[ep_tester]
                    db.update_project(p['id'], ep_name, ep_app_name, ep_type, ep_start, ep_end, ep_report_date, selected_tester['name'], selected_tester['bio'], p_hosts, s_strengths, s_weaknesses, p.get('cvss_mapping', ''), t_used_json)
                    if save_as_default:
                        db.update_setting('summary_of_strengths', s_strengths)
                        db.update_setting('summary_of_weaknesses', s_weaknesses)
                        db.update_setting('tools_used', t_used_json)
                    st.success("Project updated!")
                    st.rerun()

            if st.button("Delete Project", key=f"del_project_{p['id']}"):
                db.delete_project(p['id'])
                st.rerun()
