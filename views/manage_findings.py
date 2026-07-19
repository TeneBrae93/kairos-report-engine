import streamlit as st
import os
from database import operations as db
from streamlit_jodit import st_jodit
from parsers.nessus import parse_nessus
from parsers.burp import parse_burp
from utils.helpers import process_base64_images, restore_base64_images, sanitize_rich_html

def show_manage_findings():
    st.title("Add Findings")
    st.write("Populate your project with specific security findings. You can manually create findings, import standardized issues directly from your Vulnerability Library, or automatically ingest raw XML output from Nessus and Burp Suite scanners.")
    projects = db.get_projects()
    active_client_id = st.session_state.get('active_client_id')
    if active_client_id:
        projects = [p for p in projects if p['client_id'] == active_client_id]
        
    if not projects:
        st.warning("Please create a project for the active client first.")
        return
        
    project_options = {f"{p['name']} (Client: {p['client_name']})": p['id'] for p in projects}
    project_options_list = list(project_options.keys())
    default_index = 0
    if 'manage_findings_project_id' in st.session_state:
        for i, p_name in enumerate(project_options_list):
            if project_options[p_name] == st.session_state.manage_findings_project_id:
                default_index = i
                break
                
    selected_project = st.selectbox("Select Project to manage findings", project_options_list, index=default_index)
    project_id = project_options[selected_project]
    
    active_project = next((p for p in projects if p['id'] == project_id), None)
    is_web_app = active_project and active_project.get('project_type') == 'Web Application Penetration Test'
    
    st.divider()
    st.subheader("Current Project Findings")
    findings = db.get_project_findings(project_id)
    if findings:
        for f in findings:
            with st.expander(f"[{f['severity']}] {f['title']} (Host: {f.get('host', 'N/A')})"):
                with st.form(f"edit_form_{f['id']}"):
                    e_title = st.text_input("Title", value=f['title'])
                    
                    e_sev_options = ["Critical", "High", "Medium", "Low", "Info"]
                    e_sev_index = e_sev_options.index(f['severity']) if f['severity'] in e_sev_options else 4
                    e_sev = st.selectbox("Severity", e_sev_options, index=e_sev_index)
                    
                    col_h, col_p = st.columns(2)
                    e_host = col_h.text_input("Host", value=f.get('host', ''))
                    if is_web_app:
                        e_path = col_p.text_input("Affected Path", value=f.get('path', ''))
                    else:
                        e_path = f.get('path', '')
                    
                    col_c, col_v = st.columns(2)
                    e_cvss = col_c.number_input("CVSS", min_value=0.0, max_value=10.0, step=0.1, value=float(f.get('cvss') or 0.0))
                    e_cvss_vector = col_v.text_input("CVSSv4 Vector String", value=f.get('cvss_vector', ''))
                    
                    e_desc = st.text_area("Description", value=f.get('description', ''))
                    e_rem = st.text_area("Remediation", value=f.get('remediation', ''))
                    e_refs = st.text_area("References (one URL per line)", value=f.get('refs', ''))
                    
                    st.markdown("**Steps to Reproduce & PoC**")
                    jodit_config = {"theme": "dark", "style": {"background": "#0e1117", "color": "#ffffff"}, "height": 400, "uploader": {"insertImageAsBase64URI": True}}
                    safe_steps = sanitize_rich_html(restore_base64_images(f.get('steps_to_reproduce', '')))
                    e_steps = st_jodit(value=safe_steps, config=jodit_config, key=f"e_steps_{f['id']}")
                    
                    if st.form_submit_button("Save Changes"):
                        processed_steps = process_base64_images(sanitize_rich_html(e_steps), active_project['client_id'], project_id)
                        db.update_project_finding(f['id'], e_title, e_sev, e_desc, e_rem, e_cvss, e_host, e_path, e_cvss_vector, e_refs, processed_steps)
                        st.success("Saved!")
                        st.rerun()
                
                if st.button("Delete Finding", key=f"del_find_{f['id']}"):
                    db.delete_project_finding(f['id'])
                    st.rerun()
    else:
        st.write("No findings yet.")

    st.divider()
    st.divider()
    
    with st.expander("Import from Library"):
        lib = db.get_vuln_library()
        
        if lib and active_project:
            lib = [v for v in lib if v.get('service_type') == active_project.get('project_type')]
            
        if not lib:
            st.info(f"No vulnerabilities found in the library for {active_project.get('project_type', 'this project type')}.")
        else:
            with st.form("import_from_lib"):
                lib_options = {f"[{v['severity']}] {v['title']}": v for v in lib}
                selected_vuln_name = st.selectbox("Select Vulnerability", list(lib_options.keys()))
                
                col_h, col_p = st.columns(2)
                lib_host = col_h.text_input("Host")
                if is_web_app:
                    lib_path = col_p.text_input("Affected Path (e.g. /admin)")
                else:
                    lib_path = ""
                
                if st.form_submit_button("Import to Project") and selected_vuln_name:
                    selected_vuln = lib_options[selected_vuln_name]
                    db.add_project_finding(
                        project_id,
                        selected_vuln['title'],
                        selected_vuln['severity'],
                        selected_vuln['description'],
                        selected_vuln['remediation'],
                        selected_vuln['cvss'],
                        lib_host,
                        lib_path,
                        selected_vuln.get('cvss_vector', ''),
                        selected_vuln.get('refs', ''),
                        sanitize_rich_html(selected_vuln.get('steps_to_reproduce', ''))
                    )
                    st.success("Imported finding from library.")
                    st.rerun()

    with st.expander("Import Scanner Output"):
        import_type = st.radio("Select Tool", ["Nessus", "Burp Suite"], horizontal=True)
        
        if import_type == "Nessus":
            uploaded_file = st.file_uploader("Upload Nessus File (.nessus)", type=['nessus', 'xml'])
            parser_func = parse_nessus
        else:
            uploaded_file = st.file_uploader("Upload Burp XML File", type=['xml'])
            parser_func = parse_burp
        
        if uploaded_file is not None:
            if st.button("Parse & Import Findings"):
                temp_path = f"data/temp_{uploaded_file.name}"
                with open(temp_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                    
                try:
                    findings = parser_func(temp_path)
                    st.success(f"Parsed {len(findings)} findings.")
                    for f in findings:
                        db.add_project_finding(
                            project_id, 
                            f['title'], 
                            f['severity'], 
                            f['description'], 
                            f['remediation'], 
                            f['cvss'], 
                            f['host'],
                            f.get('path', ''),
                            '',
                            '',
                            ''
                        )
                    st.success("Successfully added all findings to project!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error parsing file: {e}")
                finally:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)

    st.divider()
    if 'add_finding_key' not in st.session_state:
        st.session_state.add_finding_key = 0

    st.subheader("Add Manual Finding")
    with st.form(f"add_manual_finding_{st.session_state.add_finding_key}"):
        mf_title = st.text_input("Title")
        mf_sev = st.selectbox("Severity", ["Critical", "High", "Medium", "Low", "Info"])
        col_h, col_p = st.columns(2)
        mf_host = col_h.text_input("Host")
        if is_web_app:
            mf_path = col_p.text_input("Affected Path (e.g. /admin)")
        else:
            mf_path = ""
        
        col_c, col_v = st.columns(2)
        mf_cvss = col_c.number_input("CVSS", min_value=0.0, max_value=10.0, step=0.1)
        mf_cvss_vector = col_v.text_input("CVSSv4 Vector String")
        
        mf_desc = st.text_area("Description")
        st.markdown("**Steps to Reproduce**")
        jodit_config = {"theme": "dark", "style": {"background": "#0e1117", "color": "#ffffff"}, "placeholder": "Write your steps to reproduce here (you can paste images)...", "height": 400, "uploader": {"insertImageAsBase64URI": True}}
        mf_steps = st_jodit(value="", config=jodit_config, key=f"mf_steps_add_{st.session_state.add_finding_key}")
        mf_rem = st.text_area("Remediation")
        mf_refs = st.text_area("References (one URL per line)")
        if st.form_submit_button("Add Finding") and mf_title:
            processed_mf_steps = process_base64_images(sanitize_rich_html(mf_steps), active_project['client_id'], project_id)
            db.add_project_finding(project_id, mf_title, mf_sev, mf_desc, mf_rem, mf_cvss, mf_host, mf_path, mf_cvss_vector, mf_refs, processed_mf_steps)
            st.success("Added finding.")
            st.session_state.add_finding_key += 1
            st.rerun()
