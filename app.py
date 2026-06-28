import streamlit as st
import os
import uuid
from database.db import init_db, get_user_count, add_user, get_user, update_user_mfa
from database import operations as db
from parsers.nessus import parse_nessus
from parsers.burp import parse_burp
from reporting.generator import generate_report
from streamlit_jodit import st_jodit
import json
import csv
import io
import re
import base64
import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

def get_image_base64(path):
    with open(path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode()

def process_base64_images(html_content, client_id, project_id):
    if not html_content:
        return html_content
    
    pattern = re.compile(r'src="data:image/([^;]+);base64,([^"]+)"')
    
    def replacer(match):
        ext = match.group(1)
        b64_data = match.group(2)
        
        asset_dir = f"data/projects/{client_id}/{project_id}/assets"
        os.makedirs(asset_dir, exist_ok=True)
        
        filename = f"{uuid.uuid4().hex}.{ext}"
        filepath = os.path.join(asset_dir, filename)
        
        try:
            with open(filepath, "wb") as fh:
                fh.write(base64.b64decode(b64_data))
            abs_path = os.path.abspath(filepath)
            return f'src="file://{abs_path}"'
        except Exception as e:
            return match.group(0)
            
    return pattern.sub(replacer, html_content)

# Initialize DB on first run
init_db()

st.set_page_config(page_title="Kairos Report Engine", page_icon="assets/KairosSecLogo.png", layout="wide")

def main():
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
            st.session_state.clear()
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
    
    st.subheader("Add New Project")
    with st.form("add_project"):
        p_name = st.text_input("Project Name")
        p_app_name = st.text_input("Application Name (For Cover Page)")
        st.info(f"Adding new project for **{active_client_name}**")
        p_type = st.selectbox("Project Type", PROJECT_TYPES)
        col_s, col_e, col_r = st.columns(3)
        p_start = col_s.date_input("Start Date").strftime('%Y-%m-%d')
        p_end = col_e.date_input("End Date").strftime('%Y-%m-%d')
        p_report_date = col_r.date_input("Report Date").strftime('%Y-%m-%d')
        
        if st.form_submit_button("Add Project") and p_name:
            settings = db.get_settings()
            db.add_project(
                name=p_name,
                application_name=p_app_name, 
                client_id=active_client_id, 
                project_type=p_type,
                start_date=p_start, 
                end_date=p_end,
                report_date=p_report_date,
                tester_name=settings.get('tester_name', ''),
                tester_description=settings.get('tester_description', ''),
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
                t_name = st.text_input("Tester Name", value=p.get('tester_name', '') or '')
                t_label = f"{t_name} is ..." if t_name else "[Tester Name] is ..."
                t_desc = st.text_area(t_label, value=p.get('tester_description', '') or '', placeholder="an offensive security expert with a strong track record of...")
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
                    db.update_project(p['id'], ep_name, ep_app_name, ep_type, ep_start, ep_end, ep_report_date, t_name, t_desc, p_hosts, s_strengths, s_weaknesses, p.get('cvss_mapping', ''), t_used_json)
                    if save_as_default:
                        db.update_setting('tester_name', t_name)
                        db.update_setting('tester_description', t_desc)
                        db.update_setting('summary_of_strengths', s_strengths)
                        db.update_setting('summary_of_weaknesses', s_weaknesses)
                        db.update_setting('tools_used', t_used_json)
                    st.success("Project updated!")
                    st.rerun()

            if st.button("Delete Project", key=f"del_project_{p['id']}"):
                db.delete_project(p['id'])
                st.rerun()

def show_vuln_library():
    st.title("Vulnerability Library")
    st.write("Maintain a centralized repository of common vulnerabilities. You can manually add entries or bulk import CSVs to quickly populate your library, making it easier to pull standardized findings directly into your active projects.")
    
    project_types = [
        "Web Application Penetration Test",
        "Internal Network Penetration Test",
        "External Network Penetration Test",
        "AI/LLM Penetration Test",
        "Cloud Penetration Test"
    ]

    st.subheader("Bulk Import Vulnerabilities")
    
    # Sample CSV for download
    sample_csv = io.StringIO()
    writer = csv.writer(sample_csv)
    writer.writerow(["Service Type", "Title", "Severity", "CVSS Score", "CVSSv4 Vector String", "Description", "Remediation", "References"])
    writer.writerow(["Web Application Penetration Test", "Example SQL Injection", "Critical", "9.8", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "SQL injection found in the login form...", "Use parameterized queries...", "https://owasp.org/www-community/attacks/SQL_Injection"])
    
    st.download_button(
        label="Download Sample CSV Template",
        data=sample_csv.getvalue(),
        file_name="kairos_vuln_import_template.csv",
        mime="text/csv"
    )
    
    uploaded_csv = st.file_uploader("Upload CSV", type=['csv'])
    if uploaded_csv is not None:
        if st.button("Import CSV"):
            try:
                stringio = io.StringIO(uploaded_csv.getvalue().decode("utf-8"))
                reader = csv.DictReader(stringio)
                
                required_fields = ["Service Type", "Title", "Severity", "CVSS Score", "CVSSv4 Vector String", "Description", "Remediation", "References"]
                if not all(field in reader.fieldnames for field in required_fields):
                    st.error(f"Invalid CSV format. Missing one of the required fields: {', '.join(required_fields)}")
                else:
                    count = 0
                    for row in reader:
                        title = row.get("Title", "").strip()
                        if not title:
                            continue
                        
                        svc_type = row.get("Service Type", "Web Application Penetration Test").strip()
                        if svc_type not in project_types:
                            svc_type = "Web Application Penetration Test"
                            
                        sev = row.get("Severity", "Info").strip()
                        if sev not in ["Critical", "High", "Medium", "Low", "Info"]:
                            sev = "Info"
                            
                        try:
                            cvss = float(row.get("CVSS Score", 0.0))
                        except ValueError:
                            cvss = 0.0
                            
                        cvss_vector = row.get("CVSSv4 Vector String", "").strip()
                        cve = row.get("CVE ID", "").strip()
                        desc = row.get("Description", "").strip()
                        rem = row.get("Remediation", "").strip()
                        refs = row.get("References", "").strip()
                        steps = row.get("Steps to Reproduce", "").strip()
                        
                        db.add_to_vuln_library(title, sev, desc, rem, cvss, cve, steps, svc_type, cvss_vector, refs)
                        count += 1
                        
                    st.success(f"Successfully imported {count} vulnerabilities into the library!")
                    st.rerun()
            except Exception as e:
                st.error(f"Error parsing CSV: {e}")

    st.divider()

    st.subheader("Add Vulnerability Manually")
    with st.form("add_vuln_lib"):
        v_service_type = st.selectbox("Service Type", project_types)
        v_title = st.text_input("Title")
        v_sev = st.selectbox("Severity", ["Critical", "High", "Medium", "Low", "Info"])
        v_cvss = st.number_input("CVSS Score", min_value=0.0, max_value=10.0, step=0.1)
        v_cvss_vector = st.text_input("CVSSv4 Vector String")
        v_cve = st.text_input("CVE ID (optional)")
        v_desc = st.text_area("Description")
        st.markdown("**Steps to Reproduce**")
        jodit_config = {"theme": "dark", "style": {"background": "#0e1117", "color": "#ffffff"}, "placeholder": "Write your steps to reproduce here (you can paste images)...", "height": 400, "uploader": {"insertImageAsBase64URI": True}}
        v_steps = st_jodit(value="", config=jodit_config, key="v_steps_add")
        v_rem = st.text_area("Remediation")
        v_refs = st.text_area("References (one URL per line)")
        if st.form_submit_button("Add to Library") and v_title:
            db.add_to_vuln_library(v_title, v_sev, v_desc, v_rem, v_cvss, v_cve, v_steps, v_service_type, v_cvss_vector, v_refs)
            st.success("Added vulnerability to library.")
            st.rerun()

    st.divider()
    st.subheader("Library Entries")
    filter_service_type = st.selectbox("Filter by Service Type", ["All"] + project_types)
    
    lib = db.get_vuln_library()
    
    if filter_service_type != "All":
        lib = [v for v in lib if v.get('service_type') == filter_service_type]
        
    for v in lib:
        with st.expander(f"[{v['severity']}] {v['title']}"):
            st.write(f"**CVSS Score:** {v['cvss']}")
            if v.get('cvss_vector'):
                st.write(f"**CVSSv4 Vector String:** {v['cvss_vector']}")
            if v.get('cve'):
                st.write(f"**CVE ID:** {v['cve']}")
            st.write(f"**Description:** {v['description']}")
            if v.get('steps_to_reproduce'):
                st.write("**Steps to Reproduce:**")
                st.write(v['steps_to_reproduce'])
            st.write(f"**Remediation:** {v['remediation']}")
            if v.get('refs'):
                st.write(f"**References:**\n{v['refs']}")
            if st.button("Delete", key=f"del_vuln_{v['id']}"):
                db.delete_from_vuln_library(v['id'])
                st.rerun()

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
                    e_cvss = col_c.number_input("CVSS", min_value=0.0, max_value=10.0, step=0.1, value=float(f.get('cvss', 0.0)))
                    e_cvss_vector = col_v.text_input("CVSSv4 Vector String", value=f.get('cvss_vector', ''))
                    
                    e_desc = st.text_area("Description", value=f.get('description', ''))
                    e_rem = st.text_area("Remediation", value=f.get('remediation', ''))
                    e_refs = st.text_area("References (one URL per line)", value=f.get('refs', ''))
                    
                    st.markdown("**Steps to Reproduce & PoC**")
                    jodit_config = {"theme": "dark", "style": {"background": "#0e1117", "color": "#ffffff"}, "height": 400, "uploader": {"insertImageAsBase64URI": True}}
                    e_steps = st_jodit(value=f.get('steps_to_reproduce', ''), config=jodit_config, key=f"e_steps_{f['id']}")
                    
                    if st.form_submit_button("Save Changes"):
                        processed_steps = process_base64_images(e_steps, active_project['client_id'], project_id)
                        db.update_project_finding(f['id'], e_title, e_sev, e_desc, e_rem, e_cvss, e_host, e_path, e_cvss_vector, e_refs, processed_steps)
                        st.success("Saved!")
                        st.rerun()
                
                if st.button("Delete Finding", key=f"del_find_{f['id']}"):
                    db.delete_project_finding(f['id'])
                    st.rerun()
    else:
        st.write("No findings yet.")

    st.divider()
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Import from Library")
        lib = db.get_vuln_library()
        
        # Intelligently filter the library to only show vulnerabilities relevant to the current project's type
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
                        "", # cvss_vector
                        "", # refs
                        selected_vuln.get('steps_to_reproduce', '')
                    )
                    st.success("Imported finding from library.")
                    st.rerun()

        st.divider()

        st.subheader("Import Scanner Output")
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

    with col2:
        st.subheader("Add Manual Finding")
        with st.form("add_manual_finding"):
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
            mf_steps = st_jodit(value="", config=jodit_config, key="mf_steps_add")
            mf_rem = st.text_area("Remediation")
            mf_refs = st.text_area("References (one URL per line)")
            if st.form_submit_button("Add Finding") and mf_title:
                processed_mf_steps = process_base64_images(mf_steps, active_project['client_id'], project_id)
                db.add_project_finding(project_id, mf_title, mf_sev, mf_desc, mf_rem, mf_cvss, mf_host, mf_path, mf_cvss_vector, mf_refs, processed_mf_steps)
                st.success("Added finding.")
                st.rerun()


def show_generate_report():
    st.title("Generate Report")
    st.write("Compile all your project data and findings into a polished, professional PDF report. Select your active project below, verify the findings count, and click generate to produce the final deliverable.")
    
    projects = db.get_projects()
    active_client_id = st.session_state.get('active_client_id')
    if active_client_id:
        projects = [p for p in projects if p['client_id'] == active_client_id]
        
    if not projects:
        st.warning("Please create a project for the active client first.")
        return
        
    project_options = {f"{p['name']} (Client: {p['client_name']})": p for p in projects}
    selected_pname = st.selectbox("Select Project for Report", list(project_options.keys()))
    project = project_options[selected_pname]
    
    findings = db.get_project_findings(project['id'])
    st.write(f"Total findings for this project: {len(findings)}")
    
    if st.button("Generate PDF Report"):
        if not findings:
            st.error("No findings to report. Please add findings first.")
        else:
            with st.spinner("Generating PDF..."):
                clients = db.get_clients()
                client = next((c for c in clients if c['id'] == project['client_id']), None)
                firm = db.get_settings()
                
                output_dir = "reports"
                out_filename = f"{output_dir}/report_{project['id']}.pdf"
                
                try:
                    generate_report(project, client, firm, findings, out_filename)
                    st.success("Report generated successfully!")
                    
                    with open(out_filename, "rb") as pdf_file:
                        btn = st.download_button(
                            label="Download PDF",
                            data=pdf_file,
                            file_name=f"Kairos_Report_{project['name'].replace(' ', '_')}.pdf",
                            mime="application/pdf"
                        )
                except Exception as e:
                    st.error(f"Failed to generate report: {e}")



def show_templates():
    st.title("Report Templates")
    st.write("Customize the Markdown report template used for each specific assessment type.")
    
    project_types = [
        "Web Application Penetration Test",
        "Internal Network Penetration Test",
        "External Network Penetration Test",
        "AI/LLM Penetration Test",
        "Cloud Penetration Test"
    ]
    
    selected_type = st.selectbox("Select Project Type to Edit", project_types)
    safe_type = selected_type.replace(' ', '_').replace('/', '_')
    
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    custom_template_path = os.path.join(template_dir, f'report_template_{safe_type}.md')
    default_template_path = os.path.join(template_dir, 'report_template.md')
    
    is_custom = os.path.exists(custom_template_path)
    if is_custom:
        st.info(f"Editing custom template for: **{selected_type}**")
        path_to_read = custom_template_path
    else:
        st.info(f"No custom template found for **{selected_type}**. Displaying the default template.")
        path_to_read = default_template_path
        
    try:
        with open(path_to_read, 'r', encoding='utf-8') as f:
            template_content = f.read()
    except Exception as e:
        st.error(f"Error reading template: {e}")
        return
        
    with st.form("edit_template_form"):
        edited_content = st.text_area("Template Content (Markdown)", value=template_content, height=800)
        col1, col2 = st.columns([1, 1])
        
        with col1:
            if st.form_submit_button("Save Template"):
                try:
                    with open(custom_template_path, 'w', encoding='utf-8') as f:
                        f.write(edited_content)
                    st.success(f"Custom template saved for {selected_type}!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to save template: {e}")
                    
        with col2:
            if is_custom:
                if st.form_submit_button("Reset to Default (Delete Custom)"):
                    try:
                        os.remove(custom_template_path)
                        st.success(f"Custom template deleted for {selected_type}. Reverted to default.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to delete template: {e}")

def show_setup():
    st.title("Kairos First-Time Setup")
    st.write("Welcome to Kairos Report Engine. Since there are no users in the system, you must create the initial Administrator account.")
    
    with st.form("setup_form"):
        username = st.text_input("Administrator Username")
        password = st.text_input("Passphrase", type="password")
        password_confirm = st.text_input("Confirm Passphrase", type="password")
        
        if st.form_submit_button("Create Administrator"):
            if password != password_confirm:
                st.error("Passphrases do not match.")
            elif len(password) < 12:
                st.error("Passphrase must be at least 12 characters.")
            else:
                try:
                    hash_pw = ph.hash(password)
                    add_user(username, hash_pw)
                    st.success("Administrator account created! Please log in.")
                    st.rerun()
                except ValueError as e:
                    st.error(str(e))

def show_login():
    st.title("Kairos Login")
    
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = 0
    if 'lockout_until' not in st.session_state:
        st.session_state.lockout_until = 0
        
    import time
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
                if totp.verify(token):
                    st.session_state.logged_in = True
                    st.session_state.username = user['username']
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
                        st.session_state.login_attempts = 0
                        st.rerun()
                except VerifyMismatchError:
                    st.error("Invalid credentials.")
                    st.session_state.login_attempts += 1
            
            if st.session_state.login_attempts >= 3:
                st.session_state.lockout_until = time.time() + 15
                st.rerun()

def show_profile():
    st.title("Security Profile")
    st.write(f"Logged in as: **{st.session_state.username}**")
    
    user = get_user(st.session_state.username)
    
    st.subheader("Multi-Factor Authentication (TOTP)")
    if user['mfa_enabled']:
        st.success("MFA is currently ENABLED on your account.")
        if st.button("Disable MFA"):
            update_user_mfa(st.session_state.username, None, False)
            st.success("MFA Disabled.")
            st.rerun()
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
            import io
            img_byte_arr = io.BytesIO()
            qr.save(img_byte_arr, format='PNG')
            img_bytes = img_byte_arr.getvalue()
            
            st.image(img_bytes, caption="Scan with Authenticator App", width=300)
            st.write(f"Manual Entry Code: `{secret}`")
            
            with st.form("verify_mfa_setup"):
                code = st.text_input("Enter 6-digit code to verify")
                if st.form_submit_button("Verify and Enable"):
                    totp = pyotp.TOTP(secret)
                    if totp.verify(code):
                        update_user_mfa(st.session_state.username, secret, True)
                        del st.session_state.mfa_setup_secret
                        st.success("MFA Successfully Enabled!")
                        st.rerun()
                    else:
                        st.error("Invalid code, try again.")

def show_admin_users():
    st.title("User Management")
    st.write("Create additional accounts for your team.")
    
    with st.form("add_user_form"):
        username = st.text_input("New Username")
        password = st.text_input("Passphrase", type="password")
        
        if st.form_submit_button("Create User"):
            if len(password) < 12:
                st.error("Passphrase must be at least 12 characters.")
            else:
                try:
                    hash_pw = ph.hash(password)
                    add_user(username, hash_pw)
                    st.success(f"User {username} created!")
                except ValueError as e:
                    st.error(str(e))

if __name__ == "__main__":
    main()
