import streamlit as st
import os
import uuid
from database.db import init_db
from database import operations as db
from parsers.nessus import parse_nessus
from parsers.burp import parse_burp
from reporting.generator import generate_report
from streamlit_jodit import st_jodit
import json
import csv
import io

import base64

def get_image_base64(path):
    with open(path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode()

# Initialize DB on first run
init_db()

st.set_page_config(page_title="Kairos Report Engine", page_icon="assets/KairosSecLogo.png", layout="wide")

def main():
    logo_b64 = get_image_base64("assets/KairosSecLogo.png")
    st.sidebar.markdown(f'<a href="https://kairos-sec.com" target="_blank"><img src="data:image/png;base64,{logo_b64}" alt="Kairos Sec" width="75%" style="margin-bottom: 20px;"></a>', unsafe_allow_html=True)
    st.sidebar.title("Kairos Report Engine")
    menu = ["Dashboard", "Clients & Projects", "Vuln Library", "Manage Findings", "Generate Report", "Settings"]
    
    if "nav" not in st.session_state:
        st.session_state.nav = "Dashboard"
        
    choice = st.sidebar.radio("Navigation", menu, index=menu.index(st.session_state.nav))
    if choice != st.session_state.nav:
        st.session_state.nav = choice
        st.rerun()

    if st.session_state.nav == "Dashboard":
        show_dashboard()
    elif st.session_state.nav == "Clients & Projects":
        show_clients_projects()
    elif st.session_state.nav == "Vuln Library":
        show_vuln_library()
    elif st.session_state.nav == "Manage Findings":
        show_manage_findings()
    elif st.session_state.nav == "Generate Report":
        show_generate_report()
    elif st.session_state.nav == "Settings":
        show_settings()

def show_dashboard():
    st.title("Kairos Report Engine")
    st.write("Welcome to the Kairos Report Engine.")
    
    clients = db.get_clients()
    projects = db.get_projects()
    vulns = db.get_vuln_library()
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Active Clients", len(clients))
    col2.metric("Total Projects", len(projects))
    col3.metric("Vulns in Library", len(vulns))
    
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
    st.subheader("Project Overview")
    
    if not clients:
        st.info("No clients found. Head to 'Clients & Projects' to get started.")
        return
        
    col_c, col_p = st.columns(2)
    with col_c:
        client_options = {c['name']: c['id'] for c in clients}
        selected_client = st.selectbox("Select Client", list(client_options.keys()))
        
        client_id = client_options[selected_client]
        client_projects = [p for p in projects if p['client_id'] == client_id]
        
    with col_p:
        if not client_projects:
            st.info(f"No projects found for client: {selected_client}.")
            return
    
        project_options = {p['name']: p for p in client_projects}
        selected_project = st.selectbox("Select Project", list(project_options.keys()))
        proj = project_options[selected_project]
    
    proj_findings = db.get_project_findings(proj['id'])
    
    c1, c2 = st.columns(2)
    with c1:
        st.write(f"**Start Date:** {proj.get('start_date', 'N/A')}")
        st.write(f"**End Date:** {proj.get('end_date', 'N/A')}")
        st.write(f"**Tester:** {proj.get('tester_name', 'N/A')}")
    with c2:
        st.write(f"**Total Findings:** {len(proj_findings)}")
        if st.button("Go To Project"):
            st.session_state.nav = "Clients & Projects"
            st.session_state.edit_project_id = proj['id']
            st.rerun()
        
    st.divider()
    st.subheader("Tools Used")
    st.write("Manage the tools used during this engagement. These will be formatted as a table in the final report.")
    
    tools_str = proj.get('tools_used', '[]')
    try:
        tools_list = json.loads(tools_str)
        if not isinstance(tools_list, list):
            tools_list = [{"Name": "Tool", "Description": tools_str}]
    except Exception:
        tools_list = [{"Name": "Unknown Tool", "Description": tools_str}] if tools_str else []
        
    if not tools_list:
        tools_list = [{"Name": "", "Description": ""}]
        
    edited_tools = st.data_editor(
        tools_list, 
        column_config={
            "Name": st.column_config.TextColumn("Tool Name", width="medium", required=True),
            "Description": st.column_config.TextColumn("Description", width="large", required=True)
        },
        num_rows="dynamic", 
        use_container_width=True,
        key="dash_tools_editor"
    )
    
    if st.button("Save Tools to Project"):
        cleaned_tools = [t for t in edited_tools if t.get("Name") or t.get("Description")]
        db.update_project(
            proj['id'], proj['name'], proj.get('application_name', ''), proj.get('start_date', ''), proj.get('end_date', ''), proj.get('report_date', ''), 
            proj.get('tester_name', ''), proj.get('tester_description', ''), proj.get('hosts', ''), 
            proj.get('summary_of_strengths', ''), proj.get('summary_of_weaknesses', ''), 
            proj.get('cvss_mapping', ''), json.dumps(cleaned_tools)
        )
        st.success("Tools saved successfully!")
        st.rerun()

def show_settings():
    st.title("Settings / Firm Profile")
    st.write("Manage firm information and default boilerplate templates used in reports.")
    
    settings = db.get_settings()
    
    with st.form("settings_form"):
        firm_name = st.text_input("Firm Name", value=settings.get('firm_name', ''))
        firm_website = st.text_input("Firm Website", value=settings.get('firm_website', ''))
        exec_summary = st.text_area("Executive Summary Boilerplate", value=settings.get('executive_summary_template', ''), height=200)
        
        submitted = st.form_submit_button("Save Settings")
        if submitted:
            db.update_setting('firm_name', firm_name)
            db.update_setting('firm_website', firm_website)
            db.update_setting('executive_summary_template', exec_summary)
            st.success("Settings saved successfully!")

def show_clients_projects():
    st.title("Clients & Projects")
    
    if st.session_state.get('edit_project_id'):
        tab1, tab2 = st.tabs(["Manage Projects", "Manage Clients"])
        projects_tab, clients_tab = tab1, tab2
    else:
        tab1, tab2 = st.tabs(["Manage Clients", "Manage Projects"])
        clients_tab, projects_tab = tab1, tab2
    
    with clients_tab:
        st.subheader("Add New Client")
        with st.form("add_client"):
            c_name = st.text_input("Client Name")
            c_desc = st.text_area("Description")
            if st.form_submit_button("Add Client") and c_name:
                db.add_client(c_name, c_desc)
                st.success(f"Added client: {c_name}")
                st.rerun()
                
        st.subheader("Existing Clients")
        clients = db.get_clients()
        for c in clients:
            with st.expander(c['name']):
                st.write(c.get('description', 'No description'))
                if st.button("Delete Client", key=f"del_client_{c['id']}"):
                    db.delete_client(c['id'])
                    st.rerun()

    with projects_tab:
        clients = db.get_clients()
        if not clients:
            st.warning("Please create a client first.")
            return

        client_options = {c['name']: c['id'] for c in clients}
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
            p_client = st.selectbox("Client", list(client_options.keys()))
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
                    client_id=client_options[p_client], 
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
                
        st.subheader("Existing Projects")
        projects = db.get_projects()
        for p in projects:
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
    st.write("Manage common vulnerabilities for quick insertion into projects.")
    
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
    st.title("Manage Project Findings")
    projects = db.get_projects()
    if not projects:
        st.warning("Please create a project first.")
        return
        
    project_options = {p['name']: p['id'] for p in projects}
    selected_project = st.selectbox("Select Project to manage findings", list(project_options.keys()))
    project_id = project_options[selected_project]
    
    active_project = next((p for p in projects if p['id'] == project_id), None)
    is_web_app = active_project and active_project.get('project_type') == 'Web Application Penetration Test'
    
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
                db.add_project_finding(project_id, mf_title, mf_sev, mf_desc, mf_rem, mf_cvss, mf_host, mf_path, mf_cvss_vector, mf_refs, mf_steps)
                st.success("Added finding.")
                st.rerun()

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
                        db.update_project_finding(f['id'], e_title, e_sev, e_desc, e_rem, e_cvss, e_host, e_path, e_cvss_vector, e_refs, e_steps)
                        st.success("Saved!")
                        st.rerun()
                
                if st.button("Delete Finding", key=f"del_find_{f['id']}"):
                    db.delete_project_finding(f['id'])
                    st.rerun()
    else:
        st.write("No findings yet.")

def show_generate_report():
    st.title("Generate Report")
    
    projects = db.get_projects()
    if not projects:
        st.warning("Please create a project first.")
        return
        
    project_options = {p['name']: p for p in projects}
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

if __name__ == "__main__":
    main()
