import streamlit as st
import io
import csv
from database import operations as db
from streamlit_jodit import st_jodit

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
            with st.form(f"edit_vuln_{v['id']}"):
                e_service_type_idx = project_types.index(v.get('service_type', 'Web Application Penetration Test')) if v.get('service_type') in project_types else 0
                e_service_type = st.selectbox("Service Type", project_types, index=e_service_type_idx)
                
                e_title = st.text_input("Title", value=v['title'])
                
                e_sev_options = ["Critical", "High", "Medium", "Low", "Info"]
                e_sev_index = e_sev_options.index(v['severity']) if v['severity'] in e_sev_options else 4
                e_sev = st.selectbox("Severity", e_sev_options, index=e_sev_index)
                
                col_c, col_v = st.columns(2)
                e_cvss = col_c.number_input("CVSS", min_value=0.0, max_value=10.0, step=0.1, value=float(v.get('cvss') or 0.0))
                e_cvss_vector = col_v.text_input("CVSSv4 Vector String", value=v.get('cvss_vector', ''))
                
                e_cve = st.text_input("CVE ID", value=v.get('cve', ''))
                
                e_desc = st.text_area("Description", value=v.get('description', ''))
                
                st.markdown("**Steps to Reproduce**")
                jodit_config = {"theme": "dark", "style": {"background": "#0e1117", "color": "#ffffff"}, "height": 400, "uploader": {"insertImageAsBase64URI": True}}
                e_steps = st_jodit(value=v.get('steps_to_reproduce', ''), config=jodit_config, key=f"e_steps_{v['id']}")
                
                e_rem = st.text_area("Remediation", value=v.get('remediation', ''))
                e_refs = st.text_area("References (one URL per line)", value=v.get('refs', ''))
                
                if st.form_submit_button("Save Changes"):
                    db.update_in_vuln_library(v['id'], e_title, e_sev, e_desc, e_rem, e_cvss, e_cve, e_steps, e_service_type, e_cvss_vector, e_refs)
                    st.success("Saved!")
                    st.rerun()
            
            if st.button("Delete Vulnerability", key=f"del_vuln_{v['id']}"):
                db.delete_from_vuln_library(v['id'])
                st.rerun()
