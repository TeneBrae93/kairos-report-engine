import streamlit as st
import os
import base64
from database import operations as db
from reporting.generator import generate_report, generate_attestation

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
    
    output_dir = "reports"
    out_filename = f"{output_dir}/report_{project['id']}.pdf"
    
    out_attestation = f"{output_dir}/attestation_{project['id']}.pdf"
    
    with st.expander("Attestation Letter Customization"):
        db_testers = db.get_testers()
        tester_name = project.get('tester_name', '')
        
        if project.get('attestation_bio') is not None:
            default_bio = project.get('attestation_bio')
        else:
            default_bio = ""
            if tester_name:
                db_tester = next((t for t in db_testers if t['name'] == tester_name), None)
                if db_tester:
                    default_bio = db_tester.get('bio', '')
        
        with st.form(f"attestation_customization_form_{project['id']}"):
            attestation_bio = st.text_area("Tester Bio for Attestation Letter", value=default_bio, height=150)
            if st.form_submit_button("Save Customization"):
                db.update_project_attestation_bio(project['id'], attestation_bio)
                st.success("Customization saved!")
                st.rerun()
    
    col_rep, col_att = st.columns(2)
    
    with col_rep:
        if st.button("Generate PDF Report", use_container_width=True):
            if not findings:
                st.error("No findings to report. Please add findings first.")
            else:
                with st.spinner("Generating PDF..."):
                    clients = db.get_clients()
                    client = next((c for c in clients if c['id'] == project['client_id']), None)
                    firm = db.get_settings()
                    try:
                        generate_report(project, client, firm, findings, out_filename)
                        st.success("Report generated successfully!")
                        
                        missing = []
                        if not project.get('tester_name'): missing.append("Assigned Tester")
                        if not project.get('summary_of_strengths'): missing.append("Summary of Strengths")
                        if not project.get('summary_of_weaknesses'): missing.append("Summary of Weaknesses")
                        if not project.get('tools_used') or project.get('tools_used') == '[]' or project.get('tools_used') == '[{"Name": "", "Description": ""}]': missing.append("Tools Used")
                        if not project.get('hosts'): missing.append("Scope / Hosts")
                        
                        if missing:
                            st.warning(f"Note: The following project fields are empty and may appear blank in the report: {', '.join(missing)}")
                            
                    except Exception as e:
                        st.error(f"Failed to generate report: {e}")
    
    with col_att:
        if st.button("Generate Attestation Letter", use_container_width=True):
            with st.spinner("Generating Attestation Letter..."):
                    clients = db.get_clients()
                    client = next((c for c in clients if c['id'] == project['client_id']), None)
                    firm = db.get_settings()
                    try:
                        generate_attestation(project, client, firm, out_attestation, custom_bio=attestation_bio)
                        st.success("Attestation Letter generated successfully!")
                        
                        missing = []
                        if not project.get('tester_name'): missing.append("Assigned Tester")
                        if not project.get('start_date'): missing.append("Start Date")
                        if not project.get('end_date'): missing.append("End Date")
                        if not project.get('application_name') and not project.get('hosts'): missing.append("Application Name or Scope")
                        if not attestation_bio: missing.append("Tester Bio")
                        
                        if missing:
                            st.warning(f"Note: The following fields are empty and may appear blank in the letter: {', '.join(missing)}")
                            
                    except Exception as e:
                        st.error(f"Failed to generate attestation: {e}")
                    
    if os.path.exists(out_filename):
        st.divider()
        st.subheader("Report")
        with open(out_filename, "rb") as pdf_file:
            pdf_data = pdf_file.read()
            st.download_button(
                label="Download PDF Report",
                data=pdf_data,
                file_name=f"Kairos_Report_{project['name'].replace(' ', '_')}.pdf",
                mime="application/pdf"
            )
        with st.expander("Preview Report"):
            base64_pdf = base64.b64encode(pdf_data).decode('utf-8')
            pdf_display = f'<iframe src="data:application/pdf;base64,{base64_pdf}" width="100%" height="800px" type="application/pdf"></iframe>'
            st.markdown(pdf_display, unsafe_allow_html=True)

    if os.path.exists(out_attestation):
        st.divider()
        st.subheader("Attestation Letter")
        with open(out_attestation, "rb") as pdf_file:
            pdf_data = pdf_file.read()
            st.download_button(
                label="Download Attestation Letter",
                data=pdf_data,
                file_name=f"Attestation_{project['name'].replace(' ', '_')}.pdf",
                mime="application/pdf"
            )
        with st.expander("Preview Attestation Letter"):
            base64_pdf = base64.b64encode(pdf_data).decode('utf-8')
            pdf_display = f'<iframe src="data:application/pdf;base64,{base64_pdf}" width="100%" height="800px" type="application/pdf"></iframe>'
            st.markdown(pdf_display, unsafe_allow_html=True)
