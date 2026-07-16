import streamlit as st
import os

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
    
    template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
    template_root = os.path.realpath(template_dir)
    custom_template_path = os.path.join(template_dir, f'report_template_{safe_type}.md')
    default_template_path = os.path.join(template_dir, 'report_template.md')

    # CWE-22 defense: verify resolved path stays within templates/
    real_custom = os.path.realpath(custom_template_path)
    if not (real_custom.startswith(template_root + os.sep) or real_custom == template_root):
        st.error("Security error: template path escapes templates/ directory")
        return
    
    is_custom = os.path.exists(custom_template_path)
    if is_custom:
        st.info(f"Editing custom template for: **{selected_type}**")
        path_to_read = custom_template_path
    else:
        st.info(f"No custom template found for **{selected_type}**. Displaying the default template.")
        path_to_read = default_template_path
        
    try:
        # CWE-22 defense: verify read path stays within templates/
        real_read = os.path.realpath(path_to_read)
        if not (real_read.startswith(template_root + os.sep) or real_read == template_root):
            st.error("Security error: template path escapes templates/ directory")
            return
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
