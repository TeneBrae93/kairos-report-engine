from database.db import get_connection

# --- System ---
def cleanup_deleted_items():
    conn = get_connection()
    cursor = conn.cursor()
    # Delete items where deleted_at is older than 30 days
    cursor.execute("DELETE FROM project_findings WHERE deleted_at IS NOT NULL AND datetime(deleted_at) <= datetime('now', '-30 days')")
    cursor.execute("DELETE FROM projects WHERE deleted_at IS NOT NULL AND datetime(deleted_at) <= datetime('now', '-30 days')")
    cursor.execute("DELETE FROM clients WHERE deleted_at IS NOT NULL AND datetime(deleted_at) <= datetime('now', '-30 days')")
    conn.commit()
    conn.close()

# --- Settings ---
def get_settings() -> dict:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings")
    settings = {row['key']: row['value'] for row in cursor.fetchall()}
    conn.close()
    return settings

def update_setting(key: str, value: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

# --- Clients ---
def get_clients() -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM clients WHERE deleted_at IS NULL")
    clients = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return clients

def get_deleted_clients() -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM clients WHERE deleted_at IS NOT NULL")
    clients = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return clients

def add_client(name: str, description: str = ''):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO clients (name, description) VALUES (?, ?)", (name, description))
    conn.commit()
    conn.close()

def delete_client(client_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE clients SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (client_id,))
    # Soft delete all associated projects
    cursor.execute("UPDATE projects SET deleted_at = CURRENT_TIMESTAMP WHERE client_id = ? AND deleted_at IS NULL", (client_id,))
    # Soft delete all findings for those projects
    cursor.execute("""
        UPDATE project_findings SET deleted_at = CURRENT_TIMESTAMP 
        WHERE project_id IN (SELECT id FROM projects WHERE client_id = ?) 
        AND deleted_at IS NULL
    """, (client_id,))
    conn.commit()
    conn.close()

def restore_client(client_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE clients SET deleted_at = NULL WHERE id = ?", (client_id,))
    conn.commit()
    conn.close()

def hard_delete_client(client_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM clients WHERE id = ?", (client_id,))
    conn.commit()
    conn.close()

# --- Projects ---
def get_projects() -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT p.*, c.name as client_name 
        FROM projects p 
        JOIN clients c ON p.client_id = c.id
        WHERE p.deleted_at IS NULL AND c.deleted_at IS NULL
    """)
    projects = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return projects

def get_deleted_projects() -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT p.*, c.name as client_name 
        FROM projects p 
        JOIN clients c ON p.client_id = c.id
        WHERE p.deleted_at IS NOT NULL
    """)
    projects = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return projects

def add_project(name: str, application_name: str, client_id: int, project_type: str = 'Web Application Penetration Test', start_date: str = '', end_date: str = '', report_date: str = '', tester_name: str = '', tester_description: str = '', hosts: str = '', summary_of_strengths: str = '', summary_of_weaknesses: str = '', cvss_mapping: str = '', tools_used: str = ''):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO projects (name, application_name, client_id, project_type, start_date, end_date, report_date, tester_name, tester_description, hosts, summary_of_strengths, summary_of_weaknesses, cvss_mapping, tools_used) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, application_name, client_id, project_type, start_date, end_date, report_date, tester_name, tester_description, hosts, summary_of_strengths, summary_of_weaknesses, cvss_mapping, tools_used))
    conn.commit()
    conn.close()

def update_project(project_id: int, name: str, application_name: str, project_type: str, start_date: str, end_date: str, report_date: str, tester_name: str, tester_description: str, hosts: str, summary_of_strengths: str, summary_of_weaknesses: str, cvss_mapping: str, tools_used: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE projects 
        SET name = ?, application_name = ?, project_type = ?, start_date = ?, end_date = ?, report_date = ?, tester_name = ?, tester_description = ?, hosts = ?, summary_of_strengths = ?, summary_of_weaknesses = ?, cvss_mapping = ?, tools_used = ?
        WHERE id = ?
    """, (name, application_name, project_type, start_date, end_date, report_date, tester_name, tester_description, hosts, summary_of_strengths, summary_of_weaknesses, cvss_mapping, tools_used, project_id))
    conn.commit()
    conn.close()

def update_project_attestation_bio(project_id: int, attestation_bio: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE projects SET attestation_bio = ? WHERE id = ?", (attestation_bio, project_id))
    conn.commit()
    conn.close()

def delete_project(project_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE projects SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (project_id,))
    # Soft delete all findings for this project
    cursor.execute("UPDATE project_findings SET deleted_at = CURRENT_TIMESTAMP WHERE project_id = ? AND deleted_at IS NULL", (project_id,))
    conn.commit()
    conn.close()

def restore_project(project_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE projects SET deleted_at = NULL WHERE id = ?", (project_id,))
    conn.commit()
    conn.close()

def hard_delete_project(project_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    conn.commit()
    conn.close()

# --- Vulnerability Library ---
def get_vuln_library() -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vuln_library")
    vulns = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return vulns

def add_to_vuln_library(title: str, severity: str, description: str = '', remediation: str = '', cvss: float = 0.0, cve: str = '', steps_to_reproduce: str = '', service_type: str = 'Web Application Penetration Test', cvss_vector: str = '', refs: str = ''):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO vuln_library (service_type, title, severity, description, remediation, cvss, cve, cvss_vector, refs, steps_to_reproduce)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (service_type, title, severity, description, remediation, cvss, cve, cvss_vector, refs, steps_to_reproduce))
    conn.commit()
    conn.close()

def delete_from_vuln_library(vuln_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vuln_library WHERE id = ?", (vuln_id,))
    conn.commit()
    conn.close()

# --- Project Findings ---
def get_project_findings(project_id: int) -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM project_findings WHERE project_id = ? AND deleted_at IS NULL", (project_id,))
    findings = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return findings

def get_deleted_project_findings() -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT f.*, p.name as project_name 
        FROM project_findings f 
        JOIN projects p ON f.project_id = p.id 
        WHERE f.deleted_at IS NOT NULL
    """)
    findings = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return findings

def add_project_finding(project_id: int, title: str, severity: str, description: str, remediation: str, cvss: float, host: str, path: str = '', cvss_vector: str = '', refs: str = '', steps_to_reproduce: str = ''):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO project_findings (project_id, title, severity, description, remediation, cvss, host, path, cvss_vector, refs, steps_to_reproduce)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (project_id, title, severity, description, remediation, cvss, host, path, cvss_vector, refs, steps_to_reproduce))
    conn.commit()
    conn.close()

def update_project_finding(finding_id: int, title: str, severity: str, description: str, remediation: str, cvss: float, host: str, path: str, cvss_vector: str, refs: str, steps_to_reproduce: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE project_findings 
        SET title = ?, severity = ?, description = ?, remediation = ?, cvss = ?, host = ?, path = ?, cvss_vector = ?, refs = ?, steps_to_reproduce = ?
        WHERE id = ?
    """, (title, severity, description, remediation, cvss, host, path, cvss_vector, refs, steps_to_reproduce, finding_id))
    conn.commit()
    conn.close()

def delete_project_finding(finding_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE project_findings SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (finding_id,))
    conn.commit()
    conn.close()

def restore_project_finding(finding_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE project_findings SET deleted_at = NULL WHERE id = ?", (finding_id,))
    conn.commit()
    conn.close()

def hard_delete_project_finding(finding_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM project_findings WHERE id = ?", (finding_id,))
    conn.commit()
    conn.close()

# --- Testers ---
def get_testers():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM testers")
    testers = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return testers

def add_tester(name, title, bio):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO testers (name, title, bio) VALUES (?, ?, ?)", (name, title, bio))
    conn.commit()
    conn.close()

def delete_tester(tester_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM testers WHERE id = ?", (tester_id,))
    conn.commit()
    conn.close()

def update_tester(tester_id, name, title, bio):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE testers SET name = ?, title = ?, bio = ? WHERE id = ?", (name, title, bio, tester_id))
    conn.commit()
    conn.close()

def get_client_with_most_recent_finding():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT p.client_id
        FROM project_findings f
        JOIN projects p ON f.project_id = p.id
        WHERE f.deleted_at IS NULL AND p.deleted_at IS NULL
        ORDER BY f.id DESC
        LIMIT 1
    """)
    row = cursor.fetchone()
    conn.close()
    return row['client_id'] if row else None
