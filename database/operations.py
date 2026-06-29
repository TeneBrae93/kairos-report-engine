from database.db import get_connection

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
    cursor.execute("SELECT * FROM clients")
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

def delete_project(project_id: int):
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
    cursor.execute("SELECT * FROM project_findings WHERE project_id = ?", (project_id,))
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
        ORDER BY f.id DESC
        LIMIT 1
    """)
    row = cursor.fetchone()
    conn.close()
    return row['client_id'] if row else None
