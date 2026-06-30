import sqlite3
import os

DB_PATH = 'data/kairos.db'

def get_connection():
    # Ensure the data directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # Create Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            mfa_secret TEXT,
            mfa_enabled BOOLEAN DEFAULT 0
        )
    ''')

    # Create Settings Table (Firm profile boilerplates)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')

    # Default settings
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('firm_name', 'Default Firm')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('executive_summary_template', 'This executive summary provides an overview of the engagement...')")

    # Create Testers Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS testers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            title TEXT,
            bio TEXT
        )
    ''')

    # Create Clients Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT
        )
    ''')

    # Create Projects Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            application_name TEXT,
            client_id INTEGER NOT NULL,
            start_date TEXT,
            end_date TEXT,
            report_date TEXT,
            tester_name TEXT,
            tester_description TEXT,
            hosts TEXT,
            summary_of_strengths TEXT,
            summary_of_weaknesses TEXT,
            cvss_mapping TEXT,
            tools_used TEXT,
            FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
        )
    ''')

    # Create Vulnerability Library Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vuln_library (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_type TEXT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            remediation TEXT,
            cvss REAL,
            cve TEXT,
            cvss_vector TEXT,
            refs TEXT,
            steps_to_reproduce TEXT
        )
    ''')

    # Create Project Findings Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS project_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            remediation TEXT,
            cvss REAL,
            host TEXT,
            path TEXT,
            cvss_vector TEXT,
            refs TEXT,
            steps_to_reproduce TEXT,
            FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
        )
    ''')

    # Ensure 'title' column exists in 'testers' table (Migration)
    cursor.execute("PRAGMA table_info(testers)")
    tester_columns = [col['name'] for col in cursor.fetchall()]
    if 'title' not in tester_columns:
        cursor.execute("ALTER TABLE testers ADD COLUMN title TEXT")

    # Migration: Add steps_to_reproduce if it doesn't exist
    try:
        cursor.execute("ALTER TABLE project_findings ADD COLUMN steps_to_reproduce TEXT")
    except sqlite3.OperationalError:
        pass

    # Migration: Add new project columns
    new_project_cols = ['tester_name', 'tester_description', 'hosts', 'summary_of_strengths', 'summary_of_weaknesses', 'cvss_mapping', 'tools_used', 'application_name', 'report_date']
    for col in new_project_cols:
        try:
            cursor.execute(f"ALTER TABLE projects ADD COLUMN {col} TEXT")
        except sqlite3.OperationalError:
            pass

    # Migration: Add steps_to_reproduce to vuln_library
    try:
        cursor.execute("ALTER TABLE vuln_library ADD COLUMN steps_to_reproduce TEXT")
    except sqlite3.OperationalError:
        pass

    # Migration: Add new finding columns
    new_finding_cols = ['path', 'cvss_vector', 'refs']
    for col in new_finding_cols:
        try:
            cursor.execute(f"ALTER TABLE project_findings ADD COLUMN {col} TEXT")
        except sqlite3.OperationalError:
            pass

    # Migration: Add deleted_at columns for Soft Delete functionality
    for table in ['clients', 'projects', 'project_findings']:
        try:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN deleted_at TEXT")
        except sqlite3.OperationalError:
            pass
            
    # Migration: Add attestation_bio to projects
    try:
        cursor.execute("ALTER TABLE projects ADD COLUMN attestation_bio TEXT")
    except sqlite3.OperationalError:
        pass
            
    # Migration: Add project_type to projects
    try:
        cursor.execute("ALTER TABLE projects ADD COLUMN project_type TEXT DEFAULT 'Web Application Penetration Test'")
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE vuln_library ADD COLUMN service_type TEXT")
        cursor.execute("UPDATE vuln_library SET service_type = 'Web Application Penetration Test' WHERE service_type IS NULL")
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE vuln_library ADD COLUMN cvss_vector TEXT")
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE vuln_library ADD COLUMN refs TEXT")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()

# User Management Functions
def get_user_count():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    conn.close()
    return count

def add_user(username, password_hash):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
    except sqlite3.IntegrityError:
        raise ValueError("Username already exists")
    finally:
        conn.close()

def get_user(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def update_user_mfa(username, mfa_secret, mfa_enabled):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET mfa_secret = ?, mfa_enabled = ? WHERE username = ?", (mfa_secret, mfa_enabled, username))
    conn.commit()
    conn.close()

def update_user_password(username, new_password_hash):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_password_hash, username))
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
