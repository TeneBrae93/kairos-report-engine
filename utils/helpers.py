import os
import hashlib
import re
import base64
import shutil
import tempfile

import nh3

RICH_TEXT_TAGS = {
    'a', 'abbr', 'b', 'blockquote', 'br', 'code', 'del', 'div', 'em',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img', 'li',
    'ol', 'p', 'pre', 's', 'span', 'strong', 'sub', 'sup', 'table',
    'tbody', 'td', 'th', 'thead', 'tr', 'u', 'ul'
}
RICH_TEXT_ATTRIBUTES = {
    '*': {'class', 'title'},
    'a': {'href', 'target', 'title'},
    'img': {'src', 'alt', 'title', 'width', 'height'},
    'ol': {'start', 'type'},
    'li': {'value'},
    'td': {'colspan', 'rowspan'},
    'th': {'colspan', 'rowspan'},
}
RICH_TEXT_URL_SCHEMES = {'data', 'http', 'https', 'mailto'}
RICH_TEXT_DROP_CONTENT = {'embed', 'iframe', 'math', 'object', 'script', 'style', 'svg', 'template'}


def sanitize_rich_html(html_content: str) -> str:
    """Return the supported rich-text subset with executable markup removed."""
    if not html_content:
        return ''
    return nh3.clean(
        html_content,
        tags=RICH_TEXT_TAGS,
        attributes=RICH_TEXT_ATTRIBUTES,
        clean_content_tags=RICH_TEXT_DROP_CONTENT,
        url_schemes=RICH_TEXT_URL_SCHEMES,
        strip_comments=True,
    )


def normalize_code_blocks_for_markdown(html_content: str) -> str:
    """Ensure <pre> blocks start on their own block lines so Python-Markdown preserves multi-line code blocks."""
    if not html_content:
        return ''
    return re.sub(
        r'\s*(<pre\b[^>]*>.*?</pre>)\s*',
        r'\n\n\1\n\n',
        html_content,
        flags=re.DOTALL | re.IGNORECASE,
    )


def _inject_script_into_build_dir(build_dir: str, plugin_js_path: str) -> bool:
    """Copy jodit_codeblock.js into the Streamlit Jodit build dir and link it in index.html."""
    index_path = os.path.join(build_dir, "index.html")
    target_js_path = os.path.join(build_dir, "jodit_codeblock.js")
    if not os.path.exists(index_path) or not os.path.exists(plugin_js_path):
        return False

    with open(plugin_js_path, "rb") as src_f:
        plugin_bytes = src_f.read()
    plugin_hash = hashlib.md5(plugin_bytes).hexdigest()[:8]

    with open(target_js_path, "wb") as dst_f:
        dst_f.write(plugin_bytes)

    with open(index_path, "r", encoding="utf-8") as idx_f:
        html = idx_f.read()

    script_tag = f'<script defer="defer" src="./jodit_codeblock.js?v={plugin_hash}"></script>'
    if "jodit_codeblock.js" in html:
        updated_html = re.sub(
            r'<script[^>]*src="\./jodit_codeblock\.js[^"]*"[^>]*></script>',
            script_tag,
            html,
        )
    else:
        updated_html = html.replace("</head>", f"{script_tag}</head>", 1)

    if updated_html != html:
        with open(index_path, "w", encoding="utf-8") as idx_f:
            idx_f.write(updated_html)
    return True


def ensure_jodit_codeblock_plugin() -> None:
    """Ensure the Streamlit Jodit component includes the custom Code Block toolbar & footer button."""
    plugin_js_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jodit_codeblock.js")
    if not os.path.exists(plugin_js_path):
        return

    try:
        import streamlit_jodit
        import streamlit.components.v1 as components

        pkg_dir = os.path.dirname(os.path.abspath(streamlit_jodit.__file__))
        orig_build_dir = os.path.join(pkg_dir, "frontend", "build")
        if not os.path.exists(orig_build_dir):
            return

        try:
            _inject_script_into_build_dir(orig_build_dir, plugin_js_path)
        except OSError:
            fallback_dir = os.path.join(tempfile.gettempdir(), "kairos_jodit_build")
            if not os.path.exists(fallback_dir):
                shutil.copytree(orig_build_dir, fallback_dir, dirs_exist_ok=True)
            _inject_script_into_build_dir(fallback_dir, plugin_js_path)
            streamlit_jodit._component_func = components.declare_component(
                "streamlit_jodit", path=fallback_dir
            )
    except Exception:
        pass


ensure_jodit_codeblock_plugin()


def get_image_base64(path):
    with open(path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode()

def restore_base64_images(html_content):
    if not html_content:
        return html_content
        
    pattern = re.compile(r'src="file://([^"]+)"')
    
    def replacer(match):
        filepath = match.group(1)
        if not os.path.exists(filepath):
            rel_match = re.search(r'(?:^|/)(projects/\d+/\d+/assets/[^"]+)$', filepath)
            if rel_match:
                candidate = os.path.abspath(os.path.join("data", rel_match.group(1)))
                if os.path.exists(candidate):
                    filepath = candidate
        if os.path.exists(filepath):
            ext = filepath.split('.')[-1]
            try:
                b64 = get_image_base64(filepath)
                return f'src="data:image/{ext};base64,{b64}"'
            except Exception:
                pass
        return match.group(0)
        
    return pattern.sub(replacer, html_content)

def process_base64_images(html_content, client_id, project_id):
    if not html_content:
        return html_content
    
    pattern = re.compile(r'src="data:image/([^;]+);base64,([^"]+)"')
    
    def replacer(match):
        ext = match.group(1)
        b64_data = match.group(2)
        
        asset_dir = f"data/projects/{client_id}/{project_id}/assets"
        os.makedirs(asset_dir, exist_ok=True)
        
        # Use MD5 hash of the data so we don't duplicate files on every save
        filename = f"{hashlib.md5(b64_data.encode()).hexdigest()}.{ext}"
        filepath = os.path.join(asset_dir, filename)
        
        try:
            with open(filepath, "wb") as fh:
                fh.write(base64.b64decode(b64_data))
            abs_path = os.path.abspath(filepath)
            return f'src="file://{abs_path}"'
        except Exception as e:
            return match.group(0)
            
    return pattern.sub(replacer, html_content)


def _rewrite_asset_file_urls(
    html_content: str,
    new_client_id: int | None = None,
    new_project_id: int | None = None,
) -> str:
    """Update absolute file:// asset URLs in HTML so restored/merged backups resolve on the current host."""
    if not html_content or "file://" not in html_content:
        return html_content

    pattern = re.compile(r'src="file://([^"]*?(?:^|/)projects/(\d+)/(\d+)/assets/([^"]+))"')

    def replacer(match: re.Match) -> str:
        orig_c_id = match.group(2)
        orig_p_id = match.group(3)
        filename = match.group(4)
        c_id = new_client_id if new_client_id is not None else orig_c_id
        p_id = new_project_id if new_project_id is not None else orig_p_id
        new_abs = os.path.abspath(os.path.join("data", "projects", str(c_id), str(p_id), "assets", filename))
        return f'src="file://{new_abs}"'

    return pattern.sub(replacer, html_content)


def _merge_backup_into_active_db(staging_dir: str, staged_db: str, target_db: str) -> dict[str, int]:
    """Merge clients, projects, findings, testers, and vuln library from staged_db into target_db."""
    import sqlite3

    stats = {"clients_added": 0, "projects_added": 0, "findings_added": 0, "vulns_added": 0}
    staged_projects_root = os.path.join(staging_dir, "projects")

    src_conn = sqlite3.connect(staged_db)
    src_conn.row_factory = sqlite3.Row
    dst_conn = sqlite3.connect(target_db)
    dst_conn.row_factory = sqlite3.Row

    try:
        # 1. Merge Clients
        client_id_map: dict[int, int] = {}
        src_clients = [
            dict(r)
            for r in src_conn.execute("SELECT * FROM clients").fetchall()
            if not dict(r).get("deleted_at")
        ]
        for sc in src_clients:
            old_cid = sc["id"]
            cname = (sc.get("name") or "").strip()
            cdesc = sc.get("description") or ""
            existing = dst_conn.execute(
                "SELECT id, description FROM clients WHERE LOWER(TRIM(name)) = LOWER(TRIM(?)) AND deleted_at IS NULL",
                (cname,),
            ).fetchone()
            if existing:
                client_id_map[old_cid] = existing["id"]
                if not existing["description"] and cdesc:
                    dst_conn.execute("UPDATE clients SET description = ? WHERE id = ?", (cdesc, existing["id"]))
            else:
                cur = dst_conn.execute(
                    "INSERT INTO clients (name, description) VALUES (?, ?)",
                    (cname, cdesc),
                )
                client_id_map[old_cid] = cur.lastrowid
                stats["clients_added"] += 1

        # 2. Merge Projects and their Findings + Assets
        project_cols = [
            "name", "application_name", "client_id", "project_type",
            "start_date", "end_date", "report_date", "tester_name",
            "tester_description", "hosts", "summary_of_strengths",
            "summary_of_weaknesses", "cvss_mapping", "tools_used",
            "is_whitelabel", "whitelabel_firm_name", "whitelabel_firm_website",
            "appendices", "attack_narrative", "attestation_bio",
            "use_custom_attestation", "custom_attestation",
        ]

        src_projects = [
            dict(r)
            for r in src_conn.execute("SELECT * FROM projects").fetchall()
            if not dict(r).get("deleted_at")
        ]

        for sp in src_projects:
            old_pid = sp["id"]
            old_cid = sp.get("client_id")
            if old_cid not in client_id_map:
                continue
            new_cid = client_id_map[old_cid]
            pname = (sp.get("name") or "").strip()

            existing_proj = dst_conn.execute(
                "SELECT id FROM projects WHERE client_id = ? AND LOWER(TRIM(name)) = LOWER(TRIM(?)) AND deleted_at IS NULL",
                (new_cid, pname),
            ).fetchone()

            if existing_proj:
                new_pid = existing_proj["id"]
            else:
                sp_copy = dict(sp)
                sp_copy["client_id"] = new_cid
                # Temporary insert so we obtain new_pid for asset path rewriting
                placeholders = ", ".join(["?"] * len(project_cols))
                col_names = ", ".join(project_cols)
                values = [sp_copy.get(c) for c in project_cols]
                cur = dst_conn.execute(
                    f"INSERT INTO projects ({col_names}) VALUES ({placeholders})",
                    values,
                )
                new_pid = cur.lastrowid
                stats["projects_added"] += 1

            # Copy project assets from staging_dir/projects/<old_cid>/<old_pid>/assets
            # to data/projects/<new_cid>/<new_pid>/assets
            src_asset_dir = os.path.join(staged_projects_root, str(old_cid), str(old_pid), "assets")
            if os.path.exists(src_asset_dir):
                dst_asset_dir = os.path.join("data", "projects", str(new_cid), str(new_pid), "assets")
                os.makedirs(dst_asset_dir, exist_ok=True)
                for fname in os.listdir(src_asset_dir):
                    s_file = os.path.join(src_asset_dir, fname)
                    d_file = os.path.join(dst_asset_dir, fname)
                    if os.path.isfile(s_file) and not os.path.exists(d_file):
                        shutil.copy2(s_file, d_file)

            # Rewrite attack_narrative asset URLs for new_cid / new_pid
            if not existing_proj and sp.get("attack_narrative"):
                rewritten_narrative = _rewrite_asset_file_urls(
                    sp["attack_narrative"], new_client_id=new_cid, new_project_id=new_pid
                )
                dst_conn.execute(
                    "UPDATE projects SET attack_narrative = ? WHERE id = ?",
                    (rewritten_narrative, new_pid),
                )

            # Merge Findings for this project
            src_findings = [
                dict(r)
                for r in src_conn.execute(
                    "SELECT * FROM project_findings WHERE project_id = ?", (old_pid,)
                ).fetchall()
                if not dict(r).get("deleted_at")
            ]
            for sf in src_findings:
                ftitle = sf.get("title") or ""
                fsev = sf.get("severity") or "Info"
                fhost = sf.get("host") or ""
                fpath = sf.get("path") or ""

                dup_finding = dst_conn.execute(
                    """
                    SELECT id FROM project_findings
                    WHERE project_id = ? AND title = ? AND severity = ?
                      AND COALESCE(host, '') = ? AND COALESCE(path, '') = ?
                      AND deleted_at IS NULL
                    """,
                    (new_pid, ftitle, fsev, fhost, fpath),
                ).fetchone()

                if not dup_finding:
                    rewritten_steps = _rewrite_asset_file_urls(
                        sf.get("steps_to_reproduce") or "",
                        new_client_id=new_cid,
                        new_project_id=new_pid,
                    )
                    dst_conn.execute(
                        """
                        INSERT INTO project_findings (
                            project_id, title, severity, description, remediation,
                            cvss, host, path, cvss_vector, refs, steps_to_reproduce
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            new_pid,
                            ftitle,
                            fsev,
                            sf.get("description") or "",
                            sf.get("remediation") or "",
                            sf.get("cvss") or 0.0,
                            fhost,
                            fpath,
                            sf.get("cvss_vector") or "",
                            sf.get("refs") or "",
                            rewritten_steps,
                        ),
                    )
                    stats["findings_added"] += 1

        # 3. Merge Testers
        try:
            src_testers = [dict(r) for r in src_conn.execute("SELECT * FROM testers").fetchall()]
            for st_row in src_testers:
                tname = (st_row.get("name") or "").strip()
                if not tname:
                    continue
                exists = dst_conn.execute(
                    "SELECT id FROM testers WHERE LOWER(TRIM(name)) = LOWER(TRIM(?))", (tname,)
                ).fetchone()
                if not exists:
                    dst_conn.execute(
                        "INSERT INTO testers (name, title, bio) VALUES (?, ?, ?)",
                        (tname, st_row.get("title") or "", st_row.get("bio") or ""),
                    )
        except Exception:
            pass

        # 4. Merge Vulnerability Library
        try:
            src_vulns = [dict(r) for r in src_conn.execute("SELECT * FROM vuln_library").fetchall()]
            for sv in src_vulns:
                vtitle = (sv.get("title") or "").strip()
                vsvc = sv.get("service_type") or "Web Application Penetration Test"
                if not vtitle:
                    continue
                exists = dst_conn.execute(
                    "SELECT id FROM vuln_library WHERE LOWER(TRIM(title)) = LOWER(TRIM(?)) AND COALESCE(service_type, '') = ?",
                    (vtitle, vsvc),
                ).fetchone()
                if not exists:
                    dst_conn.execute(
                        """
                        INSERT INTO vuln_library (
                            service_type, title, severity, description, remediation,
                            cvss, cve, cvss_vector, refs, steps_to_reproduce
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            vsvc,
                            vtitle,
                            sv.get("severity") or "Info",
                            sv.get("description") or "",
                            sv.get("remediation") or "",
                            sv.get("cvss") or 0.0,
                            sv.get("cve") or "",
                            sv.get("cvss_vector") or "",
                            sv.get("refs") or "",
                            sv.get("steps_to_reproduce") or "",
                        ),
                    )
                    stats["vulns_added"] += 1
        except Exception:
            pass

        dst_conn.commit()
    finally:
        src_conn.close()
        dst_conn.close()

    return stats


def restore_backup_archive(
    zip_source,
    preserve_current_users: bool = True,
    merge_existing: bool = True,
) -> dict[str, int]:
    """Validate and restore (or merge) a Kairos backup ZIP archive into data/."""
    import sqlite3
    import zipfile
    from database.db import DB_PATH, init_db

    if not zipfile.is_zipfile(zip_source):
        raise ValueError("The uploaded file is not a valid ZIP archive.")

    zip_source.seek(0)
    with tempfile.TemporaryDirectory() as staging_dir:
        with zipfile.ZipFile(zip_source, "r") as zf:
            names = zf.namelist()
            has_root_db = "kairos.db" in names
            has_nested_db = "data/kairos.db" in names
            if not has_root_db and not has_nested_db:
                raise ValueError("Invalid backup archive: 'kairos.db' was not found in the ZIP file.")

            strip_prefix = "data/" if (has_nested_db and not has_root_db) else ""
            real_staging = os.path.realpath(staging_dir)

            for member in zf.infolist():
                member_name = member.filename.replace("\\", "/")
                if strip_prefix and member_name.startswith(strip_prefix):
                    rel_name = member_name[len(strip_prefix):]
                else:
                    rel_name = member_name

                rel_name = rel_name.lstrip("/")
                if not rel_name:
                    continue

                dest_path = os.path.realpath(os.path.join(real_staging, rel_name))
                if not (dest_path == real_staging or dest_path.startswith(real_staging + os.sep)):
                    raise ValueError(f"Unsafe path detected in backup archive: {member.filename}")

                if member.is_dir() or member_name.endswith("/"):
                    os.makedirs(dest_path, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    with zf.open(member, "r") as src_f, open(dest_path, "wb") as dst_f:
                        shutil.copyfileobj(src_f, dst_f)

        staged_db = os.path.join(staging_dir, "kairos.db")
        if not os.path.exists(staged_db):
            raise ValueError("Invalid backup archive: 'kairos.db' could not be extracted.")

        with open(staged_db, "rb") as db_f:
            header = db_f.read(16)
        if header != b"SQLite format 3\x00":
            raise ValueError("Invalid backup archive: 'kairos.db' is not a valid SQLite database.")

        # Verify SQLite integrity before modifying active data
        test_conn = sqlite3.connect(staged_db)
        try:
            integrity = test_conn.execute("PRAGMA integrity_check").fetchone()
            if not integrity or integrity[0].lower() != "ok":
                raise ValueError("The backup database failed SQLite integrity verification.")
        finally:
            test_conn.close()

        os.makedirs("data", exist_ok=True)

        # Merge Mode: keep all existing clients/projects/findings and add new ones from the backup
        if merge_existing and os.path.exists(DB_PATH):
            init_db()
            return _merge_backup_into_active_db(staging_dir, staged_db, DB_PATH)

        # Full Replace Mode: overwrite database & assets
        existing_users = []
        existing_api_key = None
        if preserve_current_users and os.path.exists(DB_PATH):
            try:
                cur_conn = sqlite3.connect(DB_PATH)
                cur_conn.row_factory = sqlite3.Row
                existing_users = [dict(r) for r in cur_conn.execute("SELECT * FROM users").fetchall()]
                row = cur_conn.execute("SELECT value FROM settings WHERE key = 'gemini_api_key'").fetchone()
                if row and row["value"]:
                    existing_api_key = row["value"]
                cur_conn.close()
            except Exception:
                pass

        shutil.copy2(staged_db, DB_PATH)

        staged_projects_dir = os.path.join(staging_dir, "projects")
        target_projects_dir = os.path.join("data", "projects")
        if os.path.exists(staged_projects_dir):
            if os.path.exists(target_projects_dir):
                shutil.rmtree(target_projects_dir)
            shutil.copytree(staged_projects_dir, target_projects_dir)

    init_db()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        if preserve_current_users and existing_users:
            for u in existing_users:
                conn.execute(
                    """
                    INSERT INTO users (username, password_hash, mfa_secret, mfa_enabled)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(username) DO UPDATE SET
                        password_hash = excluded.password_hash,
                        mfa_secret = excluded.mfa_secret,
                        mfa_enabled = excluded.mfa_enabled
                    """,
                    (
                        u.get("username"),
                        u.get("password_hash"),
                        u.get("mfa_secret"),
                        u.get("mfa_enabled", 0),
                    ),
                )

        if existing_api_key:
            row = conn.execute("SELECT value FROM settings WHERE key = 'gemini_api_key'").fetchone()
            if not row or not row["value"]:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES ('gemini_api_key', ?)",
                    (existing_api_key,),
                )

        for f_row in conn.execute("SELECT id, steps_to_reproduce FROM project_findings WHERE steps_to_reproduce LIKE '%file://%'").fetchall():
            updated_steps = _rewrite_asset_file_urls(f_row["steps_to_reproduce"])
            if updated_steps != f_row["steps_to_reproduce"]:
                conn.execute(
                    "UPDATE project_findings SET steps_to_reproduce = ? WHERE id = ?",
                    (updated_steps, f_row["id"]),
                )

        for p_row in conn.execute("SELECT id, attack_narrative FROM projects WHERE attack_narrative LIKE '%file://%'").fetchall():
            updated_narrative = _rewrite_asset_file_urls(p_row["attack_narrative"])
            if updated_narrative != p_row["attack_narrative"]:
                conn.execute(
                    "UPDATE projects SET attack_narrative = ? WHERE id = ?",
                    (updated_narrative, p_row["id"]),
                )

        conn.commit()
    finally:
        conn.close()

    return {"clients_added": -1, "projects_added": -1, "findings_added": -1, "vulns_added": -1}
