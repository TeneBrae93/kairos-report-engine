"""
Test fixtures for path traversal verification.

The vulnerable pattern in views/manage_findings.py line 134:
    temp_path = f"data/temp_{uploaded_file.name}"

Because Python treats "temp_.." as a single path component (not "temp_" then ".."),
the traversal payload needs an extra hop:  "x/../../tmp/target.txt"  →
    data/temp_x/../../tmp/target.txt  →  escapes data/  →  tmp/target.txt

Provides:
  - Sandbox temp directory with data/, data/temp_h/, tmp/, and app structure
  - Mock UploadedFile class matching Streamlit's API (name, getbuffer)
  - Replica of the vulnerable logic + helper that creates needed intermediate dirs
"""

import io
import os
import shutil
import tempfile
import pytest


class MockUploadedFile:
    """Mirrors Streamlit's UploadedFile: .name (str) and .getbuffer() (memoryview)."""

    def __init__(self, name: str, content: bytes):
        self.name = name
        self._buffer = io.BytesIO(content)

    def getbuffer(self) -> memoryview:
        return self._buffer.getbuffer()


@pytest.fixture
def sandbox():
    """Isolated sandbox with data/, tmp/, and data/temp_h/ (hop dir for traversal)."""
    original_cwd = os.getcwd()
    sandbox_dir = tempfile.mkdtemp(prefix="vuln_test_")
    os.makedirs(os.path.join(sandbox_dir, "data", "temp_h"), exist_ok=True)
    os.makedirs(os.path.join(sandbox_dir, "tmp"), exist_ok=True)

    os.chdir(sandbox_dir)
    yield sandbox_dir

    os.chdir(original_cwd)
    shutil.rmtree(sandbox_dir, ignore_errors=True)


@pytest.fixture
def sandbox_with_app(sandbox):
    """Sandbox with full app directory tree for destructive overwrite tests."""
    for subdir in ["reporting", "templates", "views", "utils", "database"]:
        os.makedirs(os.path.join(sandbox, subdir), exist_ok=True)

    # Pre-create seed files for overwrite verification
    with open(os.path.join(sandbox, "reporting", "generator.py"), "w") as f:
        f.write("# Original generator.py\nprint('ORIGINAL')\n")
    with open(os.path.join(sandbox, "views", "login.py"), "w") as f:
        f.write("# Original login.py\ndef show_login(): pass\n")
    with open(os.path.join(sandbox, "app.py"), "w") as f:
        f.write("# Original app.py\nimport streamlit as st\n")
    with open(os.path.join(sandbox, "templates", "report_template.md"), "w") as f:
        f.write("# Original Template\n")

    return sandbox


@pytest.fixture
def rce_sandbox(sandbox):
    """Full app directory tree for RCE chain tests.
    Includes empty __init__.py files and a mock sys.modules for import simulation."""
    for subdir in ["reporting", "templates", "views", "utils", "database", "parsers"]:
        os.makedirs(os.path.join(sandbox, subdir), exist_ok=True)

    # Create empty __init__.py files (matching real project)
    for init_dir in ["reporting", "views", "utils", "database", "parsers"]:
        init_path = os.path.join(sandbox, init_dir, "__init__.py")
        with open(init_path, "w") as f:
            f.write("")

    # Create seed app files
    with open(os.path.join(sandbox, "app.py"), "w") as f:
        f.write("# Main entry point\nfrom utils import auth\n")
    with open(os.path.join(sandbox, "utils", "auth.py"), "w") as f:
        f.write("def verify_token(t): return True\n")
    with open(os.path.join(sandbox, "utils", "helpers.py"), "w") as f:
        f.write("def sanitize(x): return x\n")
    with open(os.path.join(sandbox, "reporting", "generator.py"), "w") as f:
        f.write("# Generator\n")
    with open(os.path.join(sandbox, "views", "login.py"), "w") as f:
        f.write("def show_login(): pass\n")
    with open(os.path.join(sandbox, "database", "operations.py"), "w") as f:
        f.write("def get_projects(): return []\n")
    with open(os.path.join(sandbox, "templates", "report_template.md"), "w") as f:
        f.write("# Template\n")

    return sandbox


def simulate_streamlit_reload(project_root=None):
    """Simulate Streamlit's LocalSourcesWatcher.on_file_changed() behavior:
    eject all watched modules from sys.modules so they get re-imported from
    disk on the next import statement (mimicking st.rerun()).

    In production, Streamlit does this automatically when a .py file changes.
    For testing, we manually replicate the module ejection.
    """
    import sys
    if project_root is None:
        project_root = os.getcwd()

    # Modules whose file paths are under the project root get ejected.
    # This mirrors Streamlit's logic: any .py file in the script folder or
    # its subdirectories that was imported is removed from sys.modules.
    to_eject = []
    for name, mod in list(sys.modules.items()):
        if mod is not None and hasattr(mod, "__file__") and mod.__file__ is not None:
            try:
                mod_path = os.path.realpath(mod.__file__)
                root_path = os.path.realpath(project_root)
                if mod_path.startswith(root_path + os.sep) or mod_path == root_path:
                    to_eject.append(name)
            except (TypeError, ValueError):
                pass

    ejected = []
    for name in to_eject:
        del sys.modules[name]
        ejected.append(name)

    return ejected


def execute_vulnerable_logic(uploaded_file, parser_func=None):
    """Replica of views/manage_findings.py lines 134-161 (VULNERABLE version).

    Uses the exact vulnerable path construction:
        temp_path = f"data/temp_{uploaded_file.name}"

    For traversal payloads like "h/../../tmp/evil.txt", this produces:
        data/temp_h/../../tmp/evil.txt → escapes data/ → tmp/evil.txt

    The intermediate hop directory (data/temp_h/) must be pre-created in the
    sandbox for open() to succeed. This mirrors real conditions where a benign
    upload or existing directory shares the prefix.
    """
    temp_path = f"data/temp_{uploaded_file.name}"

    # Create the target's parent directory so open() can succeed.
    # In production, common targets like /tmp already exist.
    resolved_parent = os.path.dirname(os.path.realpath(temp_path))
    os.makedirs(resolved_parent, exist_ok=True)

    with open(temp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    result = None
    error = None
    try:
        if parser_func:
            result = parser_func(temp_path)
    except Exception as e:
        error = e
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    return temp_path, result, error
