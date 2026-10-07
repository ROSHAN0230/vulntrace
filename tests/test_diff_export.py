"""
Acceptance Tests for VulnTrace Diff & Workspace Export (Spec §4.12, AC5).
Covers:
1. Unified diff LF normalization and formatting.
2. Clean `git apply --check` patch validation on repository.
3. Patch incompatibility detection via `git apply --check`.
4. Clean workspace zip export excluding git and build artifacts.
"""

import subprocess
import zipfile
from pathlib import Path

from vulntrace.export.diff_export import DiffExporter
from vulntrace.export.zip_export import ZipExporter


def test_format_git_diff_lf_normalization():
    """Proves diff text CRLF is normalized to git-compatible LF line endings."""
    crlf_diff = "--- a/file.py\r\n+++ b/file.py\r\n@@ -1 +1 @@\r\n-old\r\n+new\r\n"
    formatted = DiffExporter.format_git_diff(crlf_diff)
    assert "\r" not in formatted
    assert formatted.endswith("\n")
    assert formatted == "--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-old\n+new\n"


def test_git_apply_check_on_clean_repository(tmp_path: Path):
    """Proves exported unified diff succeeds under `git apply --check` on target repo."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    # Initialize git repo
    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo_dir), check=True, capture_output=True)

    target_file = repo_dir / "service.py"
    target_file.write_text("def run():\n    return 'insecure'\n", encoding="utf-8")

    subprocess.run(["git", "add", "service.py"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=str(repo_dir), check=True, capture_output=True)

    valid_diff = """--- a/service.py
+++ b/service.py
@@ -1,2 +1,2 @@
 def run():
-    return 'insecure'
+    return 'hardened'
"""
    diff_file = tmp_path / "patch.diff"
    DiffExporter.export_diff_file(valid_diff, diff_file)

    # Check git apply
    applies = DiffExporter.verify_git_apply_check(diff_file, repo_dir)
    assert applies is True


def test_git_apply_check_fails_on_incompatible_patch(tmp_path: Path):
    """Proves incompatible patch is rejected by `git apply --check`."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    subprocess.run(["git", "init"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo_dir), check=True, capture_output=True)

    target_file = repo_dir / "service.py"
    target_file.write_text("print('different content')\n", encoding="utf-8")

    subprocess.run(["git", "add", "service.py"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo_dir), check=True, capture_output=True)

    incompatible_diff = """--- a/service.py
+++ b/service.py
@@ -1,1 +1,1 @@
-def nonexistent_function():
+def hardened_function():
"""
    diff_file = tmp_path / "mismatch.diff"
    DiffExporter.export_diff_file(incompatible_diff, diff_file)

    applies = DiffExporter.verify_git_apply_check(diff_file, repo_dir)
    assert applies is False


def test_zip_export_excludes_ephemeral_artifacts(tmp_path: Path):
    """Proves workspace zip export excludes .git, __pycache__, and .venv artifacts."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    # Legitimate project files
    (workspace / "src").mkdir()
    (workspace / "src" / "app.py").write_text("app = 1\n", encoding="utf-8")
    (workspace / "README.md").write_text("# Doc\n", encoding="utf-8")

    # Ephemeral / internal files that must be excluded
    (workspace / ".git").mkdir()
    (workspace / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (workspace / "src" / "__pycache__").mkdir()
    (workspace / "src" / "__pycache__" / "app.cpython-311.pyc").write_bytes(b"\x00\x01\x02")
    (workspace / ".venv").mkdir()
    (workspace / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")

    output_zip = tmp_path / "export.zip"
    ZipExporter.export_workspace_zip(workspace, output_zip)

    assert output_zip.exists()
    with zipfile.ZipFile(output_zip, "r") as zf:
        names = zf.namelist()
        assert "src/app.py" in names
        assert "README.md" in names
        assert not any(".git" in n for n in names)
        assert not any("__pycache__" in n for n in names)
        assert not any(".venv" in n for n in names)
