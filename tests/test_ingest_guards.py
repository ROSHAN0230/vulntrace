"""
Acceptance Tests for VulnTrace Ingest Guards (Spec §4.14, AC1).
Covers:
1. Zip-slip and path traversal rejection.
2. Symlink escape rejection.
3. Decompression bomb detection (ratio, total uncompressed size, file count).
4. Safe extraction of legitimate archives.
5. Git clone guard protocol validation and security argument hardening.
"""

import io
import zipfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from vulntrace.ingest.upload import (
    ZipUploadGuard,
    IngestSecurityError,
    ZipSlipError,
    DecompressionBombError,
    SymlinkEscapeError,
)
from vulntrace.ingest.clone import GitCloneGuard, CloneSecurityError


def test_zip_slip_relative_path_rejected(tmp_path: Path):
    """Proves archives containing '..' path traversal components are rejected."""
    zip_file = tmp_path / "slip_attack.zip"
    extract_dir = tmp_path / "extracted"

    with zipfile.ZipFile(zip_file, "w") as zf:
        zf.writestr("../../escaped_file.py", "malicious_payload = True")

    with pytest.raises(ZipSlipError) as exc_info:
        ZipUploadGuard.validate_and_extract(zip_file, extract_dir)

    assert "Zip-slip detected" in str(exc_info.value)
    assert not (tmp_path / "escaped_file.py").exists()


def test_zip_slip_absolute_path_rejected(tmp_path: Path):
    """Proves archives containing root/absolute paths are rejected."""
    zip_file = tmp_path / "abs_attack.zip"
    extract_dir = tmp_path / "extracted"

    with zipfile.ZipFile(zip_file, "w") as zf:
        zf.writestr("/root_payload.sh", "#!/bin/sh\nexit 1")

    with pytest.raises(ZipSlipError) as exc_info:
        ZipUploadGuard.validate_and_extract(zip_file, extract_dir)

    assert "Absolute path member detected" in str(exc_info.value)


def test_zip_slip_drive_letter_rejected(tmp_path: Path):
    """Proves archives containing Windows drive letter paths are rejected."""
    zip_file = tmp_path / "drive_attack.zip"
    extract_dir = tmp_path / "extracted"

    with zipfile.ZipFile(zip_file, "w") as zf:
        zf.writestr("C:/evil.bat", "@echo off")

    with pytest.raises(ZipSlipError) as exc_info:
        ZipUploadGuard.validate_and_extract(zip_file, extract_dir)

    assert "Absolute drive path detected" in str(exc_info.value)


def test_decompression_bomb_ratio_rejected(tmp_path: Path):
    """Proves zip archives with excessive compression ratio (e.g. >100:1) are blocked."""
    zip_file = tmp_path / "bomb_ratio.zip"
    extract_dir = tmp_path / "extracted"

    # 1 MB of repetitive zeros compresses into a few hundred bytes (>1000:1 ratio)
    bomb_content = b"\x00" * (1024 * 1024)

    with zipfile.ZipFile(zip_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge_zeroes.dat", bomb_content)

    with pytest.raises(DecompressionBombError) as exc_info:
        ZipUploadGuard.validate_and_extract(zip_file, extract_dir, max_ratio=50.0)

    assert "Decompression bomb ratio" in str(exc_info.value) or "decompression ratio" in str(exc_info.value)


def test_decompression_bomb_total_size_rejected(tmp_path: Path):
    """Proves uncompressed size limits are strictly enforced."""
    zip_file = tmp_path / "bomb_size.zip"
    extract_dir = tmp_path / "extracted"

    data = b"A" * 10000

    with zipfile.ZipFile(zip_file, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("file1.dat", data)
        zf.writestr("file2.dat", data)

    # Limit to 15 KB uncompressed
    with pytest.raises(DecompressionBombError) as exc_info:
        ZipUploadGuard.validate_and_extract(zip_file, extract_dir, max_uncompressed_bytes=15000)

    assert "Total uncompressed size" in str(exc_info.value)


def test_max_file_count_rejected(tmp_path: Path):
    """Proves archives exceeding max allowable file count are rejected."""
    zip_file = tmp_path / "too_many_files.zip"
    extract_dir = tmp_path / "extracted"

    with zipfile.ZipFile(zip_file, "w") as zf:
        for i in range(15):
            zf.writestr(f"file_{i}.txt", f"content {i}")

    with pytest.raises(IngestSecurityError) as exc_info:
        ZipUploadGuard.validate_and_extract(zip_file, extract_dir, max_file_count=10)

    assert "Archive file count" in str(exc_info.value)


def test_symlink_escape_rejected(tmp_path: Path):
    """Proves symlinks pointing outside workspace root trigger SymlinkEscapeError."""
    zip_file = tmp_path / "symlink_escape.zip"
    extract_dir = tmp_path / "extracted"

    # Create a zip containing a UNIX symlink member
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        info = zipfile.ZipInfo("escape_link")
        # 0o120000 is S_IFLNK (symlink)
        info.external_attr = 0o120777 << 16
        # Target points outside the archive root
        zf.writestr(info, "../../etc/shadow")

    zip_file.write_bytes(zbuf.getvalue())

    with pytest.raises(SymlinkEscapeError) as exc_info:
        ZipUploadGuard.validate_and_extract(zip_file, extract_dir)

    assert "points outside destination" in str(exc_info.value)


def test_valid_zip_extracted_safely(tmp_path: Path):
    """Proves legitimate project zip is extracted safely and preserves structure."""
    zip_file = tmp_path / "valid_project.zip"
    extract_dir = tmp_path / "extracted"

    with zipfile.ZipFile(zip_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("src/main.py", "def app(): return 'OK'\n")
        zf.writestr("README.md", "# Project Documentation\n")

    extracted = ZipUploadGuard.validate_and_extract(zip_file, extract_dir)

    assert len(extracted) == 2
    assert (extract_dir / "src" / "main.py").read_text() == "def app(): return 'OK'\n"
    assert (extract_dir / "README.md").read_text() == "# Project Documentation\n"


def test_git_clone_guard_insecure_schemes_rejected():
    """Proves non-HTTPS protocols (ssh, file, git) are rejected by GitCloneGuard."""
    insecure_urls = [
        "file:///tmp/malicious_repo",
        "git://github.com/org/repo.git",
        "ssh://git@github.com:org/repo.git",
        "http://insecure.org/repo.git",
        "ftp://repo.org/code.git",
    ]
    for url in insecure_urls:
        with pytest.raises(CloneSecurityError) as exc_info:
            GitCloneGuard.validate_repo_url(url)
        assert "Only HTTPS" in str(exc_info.value)


def test_git_clone_guard_embedded_credentials_rejected():
    """Proves URLs with embedded credentials or access tokens are blocked."""
    leaky_urls = [
        "https://ghp_secrettoken@github.com/org/repo.git",
        "https://admin:password123@github.com/org/repo.git",
    ]
    for url in leaky_urls:
        with pytest.raises(CloneSecurityError) as exc_info:
            GitCloneGuard.validate_repo_url(url)
        assert "must not contain embedded user credentials" in str(exc_info.value)


def test_git_clone_guard_enforces_security_flags(tmp_path: Path):
    """Proves git clone arguments strictly disable hooks, fsmonitor, and submodules."""
    dest_dir = tmp_path / "cloned_repo"
    url = "https://github.com/example/repo.git"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        res = GitCloneGuard.clone_public_repo(url, dest_dir, depth=1)
        assert res == dest_dir.resolve()

        assert mock_run.called
        cmd = mock_run.call_args[0][0]
        env = mock_run.call_args[1]["env"]

        # Check command hardening arguments
        cmd_str = " ".join(cmd)
        assert "core.hooksPath=" in cmd_str
        assert "-c core.fsmonitor=false" in cmd_str
        assert "--no-recurse-submodules" in cmd_str
        assert "--depth 1" in cmd_str
        assert url in cmd

        # Check ambient credential scrubbing
        assert env["GIT_TERMINAL_PROMPT"] == "0"
        assert env["GIT_ASKPASS"] == "echo"
