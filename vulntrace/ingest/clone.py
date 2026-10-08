"""
VulnTrace Ingest Guard — Secure Git Repository Clone (Spec §4.14)
Enforces:
1. HTTPS public repositories only (rejects ssh, file, local paths).
2. URL credential scrubbing (no embedded tokens or passwords).
3. Shallow clone (--depth 1).
4. Git hooks strictly disabled during clone (-c core.hooksPath=/dev/null).
5. Filesystem monitoring disabled (-c core.fsmonitor=false).
6. Submodule recursion blocked (--no-recurse-submodules).
"""

import os
import subprocess
import urllib.parse
from pathlib import Path
from vulntrace.ingest.upload import IngestSecurityError


class CloneSecurityError(IngestSecurityError):
    """Raised when a git clone request violates repository ingest security boundaries."""
    pass


class GitCloneGuard:
    """Security validator and execution harness for cloning remote repositories."""

    ALLOWED_SCHEMES = ("https",)

    @classmethod
    def validate_repo_url(cls, url: str) -> urllib.parse.ParseResult:
        """
        Validates that a repository URL is safe for ingestion.
        Rejects non-HTTPS schemes and embedded credentials.
        """
        parsed = urllib.parse.urlparse(url.strip())

        if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
            raise CloneSecurityError(
                f"Insecure or unsupported clone protocol '{parsed.scheme}'. Only HTTPS public repositories are permitted."
            )

        if parsed.username or parsed.password:
            raise CloneSecurityError(
                "Repository URL must not contain embedded user credentials or access tokens."
            )

        if parsed.scheme.lower() == "https" and not parsed.netloc:
            raise CloneSecurityError("Repository URL is missing valid host name.")

        return parsed

    @classmethod
    def clone_public_repo(
        cls,
        repo_url: str,
        destination_dir: Path,
        depth: int = 1,
        timeout_sec: float = 60.0
    ) -> Path:
        """
        Clones a public HTTPS repository into destination_dir with security flags enforced:
        - hooks disabled via core.hooksPath
        - fsmonitor disabled
        - no submodules
        - shallow depth
        """
        cls.validate_repo_url(repo_url)
        dest_dir = Path(destination_dir).resolve()

        if dest_dir.exists() and any(dest_dir.iterdir()):
            raise CloneSecurityError(
                f"Destination directory '{dest_dir}' already exists and is not empty."
            )

        dest_dir.mkdir(parents=True, exist_ok=True)

        # Null device for hooksPath based on platform
        null_hook_path = "NUL" if os.name == "nt" else "/dev/null"

        clone_cmd = [
            "git",
            "-c", f"core.hooksPath={null_hook_path}",
            "-c", "core.fsmonitor=false",
            "clone",
            "--depth", str(depth),
            "--no-recurse-submodules",
            repo_url,
            str(dest_dir)
        ]

        # Scrub environment: disable terminal prompts and ambient credentials
        scrubbed_env = {
            k: v for k, v in os.environ.items()
            if not any(secret in k.upper() for secret in ["TOKEN", "KEY", "SECRET", "AUTH", "PASS"])
        }
        scrubbed_env["GIT_TERMINAL_PROMPT"] = "0"
        scrubbed_env["GIT_ASKPASS"] = "echo"

        try:
            res = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                env=scrubbed_env,
                check=False
            )
        except subprocess.TimeoutExpired:
            raise CloneSecurityError(f"Git clone operation timed out after {timeout_sec} seconds.")
        except Exception as e:
            raise CloneSecurityError(f"Git clone invocation failed: {e}")

        if res.returncode != 0:
            err_msg = res.stderr.strip() or res.stdout.strip()
            raise CloneSecurityError(f"Git clone failed (exit {res.returncode}): {err_msg}")

        return dest_dir
