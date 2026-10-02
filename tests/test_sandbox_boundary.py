"""
VulnTrace Sandbox Boundary & Isolation Verification Suite
Empirically tests and documents the operational boundaries of LOCAL_SUBPROCESS_FALLBACK:
- Injected host credential purging
- Filesystem isolation between source repository and disposable workspace
- Subprocess timeout watchdog and process-tree termination
"""

import os
import sys
import shutil
import tempfile
import pytest
from pathlib import Path
from vulntrace.sandbox.runner import SubprocessSandboxRunner

@pytest.fixture
def temp_sandbox_env():
    src_dir = Path(tempfile.mkdtemp(prefix="vulntrace_src_boundary_"))
    try:
        # Create dummy file in source repo
        (src_dir / "app.py").write_text("print('hello')", encoding="utf-8")
        yield src_dir
    finally:
        shutil.rmtree(src_dir, ignore_errors=True)


def test_sandbox_environment_sanitization(temp_sandbox_env):
    """
    Verifies that host secrets and API keys are completely purged from child process environment.
    """
    # 1. Artificially inject high-risk environment variables in parent process
    os.environ["MOCK_NEBIUS_API_KEY"] = "super-secret-key-12345"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "super-secret-aws-key"
    os.environ["AUTH_BEARER_TOKEN"] = "bearer-secret-token"

    disposable_dir = SubprocessSandboxRunner.prepare_disposable_workspace(temp_sandbox_env)
    try:
        # Script checks its own environment and outputs any secrets found
        audit_script = disposable_dir / "audit_env.py"
        audit_script.write_text(
            '''import os
import json

leaked = []
for k in os.environ:
    if any(pat in k.upper() for pat in ["KEY", "TOKEN", "SECRET", "AUTH", "PASSWORD", "CREDENTIAL", "NEBIUS", "TAVILY"]):
        leaked.append(k)

print(json.dumps({"leaked_keys": leaked}))
''',
            encoding="utf-8"
        )

        res = SubprocessSandboxRunner.execute_script(
            disposable_dir=disposable_dir,
            script_name="audit_env.py"
        )

        assert res.exit_code == 0
        import json
        output_data = json.loads(res.stdout)
        # Absolutely zero secret keys leaked into sandbox!
        assert output_data["leaked_keys"] == []
    finally:
        SubprocessSandboxRunner.cleanup_workspace(disposable_dir)
        # Clean up test env vars
        os.environ.pop("MOCK_NEBIUS_API_KEY", None)
        os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
        os.environ.pop("AUTH_BEARER_TOKEN", None)


def test_sandbox_filesystem_isolation(temp_sandbox_env):
    """
    Verifies that writes or mutations occurring inside the disposable workspace
    do NOT mutate the original source repository.
    """
    disposable_dir = SubprocessSandboxRunner.prepare_disposable_workspace(temp_sandbox_env)
    try:
        # Write files inside disposable sandbox
        sandboxed_mutator = disposable_dir / "mutator.py"
        sandboxed_mutator.write_text(
            '''from pathlib import Path
Path("pwned_file.txt").write_text("attacker payload")
Path("app.py").write_text("OVERWRITTEN APP CODE")
''',
            encoding="utf-8"
        )

        res = SubprocessSandboxRunner.execute_script(
            disposable_dir=disposable_dir,
            script_name="mutator.py"
        )

        assert res.exit_code == 0

        # Verify disposable workspace was mutated
        assert (disposable_dir / "pwned_file.txt").exists()
        assert (disposable_dir / "app.py").read_text() == "OVERWRITTEN APP CODE"

        # Verify source repository remains completely pristine
        assert not (temp_sandbox_env / "pwned_file.txt").exists()
        assert (temp_sandbox_env / "app.py").read_text() == "print('hello')"

    finally:
        SubprocessSandboxRunner.cleanup_workspace(disposable_dir)
        assert not disposable_dir.exists()


def test_sandbox_timeout_watchdog(temp_sandbox_env):
    """
    Verifies that an infinite loop or hanging child process is forcibly killed
    by the watchdog timeout.
    """
    disposable_dir = SubprocessSandboxRunner.prepare_disposable_workspace(temp_sandbox_env)
    try:
        hang_script = disposable_dir / "hang.py"
        hang_script.write_text(
            '''import time
while True:
    time.sleep(0.1)
''',
            encoding="utf-8"
        )

        res = SubprocessSandboxRunner.execute_script(
            disposable_dir=disposable_dir,
            script_name="hang.py",
            timeout=1.5  # Short timeout for testing
        )

        assert res.reproduction_state == "TIMED_OUT"
        assert res.exit_code == -99
        assert res.latency_ms >= 1400  # Ran approximately 1.5s
    finally:
        SubprocessSandboxRunner.cleanup_workspace(disposable_dir)
