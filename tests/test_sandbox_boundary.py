"""
VulnTrace Sandbox Boundary & Isolation Verification Suite
Empirically tests and documents the operational boundaries of LOCAL_SUBPROCESS_FALLBACK:
- Injected host credential purging
- Filesystem isolation between source repository and disposable workspace
- Subprocess timeout watchdog and process-tree termination
"""

import os
import sys
import time
import json
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


def test_job_object_orphaned_detached_child_process_termination(temp_sandbox_env):
    """
    P0.5.2 Adversarial Test:
    A child process spawns an orphaned/detached grandchild process using
    DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP and exits/times out.
    The Win32 Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE must terminate
    the detached grandchild process as well.
    """
    if sys.platform != "win32":
        pytest.skip("Win32 Job Object test applicable on Windows only.")

    disposable_dir = SubprocessSandboxRunner.prepare_disposable_workspace(temp_sandbox_env)
    try:
        spawner = disposable_dir / "spawner.py"
        # Spawner script launches detached grandchild sleeping 60 seconds
        spawner.write_text(
            '''import sys, os, time, subprocess, pathlib
grandchild_code = "import time, os, pathlib; pathlib.Path('grandchild.pid').write_text(str(os.getpid())); time.sleep(60)"
# DETACHED_PROCESS (0x00000008) | CREATE_NEW_PROCESS_GROUP (0x00000200)
p = subprocess.Popen([sys.executable, "-c", grandchild_code], creationflags=0x00000008 | 0x00000200)
time.sleep(0.5)
# Hang to trigger watchdog timeout
while True:
    time.sleep(0.1)
''',
            encoding="utf-8"
        )

        res = SubprocessSandboxRunner.execute_script(
            disposable_dir=disposable_dir,
            script_name="spawner.py",
            timeout=1.5
        )

        assert res.reproduction_state == "TIMED_OUT"
        assert res.exit_code == -99

        # Read grandchild PID
        pid_file = disposable_dir / "grandchild.pid"
        if pid_file.exists():
            g_pid = int(pid_file.read_text().strip())
            # Give OS half a second to finalize termination
            time.sleep(0.5)
            # Verify grandchild was terminated by Job Object
            with pytest.raises(OSError):
                os.kill(g_pid, 0)
    finally:
        SubprocessSandboxRunner.cleanup_workspace(disposable_dir)


def test_adversarial_subprocess_network_attempt_denied(temp_sandbox_env):
    """
    P0.5.3 Adversarial Subprocess Network Test:
    Target process attempts to spawn a subshell/subprocess to reach an external HTTP endpoint.
    Environment proxy settings and network guards deny the connection.
    """
    disposable_dir = SubprocessSandboxRunner.prepare_disposable_workspace(temp_sandbox_env)
    try:
        net_script = disposable_dir / "net_leak.py"
        net_script.write_text(
            '''import subprocess, sys, json
# Attempt external HTTP request via child Python interpreter
cmd = [sys.executable, "-c", "import urllib.request; urllib.request.urlopen('http://1.1.1.1', timeout=1)"]
proc = subprocess.run(cmd, capture_output=True, text=True)
success = (proc.returncode == 0)
print(json.dumps({"subshell_network_success": success, "stderr": proc.stderr[:100]}))
''',
            encoding="utf-8"
        )

        res = SubprocessSandboxRunner.execute_script(
            disposable_dir=disposable_dir,
            script_name="net_leak.py"
        )

        assert res.exit_code == 0
        data = json.loads(res.stdout)
        # External connection must NOT succeed
        assert data["subshell_network_success"] is False
    finally:
        SubprocessSandboxRunner.cleanup_workspace(disposable_dir)


def test_filesystem_profile_redirection_and_traversal_boundaries(temp_sandbox_env):
    """
    P0.5.6 Filesystem Boundary & Profile Redirection:
    Verifies that environment variables (USERPROFILE, HOME, APPDATA, TEMP) point to the
    disposable directory, trapping standard profile writes inside the disposable workspace.
    Documents the Windows ambient user token boundary limitation for hardcoded paths.
    """
    disposable_dir = SubprocessSandboxRunner.prepare_disposable_workspace(temp_sandbox_env)
    try:
        fs_script = disposable_dir / "profile_audit.py"
        fs_script.write_text(
            '''import os, json
from pathlib import Path

# Verify that standard home / profile lookups point inside disposable workspace
user_home = Path(os.environ.get("USERPROFILE", ""))
disposable_ws = Path(os.environ.get("TEMP", ""))

# Attempt write to user profile
test_marker = user_home / "sandbox_user_profile.marker"
test_marker.write_text("trapped")

print(json.dumps({
    "userprofile": str(user_home),
    "is_inside_ws": str(user_home).startswith(str(disposable_ws)),
    "marker_created": test_marker.exists()
}))
''',
            encoding="utf-8"
        )

        res = SubprocessSandboxRunner.execute_script(
            disposable_dir=disposable_dir,
            script_name="profile_audit.py"
        )

        assert res.exit_code == 0
        data = json.loads(res.stdout)
        assert data["is_inside_ws"] is True
        assert data["marker_created"] is True
        # Marker was written inside disposable workspace, NOT host user home!
        assert (disposable_dir / "sandbox_user_profile.marker").exists()
    finally:
        SubprocessSandboxRunner.cleanup_workspace(disposable_dir)

