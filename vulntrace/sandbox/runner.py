"""
VulnTrace Subprocess Sandbox Runner
Executes verification harnesses and regression tests in isolated disposable environments
with strict timeouts, sanitized environment variables, and process-tree cleanup.
"""

import os
import sys
import json
import time
import shutil
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from vulntrace.models import SandboxExecutionResult

import ctypes
from ctypes import wintypes

# Blacklisted environment variable substrings to ensure zero credential leakage
SECRET_PATTERNS = [
    "KEY", "TOKEN", "SECRET", "AUTH", "PASSWORD", "CREDENTIAL", "NEBIUS", "TAVILY",
    "OPENAI", "ANTHROPIC", "GEMINI", "GITHUB", "GITLAB", "BITBUCKET", "AWS", "AZURE",
    "GCP", "GOOGLE", "SSH", "PROXY_PASS", "PROXY_USER", "PROXY_AUTH", "NPM", "PYPI",
    "DOCKER", "KUBE", "CERT", "PRIVATE", "SIGN", "CI_", "SESSION", "COOKIE", "BEARER"
]

EXPLICIT_BLACKLIST_VARS = {
    "SSH_AUTH_SOCK", "SSH_AGENT_PID", "GIT_ASKPASS", "SSH_ASKPASS",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS",
    "TWINE_USERNAME", "TWINE_PASSWORD", "PIP_CONFIG_FILE",
    "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "NETRC", "CURL_CA_BUNDLE"
}


class Win32JobObject:
    """
    Win32 Job Object wrapper for strict process containment on Windows (P0.5.2).
    - Enables JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (all child/grandchild processes die when handle is closed).
    - Prevents silent breakaway: descendants remain trapped inside the Job Object.
    - Sets memory limits (512 MB process, 1024 MB job).
    - Guarantees complete process-tree termination on timeout or unexpected exit.

    NOTE ON BOUNDARY LIMITATION:
    Job Objects solve process-tree and resource containment on Windows.
    They do NOT by themselves solve filesystem DACLs or network isolation.
    """
    def __init__(self, memory_limit_mb: int = 512, job_memory_limit_mb: int = 1024):
        self.handle = None
        self.k32 = None
        if sys.platform != "win32":
            return

        try:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self.k32 = k32
            self.handle = k32.CreateJobObjectW(None, None)
            if not self.handle:
                return

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_uint64),
                    ("WriteOperationCount", ctypes.c_uint64),
                    ("OtherOperationCount", ctypes.c_uint64),
                    ("ReadTransferCount", ctypes.c_uint64),
                    ("WriteTransferCount", ctypes.c_uint64),
                    ("OtherTransferCount", ctypes.c_uint64),
                ]

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x0400
            JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x0100
            JOB_OBJECT_LIMIT_JOB_MEMORY = 0x0200

            flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            if memory_limit_mb > 0:
                flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY
                info.ProcessMemoryLimit = memory_limit_mb * 1024 * 1024
            if job_memory_limit_mb > 0:
                flags |= JOB_OBJECT_LIMIT_JOB_MEMORY
                info.JobMemoryLimit = job_memory_limit_mb * 1024 * 1024

            info.BasicLimitInformation.LimitFlags = flags
            k32.SetInformationJobObject(
                self.handle,
                9,  # JobObjectExtendedLimitInformation
                ctypes.byref(info),
                ctypes.sizeof(info)
            )
        except Exception:
            self.handle = None

    def assign_process(self, proc: subprocess.Popen) -> bool:
        if not self.handle or not proc or not hasattr(proc, "_handle"):
            return False
        try:
            res = self.k32.AssignProcessToJobObject(self.handle, int(proc._handle))
            return bool(res)
        except Exception:
            return False

    def terminate(self, exit_code: int = 99):
        if self.handle:
            try:
                self.k32.TerminateJobObject(self.handle, exit_code)
            except Exception:
                pass

    def close(self):
        if self.handle:
            try:
                self.k32.CloseHandle(self.handle)
            except Exception:
                pass
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class SubprocessSandboxRunner:
    """
    Controlled Local Subprocess Runner with Win32 Job Object Containment & Sanitized Workspace.
    Explicitly labeled: LOCAL_SUBPROCESS_FALLBACK (operating while ConTree cloud sandboxes return 403).
    """
    ENGINE_LABEL = "LOCAL_SUBPROCESS_FALLBACK"

    ISOLATION_SPECIFICATION = {
        "sandbox_tier": "LOCAL_SUBPROCESS_FALLBACK",
        "process_containment": "Windows Job Object (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 512MB RAM cap)",
        "filesystem": "Isolated temporary directory copy in %TEMP%; profile env vars redirected",
        "secrets": "Purged environment variables (credentials, API keys, SSH, and cloud tokens stripped)",
        "watchdog": "Strict subprocess timeout, Job Object termination, and taskkill fallback",
        "boundary_limitations": (
            "Shares host OS kernel and ambient user token. Job Objects enforce process tree termination "
            "and RAM quotas, but do not provide hypervisor microVM or OS-level network namespace isolation."
        )
    }

    @classmethod
    def prepare_disposable_workspace(cls, source_repo: Path) -> Path:
        """
        Clones the target repository into a disposable temporary directory.
        Never modifies the source codebase directly.
        Defends against external symlinks and directory junctions.
        """
        source_repo = Path(source_repo).resolve()
        if not source_repo.exists() or not source_repo.is_dir():
            raise FileNotFoundError(f"Source repository does not exist: {source_repo}")

        disposable_dir = Path(tempfile.mkdtemp(prefix="vulntrace_sandbox_"))

        def ignore_patterns(path: str, names: List[str]) -> List[str]:
            ignored = []
            for name in names:
                full_p = Path(path) / name
                # Reject symlinks/junctions pointing outside source_repo
                if full_p.is_symlink():
                    try:
                        resolved = full_p.resolve()
                        if not str(resolved).startswith(str(source_repo)):
                            ignored.append(name)
                            continue
                    except Exception:
                        ignored.append(name)
                        continue
                if name in [".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build", ".pytest_cache"]:
                    ignored.append(name)
            return ignored

        shutil.copytree(source_repo, disposable_dir, dirs_exist_ok=True, ignore=ignore_patterns, symlinks=False)
        return disposable_dir

    @classmethod
    def sanitize_environment(cls, disposable_dir: Path) -> Dict[str, str]:
        """
        Constructs a sanitized environment dict, purging all host credentials and secrets.
        Redirects profile and cache directories into the disposable workspace (P0.5.6).
        Only passes essential OS and Python paths.
        """
        disposable_dir = Path(disposable_dir).resolve()
        appdata_dir = disposable_dir / ".appdata"
        appdata_dir.mkdir(parents=True, exist_ok=True)
        localappdata_dir = disposable_dir / ".localappdata"
        localappdata_dir.mkdir(parents=True, exist_ok=True)

        safe_env = {
            "PYTHONPATH": str(disposable_dir),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
            "WINDIR": os.environ.get("WINDIR", "C:\\Windows"),
            "PATH": os.environ.get("PATH", ""),
            "TEMP": str(disposable_dir),
            "TMP": str(disposable_dir),
            "USERPROFILE": str(disposable_dir),
            "HOME": str(disposable_dir),
            "APPDATA": str(appdata_dir),
            "LOCALAPPDATA": str(localappdata_dir),
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1"
        }

        # Strict network isolation hints during behavioral verification
        safe_env["PIP_NO_INDEX"] = "1"
        safe_env["PIP_OFFLINE"] = "1"
        safe_env["HTTP_PROXY"] = "http://0.0.0.0:0"
        safe_env["HTTPS_PROXY"] = "http://0.0.0.0:0"
        safe_env["ALL_PROXY"] = "http://0.0.0.0:0"
        safe_env["NO_PROXY"] = ""

        # Double-check: ensure no secret variable slipped into safe_env
        for k in list(safe_env.keys()):
            k_upper = k.upper()
            if k in EXPLICIT_BLACKLIST_VARS or any(pat in k_upper for pat in SECRET_PATTERNS):
                del safe_env[k]

        return safe_env

    @classmethod
    def _kill_process_tree(cls, proc: subprocess.Popen):
        """Cleanly terminates the child process and any child processes spawned by it."""
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    capture_output=True,
                    timeout=3.0
                )
            else:
                proc.kill()
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    @classmethod
    def _get_python_executable(cls) -> str:
        """Resolves hermetic Python environment executable dynamically."""
        if sys.executable:
            return sys.executable
        venv_py = Path(__file__).resolve().parent.parent.parent / ".venv" / ("Scripts" if sys.platform == "win32" else "bin") / ("python.exe" if sys.platform == "win32" else "python")
        if venv_py.exists():
            return str(venv_py)
        return "python"

    @classmethod
    def execute_script(
        cls,
        disposable_dir: Path,
        script_name: str,
        timeout: float = 10.0,
        sentinel_filename: Optional[str] = None,
        on_log: Optional[Callable[[str], None]] = None,
        python_executable: Optional[str] = None
    ) -> SandboxExecutionResult:
        """
        Executes a Python verification script inside the disposable sandbox.
        Measures execution time, monitors stdout/stderr, and checks for sentinel file touch.
        """
        t0 = time.perf_counter()
        disposable_dir = Path(disposable_dir).resolve()
        script_path = disposable_dir / script_name

        if not script_path.exists():
            dt = (time.perf_counter() - t0) * 1000.0
            return SandboxExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"Script not found: {script_name}",
                latency_ms=round(dt, 2),
                sentinel_created=False,
                reproduction_state="ERROR",
                sandbox_engine=cls.ENGINE_LABEL,
                disposable_dir=str(disposable_dir),
                error=f"Script not found: {script_name}"
            )

        # Clear existing sentinel before run
        sentinel_path = (disposable_dir / sentinel_filename) if sentinel_filename else None
        if sentinel_path and sentinel_path.exists():
            try:
                sentinel_path.unlink()
            except Exception:
                pass

        env = cls.sanitize_environment(disposable_dir)
        py_bin = python_executable or cls._get_python_executable()
        cmd = [py_bin, str(script_path)]

        if on_log:
            on_log(f"Spawning isolated sandbox process: {' '.join(cmd)}")

        proc = None
        stdout_text = ""
        stderr_text = ""
        exit_code = -1
        timed_out = False
        job = Win32JobObject()

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(disposable_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env
            )
            # P0.5.2: Bind target process tree to Win32 Job Object
            job.assign_process(proc)

            stdout_text, stderr_text = proc.communicate(timeout=timeout)
            exit_code = proc.returncode

        except subprocess.TimeoutExpired:
            timed_out = True
            job.terminate(99)
            if proc:
                cls._kill_process_tree(proc)
                stdout_text, stderr_text = proc.communicate()
            exit_code = -99
        except Exception as e:
            job.terminate(99)
            if proc:
                cls._kill_process_tree(proc)
            stderr_text = f"Execution exception: {type(e).__name__}: {str(e)}"
            exit_code = -1
        finally:
            job.close()

        dt = (time.perf_counter() - t0) * 1000.0

        # Parent-Side Observable Evidence Audit:
        # Check sentinel creation independently on the filesystem
        sentinel_on_disk = bool(sentinel_path and sentinel_path.exists())

        # Clean up sentinel after check to avoid state pollution
        if sentinel_on_disk:
            try:
                sentinel_path.unlink()
            except Exception:
                pass

        # Parse structured behavioral assertion and verification evidence from stdout
        structured_evidence: Optional[Dict[str, Any]] = None
        assertion_result: Optional[str] = None
        exception_type: Optional[str] = None

        for line in stdout_text.splitlines():
            line_s = line.strip()
            if line_s.startswith("{") and line_s.endswith("}"):
                try:
                    payload_json = json.loads(line_s)
                    if "assertion" in payload_json:
                        structured_evidence = payload_json
                        assertion_result = payload_json.get("assertion")
                        exception_type = payload_json.get("exception_type")
                        break
                except Exception:
                    pass

        sink_reached = bool(structured_evidence and structured_evidence.get("sink_reached"))
        assertion_evaluated = bool(structured_evidence and structured_evidence.get("assertion_evaluated"))
        risky_effect = bool(structured_evidence and structured_evidence.get("risky_effect_observed"))
        expected_sec = bool(structured_evidence and structured_evidence.get("expected_security_exception"))
        unexpected_exc = bool(structured_evidence and structured_evidence.get("unexpected_exception"))

        parent_validated = False
        validation_notes: Optional[str] = None

        if timed_out:
            repro_state = "TIMED_OUT"
            validation_notes = "Subprocess exceeded execution timeout watchdog."
        elif assertion_result == "GREEN_SECURITY_BLOCK_VERIFIED":
            # Parent independently checks for contradictions in child's GREEN claim
            pos_passed = structured_evidence.get("positive_control_passed", True) if structured_evidence else False
            if sentinel_on_disk:
                # Contradiction: Child claims blocked, but exploit created sentinel on disk!
                repro_state = "VERIFICATION_REJECTED"
                validation_notes = "PARENT AUDIT FAILED: Child claimed GREEN_SECURITY_BLOCK_VERIFIED, but sentinel marker was observed on disk."
            elif risky_effect or unexpected_exc or not pos_passed:
                repro_state = "VERIFICATION_REJECTED"
                validation_notes = "PARENT AUDIT FAILED: Child claimed GREEN block, but reported risky effect observed, unexpected exception, or positive control failure."
            elif not expected_sec:
                repro_state = "VERIFICATION_REJECTED"
                validation_notes = "PARENT AUDIT FAILED: Child claimed GREEN block, but expected_security_exception was False."
            elif exit_code != 42:
                repro_state = "VERIFICATION_REJECTED"
                validation_notes = f"PARENT AUDIT FAILED: Child claimed GREEN block, but exited with code {exit_code} (expected 42)."
            elif not sink_reached or not assertion_evaluated:
                repro_state = "VERIFICATION_REJECTED"
                validation_notes = "PARENT AUDIT FAILED: Vulnerable sink was not reached or assertion was not evaluated."
            else:
                # Genuine verified green block
                repro_state = "GREEN_STATE_BLOCKED"
                parent_validated = True
                validation_notes = "Parent verified: exit code 42, zero sentinel markers, typed security exception evaluated, positive control passed."

        elif assertion_result == "RED_PASSED":
            if not sentinel_on_disk:
                # Contradiction: Child claims RED_PASSED, but no sentinel on disk!
                repro_state = "VERIFICATION_REJECTED"
                validation_notes = "PARENT AUDIT FAILED: Child claimed RED_PASSED, but no sentinel marker was created on disk."
            elif exit_code != 0:
                repro_state = "VERIFICATION_REJECTED"
                validation_notes = f"PARENT AUDIT FAILED: Child claimed RED_PASSED, but process exited with code {exit_code}."
            else:
                repro_state = "RED_STATE_REPRODUCED"
                parent_validated = True
                validation_notes = "Parent verified: exit code 0, physical sentinel marker created on disk."

        elif exit_code == 10 or (assertion_result and "INCONCLUSIVE" in assertion_result):
            if sentinel_on_disk:
                repro_state = "VERIFICATION_REJECTED"
                validation_notes = "PARENT AUDIT FAILED: Inconclusive claimed, but sentinel marker was created on disk."
            else:
                repro_state = "INCONCLUSIVE"
                parent_validated = True
                validation_notes = "Parent verified: Inconclusive state (pre-validation guard or condition un-reproduced)."

        elif sentinel_on_disk and exit_code == 0:
            repro_state = "RED_STATE_REPRODUCED"
            parent_validated = True
            validation_notes = "Parent verified: sentinel marker created on disk with exit code 0."
        elif assertion_result == "POSITIVE_CONTROL_FAILED":
            repro_state = "UNEXPECTED_FAILURE"
            validation_notes = f"PARENT AUDIT: In-harness positive control failed; remediation broke valid application behavior ({structured_evidence.get('detail', '') if structured_evidence else ''})"
        elif exit_code != 0:
            # Unhandled crash, syntax error, exit 1, or spoofed exit 42 without valid structured assertion
            repro_state = "UNEXPECTED_FAILURE"
            validation_notes = f"Process exited abnormally (exit {exit_code}) without valid defensive assertion."
        else:
            repro_state = "INCONCLUSIVE"
            validation_notes = "Process exited 0 without triggering observable exploit effect or defensive block."

        return SandboxExecutionResult(
            exit_code=exit_code,
            stdout=stdout_text.strip(),
            stderr=stderr_text.strip(),
            latency_ms=round(dt, 2),
            sentinel_created=sentinel_on_disk,
            reproduction_state=repro_state,
            assertion_result=assertion_result,
            exception_type=exception_type,
            structured_evidence=structured_evidence,
            parent_validated=parent_validated,
            validation_notes=validation_notes,
            sandbox_engine=cls.ENGINE_LABEL,
            disposable_dir=str(disposable_dir),
            error=stderr_text.strip() if repro_state in ["ERROR", "TIMED_OUT", "UNEXPECTED_FAILURE"] else None
        )

    @classmethod
    def run_pytest(
        cls,
        disposable_dir: Path,
        test_file: Optional[str] = None,
        timeout: float = 15.0,
        python_executable: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes pytest suite inside disposable workspace for regression verification.
        """
        t0 = time.perf_counter()
        disposable_dir = Path(disposable_dir).resolve()
        env = cls.sanitize_environment(disposable_dir)

        py_bin = python_executable or cls._get_python_executable()
        cmd = [py_bin, "-m", "pytest"]
        if test_file:
            cmd.append(test_file)
        cmd.extend(["-v", "--no-header"])

        proc = None
        job = Win32JobObject()
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(disposable_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env
            )
            job.assign_process(proc)
            stdout_text, stderr_text = proc.communicate(timeout=timeout)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            job.terminate(99)
            if proc:
                cls._kill_process_tree(proc)
            dt = (time.perf_counter() - t0) * 1000.0
            return {
                "passed": False,
                "exit_code": -99,
                "stdout": "",
                "stderr": "Pytest execution timed out.",
                "latency_ms": round(dt, 2),
                "error": "TIMEOUT"
            }
        except Exception as e:
            job.terminate(99)
            if proc:
                cls._kill_process_tree(proc)
            dt = (time.perf_counter() - t0) * 1000.0
            return {
                "passed": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "latency_ms": round(dt, 2),
                "error": str(e)
            }

        dt = (time.perf_counter() - t0) * 1000.0
        passed = (exit_code == 0)

        # Parse test count from stdout if available
        test_count = 0
        for line in stdout_text.splitlines():
            if "passed in" in line or "passed," in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if "passed" in p and i > 0 and parts[i-1].isdigit():
                        test_count = int(parts[i-1])

        return {
            "passed": passed,
            "exit_code": exit_code,
            "stdout": stdout_text.strip(),
            "stderr": stderr_text.strip(),
            "test_count": test_count,
            "latency_ms": round(dt, 2),
            "error": None if passed else "REGRESSION_TESTS_FAILED"
        }

    @classmethod
    def cleanup_workspace(cls, disposable_dir: Path):
        """Deterministically removes the temporary sandbox directory."""
        try:
            if disposable_dir and Path(disposable_dir).exists():
                shutil.rmtree(disposable_dir, ignore_errors=True)
        except Exception:
            pass
