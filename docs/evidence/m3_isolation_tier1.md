# VulnTrace Isolation Tier 1 Evidence & Acceptance Report (Milestone M3)

**Milestone:** M3 — Isolation Tier 1: Rootless Container Isolation & Adversarial Containment Proofs  
**Specification Reference:** `VULNTRACE_STUDIO_SPEC.md` §4.6, §4.14, and Milestone M3 Acceptance Criteria  
**Audit Date:** 2026-10-06  
**Container & Conformance Test Suite:** **38 / 38 PASSED** (55.73s)  
**Host & Non-Container Test Suite:** **128 / 128 PASSED** (265.28s)  
**Total Verified Tests:** **166 / 166 PASSED** (0 failures, 0 errors)  
**Linter Status:** `ruff check vulntrace/ tests/` — **All checks passed! (0 errors)**  

---

## 1. Executive Summary

Milestone M3 establishes **Isolation Tier 1 (Rootless Container Execution)** as the default runtime environment for all real-world and non-curated repositories evaluated by VulnTrace Studio.

Prior to M3, verification and harness detonation defaulted to Tier 0 (`LocalSubprocessBackend`). While Tier 0 provided disposable workspace copies, secret purging, Win32 Job Object cleanup, and memory limits, it executed under ambient host operating system user identity and shared host networking and filesystem DACLs.

Under M3:
1. **Rootless OCI Execution by Default (Spec §4.6):** All real-world and non-curated repositories execute inside an OCI container (`vulntrace-sandbox-base:latest`) powered by rootless Podman 5.7.0 and crun.
2. **Strict Kernel & Namespace Boundaries:**
   - **Kernel Network Denial (`--network none`):** No veth interfaces attached; raw network sockets return `Network is unreachable` at the kernel level.
   - **Read-Only Root Filesystem (`--read-only`):** Modification of container binaries, `/etc`, `/usr`, or system libraries returns `[Errno 30] Read-only file system`.
   - **Ephemeral tmpfs Scratch (`--tmpfs /tmp:rw,nosuid,nodev,size=64m`):** Temporary files and build artifacts execute in isolated in-memory storage destroyed on container exit.
   - **Unprivileged Non-Root Identity (`--user 1000:1000`):** Runs as non-root user with dropped capabilities (`--cap-drop ALL`, `--security-opt no-new-privileges`).
   - **cgroup Limits:** Enforces `--memory 512m`, `--cpus 1.0`, and `--pids-limit 128` against denial-of-service attempts.
   - **Timeout Watchdog:** Podman native `--timeout <sec>` enforced by crun with parent-side fallback cleanup.
   - **Zero Host Volume Mounts:** Only the disposable copy of the workspace is mounted (`-v <workspace>:/workspace:rw`).
3. **Tier 0 Explicitly Degraded & Refuses Untrusted Input:**
   - `LocalSubprocessBackend` strictly refuses non-curated repository inputs with `PermissionError` unless explicitly overridden via `unsafe_local=True` or `--unsafe-local`.
   - Attestation runtime engine explicitly identifies as `(DEGRADED_TIER_0)`.
4. **Adversarial Containment Proof Suite:** 14 tests in `tests/test_tier1_isolation.py` prove all 8 containment conditions and verifier 3/3 RED / 3/3 GREEN execution under Tier 1.
5. **Real Execution Failures Caught & Fixed:** Caught and resolved 4 critical runtime integration bugs (WSL2 container leak on timeout, WSL drvfs pytest cache write crash, WSL drvfs copystat build crash, and timeout vs OOM exit code collision).

---

## 2. Component Inspection & Architecture (`EXISTS / EXTEND / NEW`)

| Component | Status | Location | Description & Enhancements |
| :--- | :--- | :--- | :--- |
| `ContainerExecutionBackend` | **EXTEND** | `vulntrace/core/container_backend.py` | Enforced full Tier 1 flags (`--network none`, `--read-only`, `--tmpfs`, `--user 1000:1000`, `--cap-drop ALL`, `--memory 512m`, `--pids-limit 128`, `--timeout`). Added native tmpfs build redirection and `-p no:cacheprovider`. |
| `LocalSubprocessBackend` | **EXTEND** | `vulntrace/core/local_backend.py` | Added `unsafe_local` guard refusing non-curated repositories with `PermissionError`. Branded attestation as `(DEGRADED_TIER_0)`. |
| `BackendFactory` | **EXTEND** | `vulntrace/core/factory.py` | Added repository inspection (`target_repo`), defaulting non-curated repos to Tier 1 and refusing Tier 0 without `unsafe_local=True`. |
| `BackendCapabilities` | **EXTEND** | `vulntrace/core/backend.py` | Added `read_only_rootfs`, `tmpfs_scratch`, `non_root_user` boolean capability flags. Added `is_curated_fixture()` helper. |
| `VerificationPipeline` | **EXTEND** | `vulntrace/sandbox/pipeline.py` | Added `unsafe_local` parameter routing to backend factory resolution. |
| `VerificationPipelineRequest` | **EXTEND** | `vulntrace/models.py` | Added `unsafe_local: bool = False` schema field. |
| `test_tier1_isolation.py` | **NEW** | `tests/test_tier1_isolation.py` | 14 adversarial unit & integration tests covering all 8 containment conditions, Tier 0 refusal, and Verifier 3/3 execution under Tier 1. |
| `docs/SAFETY.md` | **NEW** | `docs/SAFETY.md` | Canonical safety documentation defining isolation boundaries, probe payload policies, and threat models. |
| `docs/evidence/m3_isolation_tier1.md` | **NEW** | `docs/evidence/m3_isolation_tier1.md` | This formal milestone evidence report. |

---

## 3. Real Execution Failures Caught and Fixed

During implementation and live execution against the rootless Podman/WSL2 substrate, four real execution failures were caught and resolved:

### 1. WSL2 Orphaned Container Leak on Subprocess Timeout
- **Symptom:** When a harness timed out, calling `proc.kill()` on the host Windows `wsl.exe` process terminated the Windows pipe, but the background Podman container in WSL2 continued executing indefinitely as an orphan.
- **Root Cause:** WSL2 process bridging does not propagate Windows `SIGKILL` signals to Linux child process trees inside container namespaces.
- **Resolution:** 
  1. Passed Podman native `--timeout <sec>` directly to `podman run`, allowing crun to enforce termination internally.
  2. Assigned deterministic unique container names (`vulntrace-exec-<uuid>`).
  3. Added an explicit `_kill_container(container_name)` fallback running `podman rm -f <container_name>` if timeout occurs.

### 2. WSL Drvfs Cache Permission Collision in Pytest
- **Symptom:** Running `pytest` inside the container as unprivileged user `1000:1000` failed with:
  `[Errno 1] Operation not permitted: '/workspace/.pytest_cache/v/cache/stepwise'`
- **Root Cause:** WSL2 drvfs file system mounts (mapping `C:\` into Linux) do not permit unprivileged Linux UID 1000 to alter metadata or set ownership on `.pytest_cache` folders created by root or Windows.
- **Resolution:** Added `-p no:cacheprovider` to container pytest command lines in `run_regression_suite`, suppressing `.pytest_cache` writes in workspace directories.

### 3. WSL Drvfs `copystat` Crash During `setup.py build`
- **Symptom:** In-container `setup.py build` crashed with `shutil.Error: [Errno 1] Operation not permitted` during `copystat` on `/workspace/build`.
- **Root Cause:** `setuptools` build step attempts `chmod` / `copystat` on compiled build artifacts when writing to `/workspace/build`. Under drvfs mounts, user 1000:1000 cannot change permissions on Windows-backed files.
- **Resolution:** Redirected setuptools build targets to the ephemeral Linux tmpfs scratch directory:
  `python3 setup.py build --build-base /tmp/build --build-lib /tmp/build/lib`

### 4. Timeout vs. OOM Kill Exit Code Collision
- **Symptom:** Both memory exhaustion and timeout watchdog executions mapped to exit code -9 / `TIMED_OUT`.
- **Root Cause:** Podman wrapper initially conflated exit code 137 (standard Linux `SIGKILL` / cgroups OOM kill) with timeout termination.
- **Resolution:** Podman native crun timeout watchdog exits with code `255`. Isolated exit code 255 for timeout handling, preserving exit code `137` for cgroups OOM kill.

---

## 4. Empirical Verification of Acceptance Criteria

All acceptance criteria are proven by automated tests executing against real container and host processes.

```powershell
.\.venv\Scripts\pytest -v tests/test_tier1_isolation.py
```

### Real Command Output:
```
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-9.1.1, pluggy-1.6.0 -- C:\AI-Tools\vulntrace\.venv\Scripts\python.exe
cachedir: .pytest_cache
rootdir: C:\AI-Tools\vulntrace
configfile: pyproject.toml
plugins: anyio-4.15.1, asyncio-1.4.0
asyncio: mode=Mode.STRICT, debug=False
collected 14 items

tests/test_tier1_isolation.py::TestAdversarialTier1Isolation::test_adversarial_outbound_network_denied PASSED [  7%]
tests/test_tier1_isolation.py::TestAdversarialTier1Isolation::test_adversarial_host_filesystem_and_readonly_root_fs PASSED [ 14%]
tests/test_tier1_isolation.py::TestAdversarialTier1Isolation::test_adversarial_fork_process_explosion_contained PASSED [ 21%]
tests/test_tier1_isolation.py::TestAdversarialTier1Isolation::test_adversarial_memory_exhaustion_contained PASSED [ 28%]
tests/test_tier1_isolation.py::TestAdversarialTier1Isolation::test_adversarial_timeout_watchdog_kills_descendants PASSED [ 35%]
tests/test_tier1_isolation.py::TestAdversarialTier1Isolation::test_adversarial_host_credentials_unavailable PASSED [ 42%]
tests/test_tier1_isolation.py::TestAdversarialTier1Isolation::test_adversarial_child_telemetry_cannot_forge_isolation_claims PASSED [ 50%]
tests/test_tier1_isolation.py::TestAdversarialTier1Isolation::test_adversarial_workspace_isolation_and_ephemeral_tmpfs PASSED [ 57%]
tests/test_tier1_isolation.py::TestTier0RefusalAndBackendFactory::test_tier0_refuses_non_curated_repo_without_unsafe_local PASSED [ 64%]
tests/test_tier1_isolation.py::TestTier0RefusalAndBackendFactory::test_tier0_allows_curated_fixture PASSED [ 71%]
tests/test_tier1_isolation.py::TestTier0RefusalAndBackendFactory::test_tier0_allows_non_curated_with_explicit_unsafe_local PASSED [ 78%]
tests/test_tier1_isolation.py::TestTier0RefusalAndBackendFactory::test_backend_factory_resolves_tier1_for_non_curated_repo PASSED [ 85%]
tests/test_tier1_isolation.py::TestVerifierAntiGamingUnderTier1::test_anti_gaming_verifier_red_reproduction_3x PASSED [ 92%]
tests/test_tier1_isolation.py::TestVerifierAntiGamingUnderTier1::test_anti_gaming_verifier_green_remediation_3x PASSED [100%]

============================= 14 passed in 23.47s =============================
```

### Detailed Breakdown per Acceptance Criterion:

#### AC1: Outbound Network Request Fails
- **Test:** `test_adversarial_outbound_network_denied`
- **Result:** **PASSED**
- **Observable:** Raw socket `connect(("8.8.8.8", 53))` fails with `OSError: [Errno 101] Network is unreachable`. HTTP request to external domain fails immediately.

#### AC2: Host Filesystem Isolation & Read-Only Root Filesystem
- **Test:** `test_adversarial_host_filesystem_and_readonly_root_fs`
- **Result:** **PASSED**
- **Observable:** Attempting to write to `/usr/local/bin/malicious_binary` or `/etc/hacked` raises `OSError: [Errno 30] Read-only file system`. Attempting to access host drive paths (`/mnt/c` or `/host_root`) fails with file not found.

#### AC3: Process / Fork Bomb Explosion Containment
- **Test:** `test_adversarial_fork_process_explosion_contained`
- **Result:** **PASSED**
- **Observable:** Script attempting unbounded `os.fork()` is contained by `--pids-limit 128`. Once PID threshold is reached, child creation fails with `BlockingIOError: [Errno 11] Resource temporarily unavailable`. Host remains completely responsive.

#### AC4: Memory Exhaustion Containment
- **Test:** `test_adversarial_memory_exhaustion_contained`
- **Result:** **PASSED**
- **Observable:** Script allocating 1GB bytearray inside container bounded by `--memory 512m` is terminated by Linux cgroup OOM killer with exit code 137.

#### AC5: Timeout Watchdog Kills Descendants
- **Test:** `test_adversarial_timeout_watchdog_kills_descendants`
- **Result:** **PASSED**
- **Observable:** Harness launching infinite detached grandchild sleep process is terminated when the 2-second timeout expires (exit code 255). Podman crun destroys the container namespace, leaving zero orphaned processes.

#### AC6: Host Credentials Unavailable
- **Test:** `test_adversarial_host_credentials_unavailable`
- **Result:** **PASSED**
- **Observable:** Container executes under non-root UID 1000, GID 1000. Host environment variables (`NEBIUS_API_KEY`, `TAVILY_API_KEY`, `AWS_ACCESS_KEY_ID`, `SSH_AUTH_SOCK`) are completely absent from container environment.

#### AC7: Child Telemetry Cannot Forge Isolation Claims
- **Test:** `test_adversarial_child_telemetry_cannot_forge_isolation_claims`
- **Result:** **PASSED**
- **Observable:** Child harness emits spoofed JSON stdout claiming `GREEN_STATE_VERIFIED`, exit code 42, and falsified isolation tier. Parent trust boundary validates physical disk for sentinel absence, detects contradiction, and rejects verdict (`VERIFICATION_REJECTED`). Unforgeable attestation records real container ID, image digest, and kernel network denial.

#### AC8: Workspace Isolation & Ephemeral tmpfs Scratch
- **Test:** `test_adversarial_workspace_isolation_and_ephemeral_tmpfs`
- **Result:** **PASSED**
- **Observable:** Harness writes to `/tmp/scratch.txt`. `/tmp` is verified to be mounted as `tmpfs` with `nosuid,nodev` options. Scratch files vanish on container cleanup. Source repository on host is untouched.

#### AC9: Tier 0 Refusal of Non-Curated Repositories
- **Test:** `test_tier0_refuses_non_curated_repo_without_unsafe_local`
- **Result:** **PASSED**
- **Observable:** Calling `LocalSubprocessBackend.initialize_workspace()` on a non-curated repo without `unsafe_local=True` raises `PermissionError: Tier 0 (LocalSubprocess) refused non-curated repository...`.

#### AC10: BackendFactory Resolves Tier 1 for Real Repositories
- **Test:** `test_backend_factory_resolves_tier1_for_non_curated_repo`
- **Result:** **PASSED**
- **Observable:** `BackendFactory.resolve_best_available_backend(target_repo=non_curated_path)` returns `ContainerExecutionBackend` (Tier 1).

#### AC11: Verifier Anti-Gaming Suite Under Tier 1
- **Tests:** `test_anti_gaming_verifier_red_reproduction_3x`, `test_anti_gaming_verifier_green_remediation_3x`
- **Result:** **PASSED**
- **Observable:** Executes vulnerable sample repository under Tier 1 container backend. 3 of 3 consecutive runs reproduce RED state (exit 0, physical sentinel created on parent disk). Applying safe patch yields 3 of 3 consecutive GREEN states (exit 42, physical sentinel absent on parent disk, parent trust boundary audited).

---

## 5. Full Regression & Conformance Suite Records

### Container & Conformance Suite (38 tests)
```powershell
.\.venv\Scripts\pytest -v tests/test_tier1_isolation.py tests/test_container_backend.py tests/test_backend_conformance.py
```
**Result:** `38 passed in 55.73s`

### Non-Container Host Regression Suite (128 tests)
```powershell
.\.venv\Scripts\pytest -v -m "not container" tests/
```
**Result:** `128 passed, 35 deselected in 265.28s (0:04:25)`

### Linter Check
```powershell
.\.venv\Scripts\ruff check vulntrace/ tests/
```
**Result:** `All checks passed!`

---

## 6. Disclosures & Open Items for Milestone M4

1. **Docker vs. Podman on Windows WSL2:** Rootless container execution is powered by Podman 5.7.0 and crun inside WSL2 Ubuntu, exposing rootless OCI container semantics.
2. **CI Isolation Fallback:** GitHub Actions runner environments execute in unprivileged VMs where nested rootless OCI containers may not be configured. CI environments fall back to Tier 0 under explicit `CI=true` override.
3. **M4 Readiness:** Milestone M3 is fully complete. M4 (Tavily Intel and Nebius Token Factory LLM layer with cassettes and token ledger) is ready to begin.
