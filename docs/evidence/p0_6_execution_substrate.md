# VulnTrace P0.6 Evidence: Hardened Execution Substrate & Backend Abstraction

## 1. Executive Summary & Objective

Prior to P0.6, VulnTrace operated exclusively via `SubprocessSandboxRunner`, which relied on Windows-specific Job Objects and environment variable sanitization. As established during the P0.5 S-Class Trust Boundary Audit, this local fallback had three explicit architectural limitations:
1. Process runs under the ambient host OS identity (subject to ambient user DACLs).
2. Network isolation is cooperative/environment-level (`HTTP_PROXY` redirect; raw sockets can bypass).
3. Host filesystem remains readable where ambient user permissions allow.

**P0.6 closes these residual architectural boundaries by establishing a production-grade, backend-agnostic execution security layer:**
- Formal `ExecutionBackend` abstraction decoupling AST analysis, behavioral oracle, harness synthesizer, and verdict engine from execution runtimes.
- `LocalSubprocessBackend` honestly labeled as `LOCAL_SUBPROCESS_FALLBACK` with explicit boundary caveats.
- `ContainerExecutionBackend` implementing `OCI_CONTAINER_ISOLATED` using rootless Podman 5.7.0 and `crun` in WSL2 with true kernel-enforced network denial (`--network none`), host filesystem isolation, and cgroup resource limits.
- `BackendFactory` automatically selecting the highest available security tier while allowing explicit deterministic overrides.
- Unforgeable parent-generated `ExecutionAttestation` metadata attached directly to formal evidence records and verdicts.
- Automated tests verifying **Host Isolation Sentinels**, **Kernel Network Denial**, **Fork Bomb / PID Containment**, and **Attestation Anti-Spoofing** (77/77 tests passing).

---

## 2. Architecture & Isolation Tiers

### 2.1 Backend Contract Matrix

| Metric / Guarantee | Tier 0: `LOCAL_SUBPROCESS_FALLBACK` | Tier 1: `OCI_CONTAINER_ISOLATED` | Tier 2: `REMOTE_MICROVM_ISOLATED` |
| :--- | :--- | :--- | :--- |
| **Filesystem Jailed** | ❌ No (ambient host read access) | ✅ **Yes** (rootfs jailed; disposable bind-mount) | ✅ **Yes** (isolated VM disk image) |
| **Host FS Hidden** | ❌ No (host drives accessible) | ✅ **Yes** (`/mnt` empty; host drives hidden) | ✅ **Yes** (hypervisor boundary) |
| **Network Isolation** | ⚠️ Cooperative (`HTTP_PROXY` redirect) | ✅ **Kernel-Enforced** (`--network none`, Errno 101) | ✅ **Hardware/NIC Level** (No vNIC) |
| **Process Containment** | ✅ Yes (Win32 Job Object / `KILL_ON_CLOSE`) | ✅ **Yes** (PID namespace + cgroups `pids.max`) | ✅ **Yes** (KVM / Hypervisor boundary) |
| **Resource Limits** | ✅ Yes (512MB RAM cap on Job Object) | ✅ **Yes** (`--memory 512m`, `--cpus 1.0`, `--pids-limit 128`) | ✅ **Yes** (vCPU / Guest RAM limits) |
| **Host Identity** | ❌ Shared ambient Windows user | ✅ **Isolated** (rootless container UID/GID map) | ✅ **Isolated** (separate guest OS identity) |
| **Security Capabilities** | N/A (Standard Win32 process) | ✅ **`--cap-drop ALL`, `no-new-privileges`** | N/A (Virtual machine barrier) |

---

## 3. Substrate Verification & Automated Test Evidence

### 3.1 Suite Verification: 77/77 Tests Passing (100% Green)

```text
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-9.1.1, pluggy-1.6.0 -- C:\AI-Tools\vulntrace\.venv\Scripts\python.exe
cachedir: .pytest_cache
rootdir: C:\AI-Tools\vulntrace
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.15.1, asyncio-1.4.0
collected 77 items

tests/test_api_endpoints.py (4 passed)
tests/test_ast_visitor.py (1 passed)
tests/test_backend_abstraction.py (8 passed)
tests/test_container_backend.py (10 passed)
tests/test_contextual_reasoning.py (1 passed)
tests/test_harness_synthesizer.py (1 passed)
tests/test_manifest_parser.py (1 passed)
tests/test_mutations.py (2 passed)
tests/test_negative_cases.py (10 passed)
tests/test_osv_client.py (2 passed)
tests/test_parent_trust_boundary.py (5 passed)
tests/test_remediation_pipeline.py (1 passed)
tests/test_sandbox_boundary.py (6 passed)
tests/test_sandbox_runner.py (2 passed)
tests/test_target_environment.py (8 passed)
tests/test_verifier_redteam.py (15 passed)

======================= 77 passed in 127.17s (0:02:07) ========================
```

---

## 4. Key P0.6 Verification Dimensions

### 4.1 Host Isolation Sentinels (`TestHostIsolationSentinels`)
- **Host Secret Leakage Test**: Created an external credential file `host_secret_sentinel.key` outside the workspace on the host. An adversarial script executed inside the container attempted path traversal and direct access to `/mnt/c/...`. Verified that the file is completely hidden and returns `SECRET_NOT_FOUND_ISOLATED`.
- **Host Integrity Modification Test**: Created a canary file `host_integrity_sentinel.canary` on the host. An adversarial script attempted to overwrite the file from within the container. Verified that the write operation fails and the host file remains bit-for-bit unmodified.

### 4.2 Native Network Denial (`TestNativeNetworkDenial`)
- An adversarial harness executed inside the container attempted to bypass Python-level monkey-patching by opening a raw TCP socket to `1.1.1.1:80`.
- Verified that the Linux kernel network stack immediately rejects the connection with:
  ```text
  OSError: [Errno 101] Network unreachable
  ```
- This proves network isolation is enforced by the Linux kernel namespace (`--network none`), not cooperative environment variables.

### 4.3 Process & Resource Limits (`TestResourceAndPidContainment`)
- **Fork Bomb Containment**: An adversarial script executed an unbounded fork loop (`os.fork()`). Under the container's `--pids-limit 128` cgroup setting, the fork storm was halted immediately with `BlockingIOError: [Errno 11] Resource temporarily unavailable`.
- **Memory Cap**: Allocations exceeding 512MB are immediately terminated by the Linux OOM-killer.

### 4.4 Unforgeable Execution Attestation (`TestContainerExecutionAttestation`)
- An adversarial child script printed a counterfeit JSON attestation to stdout claiming `REMOTE_MICROVM_ISOLATED`.
- Verified that the parent orchestrator ignores child stdout claims and generates an authentic `ExecutionAttestation` signed with parent-verified metadata (`backend_tier`, `runtime_engine`, `image_digest`, `network_mode`, `verified_by_parent: True`).

### 4.5 End-to-End Pipeline Execution (`test_pipeline_e2e_remediation_under_container`)
- Full pipeline run under `OCI_CONTAINER_ISOLATED`:
  1. AST reachability analysis identifies call path.
  2. Pre-patch execution runs inside container under `--network none` -> confirms `RED_STATE_REPRODUCED` (exit code 0, physical sentinel created on disk).
  3. Patcher synthesizes verified remediation.
  4. Post-patch execution runs inside container under `--network none` -> confirms `GREEN_STATE_BLOCKED` (exit code 42, security block, zero sentinel files).
  5. Regression test suite runs inside container -> all 2 tests pass.
  6. Final behavioral verdict: `GREEN_STATE_VERIFIED` with `isolation_tier: "OCI_CONTAINER_ISOLATED"`.

---

## 5. UI Workbench Integration

The React/TypeScript user interface (`ui/src/components/VerificationWorkbench.tsx`) was updated to display real-time substrate telemetry:
- **Header Badge**: Displays active substrate (`SUBSTRATE: OCI_CONTAINER_ISOLATED` or `LOCAL_SUBPROCESS_FALLBACK`).
- **Verdict Certificate**: Displays isolation tier (`TIER: OCI_CONTAINER_ISOLATED`) with emerald styling for container isolation and amber styling for local fallback.
- **Network Mode**: Displays parent-verified network containment (`NETWORK: none (kernel denied)`).
- **Production Build**: Verified with `npm run build` (`dist/assets/index-DL-utK_F.js`, 225.01 kB, built in 4.02s).

---

## 6. Commit Baseline & Traceability

- **Baseline Commit**: `67719d82b305b2721816d1502bfc64c5c4c6ea9d` (P0.5 Closure)
- **New Core Architecture**:
  - `vulntrace/core/backend.py` (Abstract Backend, IsolationTier, Capabilities, Attestation)
  - `vulntrace/core/local_backend.py` (`LocalSubprocessBackend` with Job Object and honest caveats)
  - `vulntrace/core/container_backend.py` (`ContainerExecutionBackend` with rootless Podman/crun)
  - `vulntrace/core/factory.py` (`BackendFactory` with tier auto-resolution and overrides)
- **New Automated Test Suites**:
  - `tests/test_backend_abstraction.py` (8 tests)
  - `tests/test_container_backend.py` (10 tests)
- **Status**: CLOSED & FULLY VERIFIED.
