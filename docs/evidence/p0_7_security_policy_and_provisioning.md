# VulnTrace — P0.7 Execution Security Policy & Provisioning Hardening

**Milestone:** P0.7 Security Capability Policy, Concrete Assurance Levels & Provisioning Egress Hardening  
**Baseline Commit:** `039ee0845d88ae9ac967b956e3e7beda6eef2911` (P0.6 Hardened Execution Substrate)  
**Audit Date:** October 3, 2026  
**Status:** **CLOSED & VERIFIED**  
**Regression Test Suite:** **106 / 106 PASSED** (0 failures, 0 errors, 0 warnings)  

---

## 1. Executive Summary

Milestone **P0.7** upgrades the execution backend abstraction established in P0.6 into an **enforceable security capability policy engine**, establishes **concrete capability-derived assurance levels** (`HIGH_ASSURANCE_CONTAINED`, `DEGRADED_LOCAL_FALLBACK`, `INSUFFICIENT_ISOLATION`), and closes the residual security questions regarding untrusted code execution during dependency provisioning.

Under P0.7:
1. **Capabilities Drive Policy:** A weak backend (`LOCAL_SUBPROCESS_FALLBACK`) can never silently claim or issue a high-assurance verdict. If high assurance is requested (`require_high_assurance=True`), execution on degraded backends is actively blocked with `PermissionError`.
2. **Concrete Assurance Levels:** Vague terms like "secure" or "production-grade" are strictly replaced with three concrete classifications:
   - `HIGH_ASSURANCE_CONTAINED`: Full filesystem jailing, host filesystem hidden, kernel-level network denial, process-tree containment, resource quotas, and unforgeable attestation.
   - `DEGRADED_LOCAL_FALLBACK`: Host subprocess with Win32 Job Object containment and memory caps, but shared host identity and readable host filesystem.
   - `INSUFFICIENT_ISOLATION`: Missing basic process tree or memory limits; all execution operations blocked.
3. **Provisioning Egress Control & Hardening:** If a target repository contains untrusted build hooks (`setup.py` / PEP 517), they execute strictly inside the container tier under `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, memory/PID limits, purged environment variables (zero host secrets), and hidden host filesystem (`/mnt/c` does not exist).
4. **Backend Conformance Test Suite:** A formal 14-test conformance suite verifies that both `LOCAL_SUBPROCESS_FALLBACK` and `OCI_CONTAINER_ISOLATED` strictly honor all declared security contracts.
5. **Verdict Policy Integration & UI Display:** The UI and API explicitly display Backend Tier, Assurance Level, High-Assurance Gate Status, and Active Boundary Caveats.

---

## 2. Concrete Assurance Classification Matrix

| Assurance Dimension | `HIGH_ASSURANCE_CONTAINED` | `DEGRADED_LOCAL_FALLBACK` | `INSUFFICIENT_ISOLATION` |
| :--- | :--- | :--- | :--- |
| **Execution Substrate** | OCI Container (Podman/crun) or MicroVM | Host Subprocess (Win32 Job Object) | Unrestricted Subprocess |
| **Filesystem Isolation** | Mount namespace jailed (`/workspace:rw`) | Disposable directory copy in `%TEMP%` | Shared / Uncontrolled |
| **Host Filesystem Hiding** | **Enforced** (`/mnt/c` non-existent) | **Not Isolated** (Readable under ambient DACLs) | None |
| **Network Control** | **Kernel-Enforced** (`--network none`) | **Cooperative** (`HTTP_PROXY` null-routing) | Open |
| **Process Tree Containment** | **Cgroup PID Limits** (`pids-limit 128`) | **Win32 Job Object** (`KILL_ON_JOB_CLOSE`) | None / Leakable |
| **Resource Limits** | **Cgroup Limits** (`512MB RAM, 1.0 CPU`) | **Job Object Limit** (`512MB RAM`) | None |
| **Host Identity Isolation** | **Rootless Container User Namespace** | **None** (Ambient Windows User Token) | Ambient |
| **Execution Attestation** | **Parent-Generated & Unforgeable** | **Parent-Generated & Unforgeable** | None / Spoofable |
| **Permitted Verdicts** | `HIGH_ASSURANCE_CONTAINED` | `DEGRADED_LOCAL_FALLBACK` | **Execution Blocked** |

---

## 3. Provisioning Security Architecture & Egress Control

### The Threat Model
When assessing third-party repositories, dependency provisioning poses a critical hostile-code risk:
- Arbitrary code execution during `setup.py build` / `pip install`
- Environment variable scraping (exfiltrating `TAVILY_API_KEY`, `NEBIUS_API_KEY`, cloud credentials)
- Host filesystem traversal (reading `%USERPROFILE%`, `.ssh`, `.aws`)
- Outbound network exfiltration during package installation

### Hardened Container Provisioning (`vulntrace/core/container_backend.py`)
In `ContainerExecutionBackend.provision_dependencies()`:
1. **Pre-Baked Image Baseline:** Common security verification dependencies (`PyYAML`, `pytest`, `setuptools`, `wheel`) are baked into `vulntrace-sandbox-base:latest`.
2. **Isolated Build Hook Execution:** If `setup.py` exists in the target repository, it is executed strictly inside the container tier:
```bash
podman run --rm \
  --network none \
  --memory 512m \
  --cpus 1.0 \
  --pids-limit 128 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -v /mnt/c/.../workspace:/workspace:rw \
  -w /workspace \
  vulntrace-sandbox-base:latest \
  python3 setup.py build
```
3. **Verified Adversarial Containment:**
   - **Host Filesystem Probe:** Host Windows paths (`/mnt/c`) do not exist inside container root namespace (`HOST_FS_MNT_EXISTS: False`).
   - **Host Secrets Probe:** Zero ambient environment variables are passed to Podman (`VULNTRACE_SECRETS_FOUND: 0 []`).
   - **Network Exfiltration Probe:** Outbound socket connections fail immediately with `[Errno 101] Network unreachable`.
   - **Fork Bomb & OOM Protection:** Cgroup caps enforce max 128 PIDs and 512MB RAM.

---

## 4. Test Suite Execution & Conformance Evidence

### Full Regression Suite: 106 / 106 Passing (0 Regressions)

```text
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\AI-Tools\vulntrace
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.15.1, asyncio-1.4.0
collected 106 items

tests/test_api_endpoints.py (4 tests) .................................. PASSED
tests/test_ast_visitor.py (1 test) ..................................... PASSED
tests/test_backend_abstraction.py (8 tests) ............................ PASSED
tests/test_backend_conformance.py (14 tests) ........................... PASSED
tests/test_container_backend.py (10 tests) ............................. PASSED
tests/test_contextual_reasoning.py (1 test) ............................ PASSED
tests/test_harness_synthesizer.py (1 test) ............................. PASSED
tests/test_manifest_parser.py (1 test) ................................. PASSED
tests/test_mutations.py (2 tests) ...................................... PASSED
tests/test_negative_cases.py (10 tests) ................................ PASSED
tests/test_osv_client.py (2 tests) ..................................... PASSED
tests/test_parent_trust_boundary.py (5 tests) .......................... PASSED
tests/test_provisioning_security.py (4 tests) .......................... PASSED
tests/test_remediation_pipeline.py (1 test) ............................ PASSED
tests/test_sandbox_boundary.py (6 tests) ............................... PASSED
tests/test_sandbox_runner.py (2 tests) ................................. PASSED
tests/test_security_policy.py (11 tests) ............................... PASSED
tests/test_target_environment.py (8 tests) ............................. PASSED
tests/test_verifier_redteam.py (15 tests) .............................. PASSED

======================= 106 passed in 132.96s (0:02:12) =======================
```

---

## 5. Live Runtime End-to-End Execution Evidence

### A. OCI Container Substrate (`HIGH_ASSURANCE_CONTAINED`)
```text
[SETUP] Target environment provisioned on backend (OCI_CONTAINER_ISOLATED) in 1.75ms. Network isolation active.
[AST] REACHABLE VULNERABLE CALL PATH IDENTIFIED: Call graph path discovered to service/custom_loader.py:parse_app_config()
[INTEL] Tavily search completed: 6 raw result(s), 5 verified relevant to CVE-2020-14343 (1 excluded) in 2837.63ms.
[HARNESS] Harness generated in 1.04ms targeting service/custom_loader.py:parse_app_config()
[REPRODUCTION] RED STATE REPRODUCED: Sentinel marker confirmed (exit 0) in 2180.78ms
[PATCH] Remediation generated via NVIDIA_NEMOTRON_3_ULTRA (2756.88ms)
[VERIFICATION] GREEN STATE VERIFIED: Risky instantiation blocked (exit 42, GREEN_SECURITY_BLOCK_VERIFIED) in 1569.76ms
[REGRESSION] Regression suite PASSED: 3 tests passed in 2256.03ms
[VERDICT] FINAL BEHAVIORAL VERDICT: GREEN_STATE_VERIFIED (Total pipeline: 19477.35ms)
[SANDBOX] Disposable workspace cleanly destroyed on backend.

--- LIVE VERIFICATION RESULT ---
Final Verdict: GREEN_STATE_VERIFIED
Assurance Level: HIGH_ASSURANCE_CONTAINED
Isolation Tier: OCI_CONTAINER_ISOLATED
Remediation Engine: NVIDIA_NEMOTRON_3_ULTRA
Tavily Sources Retained: 5
Nemotron Tokens: 1376
Post-Patch Parent Validated: True
Total Latency (ms): 19477.35
```

### B. Local Subprocess Substrate (`DEGRADED_LOCAL_FALLBACK`)
```text
--- LOCAL FALLBACK RESULT ---
Final Verdict: GREEN_STATE_VERIFIED
Assurance Level: DEGRADED_LOCAL_FALLBACK
Isolation Tier: LOCAL_SUBPROCESS_FALLBACK
Caveats Count: 4
Policy Decision Allowed: True
```

### C. Policy Gating Test (`require_high_assurance=True` on Local Subprocess)
```text
PermissionError: Execution policy violation: [
  "Operation 'HIGH_ASSURANCE_FINAL_VERDICT' requires HIGH_ASSURANCE_CONTAINED; "
  "backend tier 'LOCAL_SUBPROCESS_FALLBACK' is classified as DEGRADED_LOCAL_FALLBACK."
]
```

---

## 6. Frontend UI Integration & Production Build

The production frontend bundle builds cleanly with zero TypeScript or Vite errors:
```bash
> vulntrace-ui@0.1.0 build
> tsc && vite build

vite v5.4.21 building for production...
transforming...
✓ 1571 modules transformed.
rendering chunks...
dist/index.html                   1.15 kB │ gzip:  0.66 kB
dist/assets/index-DV4T5zV2.css   22.93 kB │ gzip:  4.87 kB
dist/assets/index-DqSNigpo.js   227.31 kB │ gzip: 64.16 kB
✓ built in 3.33s
```

UI Features added in P0.7:
- **Assurance Level Badge:** In the Master Verdict Banner, explicitly styled as emerald (`HIGH_ASSURANCE_CONTAINED`) or amber (`DEGRADED_LOCAL_FALLBACK`).
- **Security Policy & Disclosures Card:** Displays Backend Tier, Assurance Level, High-Assurance Gate Status, and Active Boundary Caveats dynamically.
- **Parent Attestation Display:** Displays cryptographic signature status and kernel network denial mode.

---

## 7. Audit Conclusion & Checkpoint

All requirements of **P0.7 Execution Security Policy & Provisioning Hardening** are complete and validated:
1. Explicit security capability policy engine implemented and enforced (`vulntrace/core/policy.py`).
2. Concrete assurance levels defined and integrated into VerdictEngine, pipeline, API, and UI.
3. Untrusted dependency provisioning and build hooks executed inside container tier with capability drops, purged secrets, and hidden host filesystem.
4. Formal backend conformance test suite created with 14 parameterized tests across all guarantees.
5. 106/106 tests passing without regression.
6. Live Tavily + Nebius Nemotron 3 Ultra verification confirmed on both OCI and local backends.
7. Frontend UI compiled and verified.
