# VulnTrace — P0.5 Trust Boundary Closure Audit & Evidence Record

**Audit Timestamp:** October 3, 2026, 11:05:00 UTC+05:30  
**Baseline Commit:** `aa37af11a84c078cac30800d88eb4267b994408f`  
**Execution Architecture:** Windows NT 64-bit (Python 3.14.2)  
**Sandbox Engine Label:** `LOCAL_SUBPROCESS_FALLBACK` (Win32 Job Object Tier)

---

## 1. Executive Summary

This document records the empirical security boundary audit, implementation changes, and verification evidence for **P0.5 Trust Boundary Closure** in VulnTrace. 

VulnTrace treats security verification as high-consequence defensive engineering. Rather than claiming unwarranted "production-grade microVM isolation" on Windows subprocess execution, this implementation enforces the strongest practical OS-level containment mechanisms available in Windows user mode while explicitly documenting the technical limitations inherent to shared-kernel, non-hypervisor environments.

---

## 2. Exact Security Guarantees Enforced vs. Limitations

### A. Dependency Provisioning (`target_env.py`)
- **Enforced Guarantee**:
  - `TargetEnvironmentManager` explicitly constructs a sanitized environment for `venv` creation and `pip install`.
  - Proactively purges all API keys, SSH credentials, tokens, cloud credentials, and package-manager auth variables (`KEY`, `TOKEN`, `SECRET`, `AUTH`, `PASS`, `CRED`, `NEBIUS`, `TAVILY`, `OPENAI`, `ANTHROPIC`, `GEMINI`, `GITHUB`, `GITLAB`, `BITBUCKET`, `AWS`, `AZURE`, `GCP`, `GOOGLE`, `SSH`, etc.).
  - Runs `pip` with `--isolated`, `--no-cache-dir`, and `--no-warn-script-location`.
  - Redirects `USERPROFILE`, `HOME`, `TEMP`, `TMP`, `APPDATA`, `LOCALAPPDATA` to the disposable workspace.
  - Target dependencies are installed into `.target_venv` inside the disposable directory; the host Python `.venv` is verified completely untouched.
- **Explicit Limitation**:
  - Sanitizing environment variables prevents passive credential theft during setup. However, arbitrary code execution during `setup.py` or PEP-517 build hooks remains inherently dangerous without VM/hypervisor hardware isolation. A malicious package running during `pip install` can execute arbitrary compute and access files readable by the host user.

### B. Process-Tree Containment (`runner.py`)
- **Enforced Guarantee**:
  - Every target execution process is assigned to a dedicated Win32 Job Object (`Win32JobObject`) using `kernel32.dll`.
  - Configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`.
  - Disables silent breakaways (`JOB_OBJECT_LIMIT_BREAKAWAY_OK` / `SILENT_BREAKAWAY_OK` are NOT set): all child, grandchild, and descendant processes remain trapped in the Job Object.
  - Applies memory quotas: `ProcessMemoryLimit = 512MB`, `JobMemoryLimit = 1024MB`.
  - On watchdog timeout or process completion, `TerminateJobObject` and `CloseHandle` guarantee that detached/orphaned child processes (even those created with `DETACHED_PROCESS` or `CREATE_NEW_PROCESS_GROUP`) are terminated by the Windows NT kernel.
- **Explicit Limitation**:
  - Job Objects provide strict process-tree lifecycle and memory quotas. They do NOT provide filesystem access restrictions or network packet filtering.

### C. Network Containment (`runner.py` / `harness_synthesizer.py`)
- **Enforced Guarantee**:
  - Environment variables set invalid proxy dead-ends (`HTTP_PROXY=http://0.0.0.0:0`, `HTTPS_PROXY=http://0.0.0.0:0`, `ALL_PROXY=http://0.0.0.0:0`).
  - `PIP_NO_INDEX=1` and `PIP_OFFLINE=1` disable network package resolution.
  - In-harness defense-in-depth: `socket.socket` and `socket.create_connection` are replaced with stubs raising `PermissionError`.
  - Adversarial subprocess tests prove that child Python interpreters spawning HTTP requests fail.
- **Explicit Limitation**:
  - In Windows user mode without administrative elevation, creating custom Windows Filtering Platform (WFP) rules or modifying `netsh advfirewall` fails with `Access is denied (requires elevation)`. Standard Win32 processes share the host TCP/IP stack. An unprivileged child process using hardcoded paths to native binaries or raw WinSock C-extensions (`ws2_32.dll`) can bypass environment variable proxies for direct TCP connections.

### D. Behavioral-Preservation Oracle (`behavior_oracle.py` / `harness_synthesizer.py`)
- **Enforced Guarantee**:
  - Replaced naive `is not None` check with a generic multi-input behavioral preservation model (`BehaviorOracle`).
  - Evaluates multi-input contracts across flat mappings, nested hierarchies, and diverse scalar/collection types.
  - Asserts structural invariants: type matching, non-empty data containers, mandatory key presence, non-null field values, and semantic equivalence.
  - Rejects:
    - Empty dictionaries `{}`
    - Empty strings `""`
    - Constant strings (e.g. `"blocked"`, `"safe"`)
    - Constant integers (`0`, `42`)
    - `None` returns
    - Structurally incomplete objects missing required fields
    - Objects with null values for required fields
    - Split-brain patches that succeed on input 1 but fail on input 2
  - Dedicated exit code `42` is emitted ONLY when both the security exploit is blocked AND all behavioral contracts pass.
- **Explicit Limitation**:
  - The oracle validates specified contract invariants. If a target service has complex dynamic side-effects (e.g., custom database mutations) not captured in the behavioral contract suite, those side-effects must be tested via the full regression suite (`pytest`).

### E. Anti-Evasion Architecture (`pipeline.py` / `harness_synthesizer.py`)
- **Enforced Guarantee**:
  - Randomized harness filenames: generated as `_eval_<random_hex>.py` instead of predictable `harness_verify.py`.
  - Randomized sentinel markers: generated as `_sentinel_<random_hex>.marker`.
  - Normalizes `sys.argv[0]` inside the harness to point to the target file or application entrypoint, stripping harness indicators.
  - Dual ground-truth validation: the parent verifier independently inspects the physical disk for sentinel files and asserts exit code `42`.
- **Explicit Limitation**:
  - Advanced anti-analysis techniques (e.g. timing attacks or inspecting OS thread handles) could theoretically determine a sandbox environment. VulnTrace mitigates this by relying on behavioral outcome contracts rather than implementation secrecy.

### F. Filesystem Boundary (`runner.py`)
- **Enforced Guarantee**:
  - Target code executes in a temporary directory under `%TEMP%/vulntrace_sandbox_*`.
  - Environment variables `USERPROFILE`, `HOME`, `APPDATA`, `LOCALAPPDATA`, `TEMP`, and `TMP` are redirected to the disposable workspace.
  - `prepare_disposable_workspace` inspects symlinks and directory junctions, rejecting links pointing outside the source repository.
  - Host repository source files remain completely unmodified.
- **Explicit Limitation**:
  - Because child processes run under the ambient security token of the Windows host user (`raahe`), the Windows NT filesystem security manager (DACLs) grants Read access to files owned by that user if accessed via absolute paths (e.g. `C:\Users\raahe\.ssh\id_rsa`). True filesystem isolation requires hypervisor microVMs or dedicated low-privilege OS accounts.

---

## 3. Empirical Test Matrix (59 / 59 Passed)

| Test Module | Tests | Status | Scope |
| :--- | :---: | :---: | :--- |
| `tests/test_api_endpoints.py` | 4 | PASSED | Health, CVE intel, AST analysis, and evidence export endpoints |
| `tests/test_ast_visitor.py` | 1 | PASSED | AST reachability call-graph traversal |
| `tests/test_contextual_reasoning.py` | 1 | PASSED | Live Nemotron 3 Ultra reasoning vs blind AST replacement |
| `tests/test_harness_synthesizer.py` | 1 | PASSED | Synthesizer generation for PyYAML CVE |
| `tests/test_manifest_parser.py` | 1 | PASSED | Dependency manifest parsing without code execution |
| `tests/test_mutations.py` | 2 | PASSED | Dynamic symbol inference and renamed call chains |
| `tests/test_negative_cases.py` | 10 | PASSED | False alarm suppression, syntax errors, shadowed symbols |
| `tests/test_osv_client.py` | 2 | PASSED | OSV CVE vulnerability database client |
| `tests/test_parent_trust_boundary.py` | 5 | PASSED | Parent-side independent filesystem sentinel audit and code 42 verification |
| `tests/test_remediation_pipeline.py` | 1 | PASSED | End-to-end pipeline execution |
| `tests/test_sandbox_boundary.py` | 6 | PASSED | Sanitization, filesystem copy, timeout, **Job Object orphan kill**, **subprocess network denial**, **profile redirection** |
| `tests/test_sandbox_runner.py` | 2 | PASSED | Script runner lifecycle and workspace sanitization |
| `tests/test_target_environment.py` | 7 | PASSED | Manifest detection, network blocking, **setup.py secret purging**, **host venv integrity**, external repo execution |
| `tests/test_verifier_redteam.py` | 16 | PASSED | Adversarial patch red-teaming: ConstructorError, YAMLError, generic Exception, deleted function, naive safe_load, **{}**, **""**, **constant string**, **constant int**, **incomplete dict**, **null field**, **multi-input split-brain**, **anti-evasion argv** |
| **TOTAL** | **59** | **ALL PASSED** | **100% Green Suite (0 failures, 0 regressions)** |

---

## 4. Live E2E Integration Verification

- **Target Benchmark**: `benchmarks/contextual_reasoning` (`CVE-2020-14343`)
- **Tavily Query**: Executed at runtime with strict automated CVE-relevance validation.
- **NVIDIA Nemotron 3 Ultra**: Executed live via Nebius Token Factory, synthesizing contextual `AppSafeLoader` patch.
- **Win32 Job Object Execution**: Target harness executed under Job Object with strict timeout and memory quota.
- **Multi-Input Behavioral Contract**: 3 distinct benign YAML contracts validated post-patch.
- **Regression Suite**: 3/3 pytest test cases passed inside disposable target environment.
- **Terminal State**: `GREEN_STATE_VERIFIED` (Parent-verified exit code 42, zero sentinel markers).
