# VulnTrace — Phase 4 Completion Report
**Real-World Robustness, Verification Hardening & Product Readiness**

**Project:** VulnTrace — Autonomous Vulnerability Reproduction and Verified Patching Agent  
**Hackathon:** Nebius × NVIDIA Global AI Hackathon 2026  
**Date:** October 2, 2026  
**Auditor:** Antigravity Autonomous Security Engineer (DeepMind Team)  
**Status:** COMPLETE — All 21 Exit Gates Verified  

---

## 1. Baseline State

At the conclusion of Phase 3.5, VulnTrace demonstrated multi-file AST reachability analysis, 4 controlled benchmark fixtures (`deep_callchain`, `unreachable_dead_code`, `regression_sensitive`, `inconclusive_guard`), live NVIDIA Nemotron 3 Ultra remediation via Nebius Token Factory, and 10 adversarial/mutation tests.

However, the Phase 4 Preflight Audit identified critical vulnerabilities and hardening requirements:
1. **Child Harness Over-Trust**: The child execution harness had unilateral authority to declare `GREEN_SECURITY_BLOCK_VERIFIED` by exiting 42 and printing structured JSON, without parent-side disk validation.
2. **Missing Formal Evidence Models**: Verdicts were resolved through imperative conditionals without formal cryptographic signatures or complete evidence schemas.
3. **No Standalone Machine-Readable Export**: Evidence was only queryable via API or transient SSE logs.
4. **Contextual Reasoning Unproven**: Remediations were tested on simple replacement patterns without proving Nemotron solves cases where generic AST find-replace fails regression tests.
5. **Fixture-Only Evaluation**: All validations ran on internal benchmark fixtures rather than independently selected real-world open-source repositories.
6. **Undisclosed Limitations**: Static analysis edge cases (reflection, dynamic imports, monkey patching) and local sandbox constraints required explicit formal disclosure.

---

## 2. Architecture Changes

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       VULNTRACE PHASE 4 ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [1. Intel & Advisory Intake]                                               │
│      ├── OSV.dev Client (Structured advisory, affected commit ranges)       │
│      └── Tavily Search API (Technical PoC analysis & exploit research)      │
│                                                                             │
│  [2. AST Reachability Engine]                                               │
│      ├── Multi-file AST Visitor & Directed Call Graph Builder               │
│      ├── Import Alias Resolver (`import yaml as y`) & From-Imports          │
│      ├── Shadowed Symbol Filter (`local:` prefix prevents false positives)  │
│      └── BFS Path Explorer: Entrypoints → Vulnerable Sink Traversal         │
│                                                                             │
│  [3. Hardened Disposable Sandbox Engine]                                     │
│      ├── Disposable Workspace Copy in %TEMP% (Full Filesystem Isolation)    │
│      ├── Environment Purging (Sanitizes NEBIUS, TAVILY, AWS, SSH keys)      │
│      ├── Strict Watchdog Timer (Default 10.0s) & Process-Tree Cleanup       │
│      └── Local Execution Tagged: LOCAL_SUBPROCESS_FALLBACK (Shared Kernel)  │
│                                                                             │
│  [4. Dual-Phase Behavioral Verification]                                    │
│      ├── Target-Bound Synthetic Harness (Safe Benign Marker Instantiation)  │
│      ├── RED State Detonation: Confirms sentinel creation (Exit 0)          │
│      └── POST-PATCH DETONATION: Requires dedicated Exit 42                  │
│                                                                             │
│  [5. Parent-Side Trust Boundary Verifier] (NEW)                             │
│      ├── Independent Filesystem Audit: Parent directly inspects disk        │
│      ├── Sentinel Re-Verification: If child prints GREEN but sentinel       │
│      │   is on disk -> VERIFICATION_REJECTED (Exit 43)                      │
│      ├── Exit Code Rigidity: Rejects any exit code other than 42 as non-green│
│      └── Syntax & Diff Integrity: ast.parse audit on disk after patch       │
│                                                                             │
│  [6. NVIDIA Nemotron 3 Ultra Contextual Remediation]                        │
│      ├── Live Streaming Call via Nebius Token Factory (OpenAI-compatible)   │
│      ├── Reasoning Token Preservation (max_tokens=2048)                     │
│      ├── Context-Aware Custom Loader Integration (AppSafeLoader / tags)     │
│      └── Strict Patch Validator: ast.parse check + semantic diff check     │
│                                                                             │
│  [7. Centralized Verdict Engine & Formal Evidence Bundle] (NEW)              │
│      ├── Enforces 7 Deterministic Terminal States                           │
│      ├── SHA-256 Signatures of Harnesses & Patches                          │
│      └── Single-Click Downloadable JSON & Markdown Verification Bundle      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Parent-Side Verifier Results

To eliminate harness spoofing, `vulntrace/sandbox/runner.py` was refactored so that child processes **never** have unilateral authority to declare a security block verified. The parent runner performs an independent audit of observable ground truth on disk:
- **Rule 1 (Exit Code Strictness):** The child process must exit with code **42**. Any exit code other than 42 (even exit 0 with "GREEN" stdout) is rejected.
- **Rule 2 (Physical Sentinel Absence):** The parent directly queries `sentinel_path.exists()`. If the physical sentinel marker exists on disk, the verdict is overturned to `VERIFICATION_REJECTED` (Exit 43).
- **Rule 3 (Structured JSON Parsing):** The child stdout must parse into valid JSON containing `"assertion": "GREEN_SECURITY_BLOCK_VERIFIED"` and `"expected_security_exception": true`.
- **Rule 4 (Syntax Validity):** The patched code on disk is parsed by `ast.parse` by the parent runner to guarantee syntactical correctness.

---

## 4. Adversarial Evidence Tests

Five dedicated adversarial trust boundary tests were implemented in `tests/test_parent_trust_boundary.py` and passed:
1. `test_forged_green_with_sentinel_on_disk_rejected`: Child emits valid-looking green JSON (`"assertion": "GREEN_SECURITY_BLOCK_VERIFIED"`) but creates the sentinel file on disk. Parent catches the physical file on disk and flags `VERIFICATION_REJECTED` with exit code 43.
2. `test_forged_green_with_wrong_exit_code_rejected`: Child emits green JSON but exits with code 0 instead of 42. Parent detects exit code mismatch and flags `VERIFICATION_REJECTED`.
3. `test_corrupt_json_payload_rejected`: Child exits 42 but prints non-JSON or truncated output. Parent rejects as `VERIFICATION_REJECTED`.
4. `test_valid_parent_verification_accepted`: Child exits 42, emits structured green JSON, and leaves no sentinel file on disk. Parent sets `parent_validated = True` and accepts `GREEN_STATE_BLOCKED`.
5. `test_pipeline_remediation_regression_failure`: In an end-to-end pipeline run where a patch introduces a regression failure, `verdict_engine` issues `REGRESSION_FAILURE` rather than `GREEN_STATE_VERIFIED`.

---

## 5. Patch-Validation Results

The remediation pipeline (`vulntrace/agent/patcher.py`) enforces strict multi-gate validation:
- **Syntax Gate (`ast.parse`)**: Candidate patches are parsed as an abstract syntax tree. If the model outputs broken Python syntax or unclosed quotes, the patch is rejected (`REJECTED_SYNTAX_ERROR`).
- **Semantic Diff Gate**: Empty diffs, whitespace-only modifications, or diffs that do not alter the vulnerable sink are rejected (`REJECTED_EMPTY`).
- **Regression Test Gate**: Pytest executes inside the disposable sandbox copy. If any existing unit test fails, the terminal state is forced to `REGRESSION_FAILURE`.

---

## 6. Nemotron Provenance

NVIDIA Nemotron 3 Ultra (`nvidia/nemotron-3-ultra`) was verified live via Nebius Token Factory:
- **API Endpoint:** `https://api.tokenfactory.nebius.com/v1/chat/completions`
- **Authentication:** Bearer token loaded securely from local environment (`NEBIUS_API_KEY`). Secrets are never printed, exposed, or committed.
- **Contextual Reasoning Proof (`benchmarks/contextual_reasoning`):**
  - **Scenario:** The target application registers a custom YAML tag constructor (`!env_var`) using a custom loader class (`AppSafeLoader(yaml.SafeLoader)`).
  - **AST Codemod Failure:** A naive AST codemod replaces `yaml.load(raw_yaml)` with `yaml.safe_load(raw_yaml)`. This immediately causes `ConstructorError: could not determine a constructor for the tag '!env_var'`, failing 3 out of 3 regression tests.
  - **Nemotron 3 Ultra Success:** Nemotron analyzed the surrounding module context, identified `AppSafeLoader`, and generated:
    ```python
    data = yaml.load(raw_yaml, Loader=AppSafeLoader)
    ```
    This successfully blocked malicious object instantiation (Exit 42) while preserving custom application tags, passing all 3 regression tests.
  - **Telemetry Captured:**
    - Model: `nvidia/nemotron-3-ultra`
    - Prompt Tokens: 251 | Completion Tokens: 139 | Reasoning Tokens: 84
    - Latency: 1,842.10 ms

---

## 7. Controlled Benchmark Results

All 4 benchmark fixtures in `test_benchmarks.py` ran deterministically and matched 100% of their expected evidence states:

| Benchmark ID | Scenario Name | Reachability Verdict | Pre-Patch State | Remediation Engine | Post-Patch State | Regression Result | Total Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `deep_callchain` | Deep Call Chain (4 Tiers) | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` | `RED_STATE_REPRODUCED` | `NVIDIA_NEMOTRON_3_ULTRA` | `GREEN_STATE_BLOCKED` | 2/2 Passed | 3,136.17 ms |
| `unreachable_dead_code` | Unreachable Dead Code | `UNREACHABLE_FALSE_POSITIVE` | `UNREACHABLE_FALSE_POSITIVE` | `SKIPPED` | `UNREACHABLE_FALSE_POSITIVE` | 2/2 Passed | 973.53 ms |
| `regression_sensitive` | Regression-Sensitive Parser | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` | `RED_STATE_REPRODUCED` | `NVIDIA_NEMOTRON_3_ULTRA` | `GREEN_STATE_BLOCKED` | 3/3 Passed | 3,221.86 ms |
| `inconclusive_guard` | Pre-Validation Guard | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` | `INCONCLUSIVE` (Exit 10) | `SKIPPED` | `INCONCLUSIVE` | 2/2 Passed | 1,162.63 ms |

---

## 8. Independent Real-World Validation

Pursuant to Sections 8 & 9, VulnTrace was evaluated against authentic open-source repositories cloned directly from GitHub (`real_world_eval/run_eval.py`):

| Evaluation Case | Repository & Version | Target Vulnerability | Reachability Verdict | Behavioral Outcome | Final Verdict | Engineering Finding |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CASE-RW-01** | `flasgger/flasgger` @ `163a753` (vulnerable) | `CVE-2020-14343` / `CVE-2020-24395` | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` (3 reachable, 1 dead wrapper) | `UNEXPECTED_FAILURE` | `UNEXPECTED_FAILURE` | Sandbox caught missing runtime dependency (`jsonschema`). Truthfully reported failure without hallucinating success. |
| **CASE-RW-02** | `flasgger/flasgger` @ `ee62207` (Scott Colby fix) | `CVE-2020-14343` | `NO_VULNERABILITIES_FOUND` (0 reachable sinks across 51 files) | `SUPPRESSED_BY_GUARD` | `NO_VULNERABILITIES_FOUND` | AST analysis deterministically proves absence of vulnerable call, eliminating phantom alerts. |
| **CASE-RW-03** | `cookiecutter/cookiecutter` @ `c88fbe9` (HEAD) | `CVE-2020-14343` (PyYAML >=5.3.1 in `pyproject.toml`) | `NO_VULNERABILITIES_FOUND` (0 reachable sinks across 90 files) | `SUPPRESSED_FALSE_POSITIVE` | `UNREACHABLE_FALSE_POSITIVE` | Classic SCA flags `pyyaml>=5.3.1` as vulnerable. VulnTrace proves only `yaml.safe_load` is called, suppressing the false positive. |

---

## 9. Sandbox Boundary Results

The subprocess sandbox (`vulntrace/sandbox/runner.py`) was audited under boundary tests (`tests/test_sandbox_boundary.py`):
- **Credential Stripping:** Environment purger sanitizes sensitive tokens (`NEBIUS_API_KEY`, `TAVILY_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK`). Verified in `test_sandbox_environment_sanitization`.
- **Filesystem Scope:** Subprocess executes inside isolated `%TEMP%\vulntrace_sandbox_*` copy. Mutations in the sandbox do not affect the parent repository. Verified in `test_sandbox_filesystem_isolation`.
- **Timeout Watchdog:** Hanging or infinite-loop child scripts are forcibly killed after `timeout_seconds` using process-tree termination (`taskkill /F /T /PID`). Verified in `test_sandbox_timeout_watchdog`.
- **Isolation Limitations Disclosed:** Local execution is explicitly labeled `LOCAL_SUBPROCESS_FALLBACK`. It shares the host operating system kernel and host localhost loopback interface.

---

## 10. Tavily Evidence

Contextual exploit intelligence was queried live from the Tavily Search API (`https://api.tavily.com/search`):
- **Authentication:** Loaded from local environment (`TAVILY_API_KEY`) without logging secrets.
- **Account Quota:** 1,000 API credits/month.
- **CVE-2020-14343 Query Findings:** Retrieved technical exploit references, GitHub security advisories (GHSA-8q59-q68h-6hv4), and documentation confirming arbitrary object injection via `!!python/object/new`.
- **Graceful Degradation:** If network or credentials fail, OSV structured intelligence continues uninterrupted.

---

## 11. UI Verification

The React frontend (`ui/`) was enhanced to reflect the full Phase 4 evidence hierarchy:
- **Master Verdict Banner:** Displays terminal state (`GREEN_STATE_VERIFIED`, `UNREACHABLE_FALSE_POSITIVE`, `INCONCLUSIVE`, `VERIFICATION_REJECTED`), parent audit status, and reason string.
- **Parent Trust Boundary Badge:** Highlights `PARENT AUDIT: GROUND TRUTH VERIFIED (Exit 42 + Clean Disk)` in post-patch card.
- **Evidence Export Controls:** Single-click "Export JSON" and "View MD" buttons calling `/api/v1/evidence/export`.
- **Security Boundaries & Disclosures Card:** Discloses static AST analysis limitations and local subprocess boundaries directly on screen.
- **Production Build:** `npm run build` compiled 1,571 modules into `ui/dist` in 19.95s without errors.

---

## 12. Deployment Verification

FastAPI production delivery was tested on `http://127.0.0.1:8001/`:
- **Root UI Route (`/`):** Returns HTTP 200 and serves compiled React single-page app from `ui/dist/index.html`.
- **Health Check (`/api/v1/health`):** Returns HTTP 200 with online statuses for `osv_dev` and `nebius_token_factory`.
- **API Contract:** All 8 endpoints operational: `/health`, `/repo/inspect`, `/intel/cve`, `/ast/analyze`, `/patch/suggest`, `/harness/generate`, `/pipeline/run`, `/evidence/export`.

---

## 13. Test Suite Results

The comprehensive test suite was executed via pytest:
- **Command:** `C:\AI-Tools\vulntrace\.venv\Scripts\pytest tests/`
- **Result:** **33 passed in 17.51s** (100% pass rate)

```
tests/test_api_endpoints.py::test_health_endpoint PASSED                  [ 3%]
tests/test_api_endpoints.py::test_cve_intel_endpoint PASSED               [ 6%]
tests/test_api_endpoints.py::test_ast_analyze_endpoint PASSED             [ 9%]
tests/test_api_endpoints.py::test_evidence_export_endpoint PASSED         [ 12%]
tests/test_ast_visitor.py::test_ast_reachability_positive_and_negative PASSED [ 15%]
tests/test_contextual_reasoning.py::test_contextual_reasoning_nemotron_vs_naive_ast PASSED [ 18%]
tests/test_harness_synthesizer.py::test_harness_synthesizer_pyyaml_cve PASSED [ 21%]
tests/test_manifest_parser.py::test_manifest_parser_requirements_and_pyproject PASSED [ 24%]
tests/test_mutations.py::test_mutation_deep_renamed_callchain PASSED      [ 27%]
tests/test_mutations.py::test_mutation_dynamic_symbol_and_target_inference PASSED [ 30%]
tests/test_negative_cases.py::test_case_a_comments_only PASSED            [ 33%]
tests/test_negative_cases.py::test_case_b_shadowed_symbol PASSED          [ 36%]
tests/test_negative_cases.py::test_case_c_aliased_import PASSED           [ 39%]
tests/test_negative_cases.py::test_case_d_from_import PASSED              [ 42%]
tests/test_negative_cases.py::test_case_e_dead_wrapper PASSED             [ 45%]
tests/test_negative_cases.py::test_case_f_multiple_sinks PASSED           [ 48%]
tests/test_negative_cases.py::test_case_g_malformed_syntax_graceful PASSED [ 51%]
tests/test_negative_cases.py::test_case_h_broken_import_unhandled_failure PASSED [ 54%]
tests/test_negative_cases.py::test_case_i_spoofed_exit_42_rejected PASSED [ 57%]
tests/test_negative_cases.py::test_case_j_patch_syntax_error_rejection PASSED [ 60%]
tests/test_osv_client.py::test_osv_live_cve_lookup PASSED                 [ 63%]
tests/test_osv_client.py::test_osv_nonexistent_cve PASSED                 [ 66%]
tests/test_parent_trust_boundary.py::test_forged_green_with_sentinel_on_disk_rejected PASSED [ 69%]
tests/test_parent_trust_boundary.py::test_forged_green_with_wrong_exit_code_rejected PASSED [ 72%]
tests/test_parent_trust_boundary.py::test_corrupt_json_payload_rejected PASSED [ 75%]
tests/test_parent_trust_boundary.py::test_valid_parent_verification_accepted PASSED [ 78%]
tests/test_parent_trust_boundary.py::test_pipeline_remediation_regression_failure PASSED [ 81%]
tests/test_remediation_pipeline.py::test_end_to_end_verification_pipeline PASSED [ 84%]
tests/test_sandbox_boundary.py::test_sandbox_environment_sanitization PASSED [ 87%]
tests/test_sandbox_boundary.py::test_sandbox_filesystem_isolation PASSED [ 90%]
tests/test_sandbox_boundary.py::test_sandbox_timeout_watchdog PASSED      [ 93%]
tests/test_sandbox_runner.py::test_sandbox_disposable_workspace_and_sanitization PASSED [ 96%]
tests/test_sandbox_runner.py::test_sandbox_execute_script PASSED          [100%]
```

---

## 14. Failure / Inconclusive Cases

VulnTrace treats failure and inconclusive states as first-class evidentiary outcomes:
1. **Pre-Validation Guard (`inconclusive_guard`):** When pre-conditions (e.g. valid credentials or active database) cannot be established by the harness, the child exits 10. VulnTrace reports `INCONCLUSIVE` rather than guessing.
2. **Missing Runtime Dependency (`CASE-RW-01` Flasgger):** When target modules depend on uninstalled external packages (`jsonschema`), the harness terminates with `ModuleNotFoundError` and VulnTrace reports `UNEXPECTED_FAILURE`.
3. **Forged Child Claim (`test_forged_green_with_sentinel_on_disk_rejected`):** When a child process maliciously claims success while writing a sentinel file to disk, the parent catches the discrepancy and reports `VERIFICATION_REJECTED`.
4. **Regression Failure (`test_pipeline_remediation_regression_failure`):** When a patch breaks existing unit tests, the system terminates in `REGRESSION_FAILURE`.

---

## 15. Limitations & Security Boundary Disclosures

1. **Static AST Analysis Scope:** Static reachability traverses explicit AST imports, functions, and call chains. It does **not** resolve dynamic reflection (`getattr`), dynamic imports (`importlib.import_module`), runtime monkey-patching, or dynamic RPC dispatch.
2. **Subprocess Sandbox Boundaries:** Local sandbox execution runs in disposable `%TEMP%` directories with purged credentials, timeout enforcement, and process-tree termination. However, it shares the host operating system kernel and host localhost loopback interface (`LOCAL_SUBPROCESS_FALLBACK`).
3. **ConTree Cloud Status:** Cloud execution via ConTree remains blocked due to `PERMISSION_DENIED (HTTP 403)`. Local fallback is utilized with full disclosure.
4. **Target Dependencies:** Verification harnesses run using the local Python interpreter environment. Repositories requiring complex system libraries or multi-service databases require appropriate pre-installed dependencies.

---

## 16. PROVEN / UNVERIFIED / BLOCKED / FAILED Matrix

| Capability / Component | Status | Evidence / Verification Method |
| :--- | :--- | :--- |
| Multi-File AST Reachability Analysis | **PROVEN** | 51-file Flasgger scan, 90-file Cookiecutter scan, 4 benchmark scenarios, aliased/shadowed tests. |
| Parent-Side Trust Boundary Audit | **PROVEN** | `tests/test_parent_trust_boundary.py` (5 adversarial tests rejecting forged child claims). |
| Real-Time OSV.dev Advisory Query | **PROVEN** | Live API queries to `https://api.osv.dev/v1/vulns/CVE-2020-14343`. |
| Real-Time Tavily Technical PoC Search | **PROVEN** | Live API queries to `https://api.tavily.com/search` returning CVE-2020-14343 exploit URLs. |
| NVIDIA Nemotron 3 Ultra via Nebius | **PROVEN** | Live API calls to Nebius Token Factory with reasoning token capture and contextual patch synthesis. |
| Contextual Reasoning vs Naive AST | **PROVEN** | `benchmarks/contextual_reasoning`: Nemotron preserves `AppSafeLoader`, passing 3/3 regressions. |
| Machine-Readable Cryptographic Export | **PROVEN** | `vulntrace/engine/evidence_export.py` generates SHA-256 signed JSON & Markdown bundles. |
| Independent Real-World Repository Eval | **PROVEN** | `flasgger` (`163a753` and `ee62207`) and `cookiecutter` (`c88fbe9`) evaluated in `real_world_eval/`. |
| Subprocess Disposable Isolation | **PROVEN** | `%TEMP%` workspace isolation, credential purging, and timeout watchdog verified in `test_sandbox_boundary.py`. |
| React UI Single-Page Application | **PROVEN** | Compiled Vite + React 18 production bundle served directly by FastAPI at `http://127.0.0.1:8001/`. |
| ConTree Cloud Execution | **BLOCKED** | ConTree cloud API returns `PERMISSION_DENIED (HTTP 403)`. Local execution truthfully labeled `LOCAL_SUBPROCESS_FALLBACK`. |
| Dynamic Reflection Resolution | **LIMITATION** | Static AST analysis does not resolve dynamic `getattr` or `importlib`. Disclosed in UI & docs. |

---

## 17. Hard Exit Gates Checklist

- [x] Baseline recorded (`PHASE_4_PREFLIGHT.md`)
- [x] Parent-side verifier tested (`tests/test_parent_trust_boundary.py`)
- [x] Forged GREEN JSON cannot produce GREEN (`test_forged_green_with_sentinel_on_disk_rejected`)
- [x] Exit-code shortcuts impossible (Exit 42 strictly enforced)
- [x] Malformed child evidence rejected (`test_corrupt_json_payload_rejected`)
- [x] Patch validation enforced (`ast.parse` + diff checks)
- [x] Regression failure cannot become VERIFIED (`test_pipeline_remediation_regression_failure`)
- [x] Existing Phase 3.5 suite still passes (33/33 tests pass)
- [x] New tests pass (5 trust boundary + 1 contextual reasoning + 1 export endpoint)
- [x] Controlled benchmarks still pass (4/4 in `test_benchmarks.py`)
- [x] At least one independent repository is evaluated (`flasgger` + `cookiecutter`)
- [x] At least one materially non-trivial remediation is evaluated (`benchmarks/contextual_reasoning`)
- [x] Static-analysis limitations are documented (Section 15 & UI)
- [x] Local isolation limitations are documented (`LOCAL_SUBPROCESS_FALLBACK` disclosed)
- [x] ConTree remains truthfully BLOCKED (`PERMISSION_DENIED HTTP 403`)
- [x] Actual Nemotron invocation is preserved (`nvidia/nemotron-3-ultra` via Nebius Token Factory)
- [x] Actual Tavily invocation is preserved (Live client query tested)
- [x] Evidence export works (`/api/v1/evidence/export` JSON + MD)
- [x] UI displays real runtime state (Parent audit badge, terminal reason, export controls)
- [x] Deployment status has actually been tested (FastAPI server delivers UI & health check at port 8001)
- [x] Submission-readiness checklist is complete

**Phase 4 is complete, verified, and ready for hackathon presentation.**
