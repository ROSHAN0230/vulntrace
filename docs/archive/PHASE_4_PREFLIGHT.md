# VulnTrace — Phase 4 Preflight Report
**Date:** October 2, 2026  
**Auditor:** Antigravity Autonomous Security Engineer (DeepMind Team)  
**Status:** Preflight Inspection Completed — Baseline Recorded  

---

## 1. Current Architecture & System Overview

VulnTrace is a defensive security automation platform for autonomous vulnerability reachability analysis, behavioral reproduction in isolated disposable workspaces, and surgical remediation verification using NVIDIA Nemotron 3 Ultra (via Nebius Token Factory).

### End-to-End Execution Trace
```
User / API Request (Repo Path + CVE ID)
   │
   ├── 1. OSV & Tavily Intel (/api/v1/intel/cve)
   │      OSV: Structured schema (advisory summary, affected commit ranges, database CPE)
   │      Tavily: Contextual intelligence (PoCs, advisories, security research URLs)
   │
   ├── 2. Manifest & Source Inspector (/api/v1/repo/inspect)
   │      ManifestParser inspects requirements.txt, pyproject.toml, package.json
   │      Discovers active dependencies, counts Python files, resolves Git commit
   │
   ├── 3. Multi-File AST Reachability Engine (/api/v1/ast/analyze)
   │      AstReachabilityAnalyzer parses full AST of all Python modules in repo
   │      Resolves aliased imports (`import yaml as y`) and from-imports (`from yaml import load`)
   │      Filters out locally shadowed symbols (`class yaml: def load()`) via `local:` prefix
   │      Builds global directed call graph, executes BFS reachability from identified entrypoints
   │      Verdicts: REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED vs UNREACHABLE_FALSE_POSITIVE
   │
   ├── 4. Controlled Defensive Verification Pipeline (/api/v1/pipeline/run & /api/v1/pipeline/stream/{job_id})
   │      SubprocessSandboxRunner creates disposable workspace copy in %TEMP%
   │      Purges host environment variables (stripping keys, secrets, auth tokens)
   │      HarnessSynthesizer synthesizes target-bound verification script with JSON assertion schema
   │      Pre-Patch Execution: Requires RED_STATE_REPRODUCED (exit 0 + sentinel verified)
   │      RemediationPatcher: NVIDIA Nemotron 3 Ultra generates surgical patch
   │      Strict Patch Validation: ast.parse syntax check + semantic diff check
   │      Post-Patch Execution: Dedicated Exit 42 + structured GREEN assertion verified
   │      Regression Suite: pytest runs inside disposable workspace
   │      Final Behavioral Verdict: GREEN_STATE_VERIFIED, UNREACHABLE_FALSE_POSITIVE, INCONCLUSIVE,
   │                                PATCH_REJECTED, REGRESSION_FAILURE, UNEXPECTED_FAILURE
   │
   └── 5. React Frontend Workbench (Vite + React 18 + Tailwind CSS + Lucide Icons)
          Real-time workbench rendering AST call graphs, OSV/Tavily intelligence,
          and live Server-Sent Events stream from the sandbox execution lifecycle.
```

---

## 2. Inventory of Current Modules & Capabilities

| Module | Source File | Purpose & Current Operational Capability |
| :--- | :--- | :--- |
| **Backend API** | `vulntrace/server.py` | FastAPI app providing REST endpoints and SSE streaming `/api/v1/pipeline/stream/{job_id}`. |
| **Data Models** | `vulntrace/models.py` | Pydantic contracts for AST graph nodes, CVE queries, sandbox results, evidence records, and terminal states. |
| **Config** | `vulntrace/config.py` | Loads `NEBIUS_API_KEY`, `TAVILY_API_KEY` from local environment without printing or exposing values. |
| **OSV Client** | `vulntrace/intel/osv_client.py` | Keyless client querying `https://api.osv.dev/v1/vulns/` for structured advisory records and commit ranges. |
| **Tavily Client** | `vulntrace/intel/tavily_client.py` | Contextual search client querying Tavily API for technical exploit references and advisory documentation. |
| **Manifest Parser** | `vulntrace/analyzer/manifest_parser.py` | Parses `requirements.txt` and `pyproject.toml` using `packaging.requirements`. |
| **AST Engine** | `vulntrace/analyzer/ast_visitor.py` | Native Python AST parser building function call graphs, tracing BFS paths, handling shadowed symbols and import aliases. |
| **Nemotron Client** | `vulntrace/agent/nemotron_client.py` | Calls `nvidia/nemotron-3-ultra` via Nebius Token Factory OpenAI-compatible API; captures token and reasoning usage. |
| **Harness Synthesizer**| `vulntrace/agent/harness_synthesizer.py` | Synthesizes target-bound verification harnesses emitting structured JSON behavioral assertion payloads. |
| **Remediation Patcher**| `vulntrace/agent/patcher.py` | Synthesizes surgical diffs via Nemotron; validates syntax (`ast.parse`) and semantic changes; rejects broken patches. |
| **Sandbox Runner** | `vulntrace/sandbox/runner.py` | Manages disposable `%TEMP%` workspaces, purges environment variables, enforces timeouts, terminates process trees via `taskkill`. |
| **Pipeline Orchestrator**| `vulntrace/sandbox/pipeline.py` | Coordinates the 6-stage lifecycle, streams SSE events, executes regression tests, computes final verdict. |
| **Controlled Benchmarks**| `benchmarks/*` | 4 multi-file benchmark fixtures (`deep_callchain`, `unreachable_dead_code`, `regression_sensitive`, `inconclusive_guard`). |
| **Frontend UI** | `ui/src/*` | React + TypeScript SPA displaying live CVE intelligence, call graph visualizer, execution terminal, and workbench status. |

---

## 3. Preflight Baseline Test Suite Results

Before any code changes, the complete existing test suite was executed:
- **Command:** `C:\AI-Tools\vulntrace\.venv\Scripts\python.exe -m pytest tests/ -v`
- **Result:** **26 passed in 14.24s** (100% pass rate)

```
tests/test_api_endpoints.py::test_health_endpoint PASSED                 [  3%]
tests/test_api_endpoints.py::test_cve_intel_endpoint PASSED              [  7%]
tests/test_api_endpoints.py::test_ast_analyze_endpoint PASSED            [ 11%]
tests/test_ast_visitor.py::test_ast_reachability_positive_and_negative PASSED [ 15%]
tests/test_harness_synthesizer.py::test_harness_synthesizer_pyyaml_cve PASSED [ 19%]
tests/test_manifest_parser.py::test_manifest_parser_requirements_and_pyproject PASSED [ 23%]
tests/test_mutations.py::test_mutation_deep_renamed_callchain PASSED     [ 26%]
tests/test_mutations.py::test_mutation_dynamic_symbol_and_target_inference PASSED [ 30%]
tests/test_negative_cases.py::test_case_a_comments_only PASSED           [ 34%]
tests/test_negative_cases.py::test_case_b_shadowed_symbol PASSED         [ 38%]
tests/test_negative_cases.py::test_case_c_aliased_import PASSED          [ 42%]
tests/test_negative_cases.py::test_case_d_from_import PASSED             [ 46%]
tests/test_negative_cases.py::test_case_e_dead_wrapper PASSED            [ 50%]
tests/test_negative_cases.py::test_case_f_multiple_sinks PASSED          [ 53%]
tests/test_negative_cases.py::test_case_g_malformed_syntax_graceful PASSED [ 57%]
tests/test_negative_cases.py::test_case_h_broken_import_unhandled_failure PASSED [ 61%]
tests/test_negative_cases.py::test_case_i_spoofed_exit_42_rejected PASSED [ 65%]
tests/test_negative_cases.py::test_case_j_patch_syntax_error_rejection PASSED [ 69%]
tests/test_osv_client.py::test_osv_live_cve_lookup PASSED                [ 73%]
tests/test_osv_client.py::test_osv_nonexistent_cve PASSED                [ 76%]
tests/test_remediation_pipeline.py::test_end_to_end_verification_pipeline PASSED [ 80%]
tests/test_sandbox_boundary.py::test_sandbox_environment_sanitization PASSED [ 84%]
tests/test_sandbox_boundary.py::test_sandbox_filesystem_isolation PASSED [ 88%]
tests/test_sandbox_boundary.py::test_sandbox_timeout_watchdog PASSED     [ 92%]
tests/test_sandbox_runner.py::test_sandbox_disposable_workspace_and_sanitization PASSED [ 96%]
tests/test_sandbox_runner.py::test_sandbox_execute_script PASSED         [100%]
============================= 26 passed in 14.24s =============================
```

In addition, all 4 controlled benchmark fixtures in `test_benchmarks.py` matched their expected evidence states:
1. `deep_callchain`: `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` → `GREEN_STATE_VERIFIED` (Nemotron 3 Ultra)
2. `unreachable_dead_code`: `UNREACHABLE_FALSE_POSITIVE` → `UNREACHABLE_FALSE_POSITIVE` (Suppressed)
3. `regression_sensitive`: `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` → `GREEN_STATE_VERIFIED` (Nemotron 3 Ultra)
4. `inconclusive_guard`: `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` → `INCONCLUSIVE` (Exit 10)

---

## 4. Known Limitations & Gaps to Address in Phase 4

1. **Trust Boundary (Parent-Side Verification)**:
   Currently, the child harness emits structured JSON asserting `GREEN_SECURITY_BLOCK_VERIFIED` and exits 42. While spoofed exit 42 without JSON is rejected, if an adversary crafts a child script that deliberately prints valid-looking GREEN JSON even when observable evidence contradicts it (e.g. the sentinel marker actually *was* created, or target file was deleted, or the file syntax is broken), the parent must independently audit observable ground truth on disk.
2. **Formal Verdict Engine**:
   Final verdict determination is currently performed in an if-elif block in `pipeline.py`. It needs a formal evidence aggregator model (`RepositoryEvidence`, `AdvisoryEvidence`, `ReachabilityEvidence`, `BehaviorEvidence`, `PatchEvidence`, `RegressionEvidence`, `ExecutionEvidence`) yielding a cryptographically traceable `FinalVerdict` object with explicit terminal states (`VERIFICATION_REJECTED`, etc.).
3. **Machine-Readable Evidence Export**:
   Currently, verification output is returned via API and partially logged in `benchmark_results.json`. There is no dedicated single-click downloadable machine-readable (.json) + human-readable (.md) verification bundle with complete provenance.
4. **Nemotron Contextual Reasoning Proof**:
   While Nemotron 3 Ultra is invoked live via Nebius Token Factory, we need a controlled benchmark case proving that Nemotron solves non-trivial contextual logic (e.g., input normalization, multi-branch wrapper, or coordinated test compatibility) that a one-line AST find-replace cannot solve.
5. **Real-World Independent Repository Validation**:
   The current benchmark fixtures were created to test VulnTrace. We must evaluate VulnTrace against independently selected real-world repositories (e.g., real open-source packages with historical CVEs) to prove generalization beyond internal fixtures.
6. **Static Analysis & Sandbox Boundary Disclosures**:
   Explicitly document what static AST can and cannot see (reflection, dynamic `getattr`, monkey-patching) and reinforce that local execution is `LOCAL_SUBPROCESS_FALLBACK` (disclosing shared OS kernel/network).

---

## 5. Planned Modifications & Files Expected to Change

| Task / Component | Target Files | Planned Modifications |
| :--- | :--- | :--- |
| **Trust Boundary Hardening** | `vulntrace/sandbox/runner.py`, `vulntrace/sandbox/pipeline.py` | Add parent-side ground truth verification: cross-check child JSON claim against observable filesystem state, sentinel presence, disk diffs, and syntax. Emit `VERIFICATION_REJECTED` if child claim contradicts reality. |
| **Formal Verdict Engine** | `vulntrace/models.py`, `vulntrace/engine/verdict_engine.py` (new) | Implement formal evidence models (`RepositoryEvidence`, `AdvisoryEvidence`, `ReachabilityEvidence`, `BehaviorEvidence`, `PatchEvidence`, `RegressionEvidence`, `ExecutionEvidence`) and a deterministic resolver for terminal states. |
| **Reproducible Evidence Export** | `vulntrace/engine/evidence_export.py` (new), `vulntrace/server.py` | Implement endpoint `/api/v1/evidence/export` generating standardized machine-readable `.json` and human-readable `.md` audit records. |
| **Nemotron Contextual Benchmark** | `benchmarks/contextual_reasoning/` (new) | Add benchmark fixture requiring surrounding context understanding (e.g., preserving custom tag handlers / schema wrappers) where generic codemod fails regression tests but Nemotron succeeds. |
| **Real-World Repository Evaluation** | `real_world_eval/` (new) | Select and evaluate independent real-world open-source repositories against VulnTrace, capturing complete evidence tables. |
| **Adversarial Trust Boundary Tests** | `tests/test_parent_trust_boundary.py` (new) | Adversarial test where child emits forged GREEN JSON while sentinel marker is created on disk, verifying parent rejects it as `VERIFICATION_REJECTED`. |
| **UI Polish & Evidence Hierarchy** | `ui/src/components/*` | Expose formal evidence breakdown, limitations disclaimer, and export button in UI. |
