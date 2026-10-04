# VulnTrace — Phase 4 Evidence Index
**Traceability Matrix of All Verified Capabilities, Tests, and Telemetry**

**Project:** VulnTrace — Autonomous Vulnerability Reproduction and Verified Patching Agent  
**Hackathon:** Nebius × NVIDIA Global AI Hackathon 2026  
**Date:** October 2, 2026  
**Auditor:** Antigravity Autonomous Security Engineer (DeepMind Team)  

---

## Traceability Matrix

| Claimed Capability | Primary Source File(s) | Verification Test File | Execution Command | Observable Output / Ground Truth | Artifact Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Parent-Side Trust Boundary Audit** | `vulntrace/sandbox/runner.py` (lines 140–210) | `tests/test_parent_trust_boundary.py` | `pytest tests/test_parent_trust_boundary.py -v` | 5 passed. Rejects forged green JSON with sentinel on disk (Exit 43 `VERIFICATION_REJECTED`). | `vulntrace_phase4_completion_report.md` (Sec. 3 & 4) |
| **2. Multi-File AST Reachability Engine** | `vulntrace/analyzer/ast_visitor.py` | `tests/test_ast_visitor.py`, `tests/test_mutations.py` | `pytest tests/test_ast_visitor.py tests/test_mutations.py -v` | 3 passed. Correctly resolves aliases (`import yaml as y`), from-imports, and shadows (`local:` prefix). | `vulntrace_phase3_5_generalization_audit.md` |
| **3. Negative & Adversarial False Positives** | `vulntrace/analyzer/ast_visitor.py` | `tests/test_negative_cases.py` | `pytest tests/test_negative_cases.py -v` | 10 passed. Case A (comments only), Case B (shadowed symbol), Case I (spoofed exit 42), Case J (syntax error). | `vulntrace_phase3_completion_report.md` |
| **4. NVIDIA Nemotron 3 Ultra Remediation** | `vulntrace/agent/nemotron_client.py`, `vulntrace/agent/patcher.py` | `tests/test_remediation_pipeline.py` | `pytest tests/test_remediation_pipeline.py -v` | 1 passed. Live streaming API call to Nebius Token Factory with reasoning token capture. | `vulntrace_phase4_completion_report.md` (Sec. 6) |
| **5. Contextual Reasoning vs Naive AST** | `benchmarks/contextual_reasoning/`, `vulntrace/agent/nemotron_client.py` | `tests/test_contextual_reasoning.py` | `pytest tests/test_contextual_reasoning.py -v` | 1 passed. Naive AST breaks custom tag `!env_var` (3 failures); Nemotron preserves `AppSafeLoader`, passing 3/3 regressions. | `vulntrace_phase4_completion_report.md` (Sec. 6) |
| **6. Reproducible Machine-Readable Evidence Export** | `vulntrace/engine/evidence_export.py`, `vulntrace/server.py` | `tests/test_api_endpoints.py` | `pytest tests/test_api_endpoints.py::test_evidence_export_endpoint -v` | 1 passed. Computes SHA-256 signatures of harnesses and patches; exports standardized JSON + MD bundles. | `vulntrace_phase4_completion_report.md` (Sec. 11 & 12) |
| **7. Real-World Open-Source Evaluation** | `real_world_eval/run_eval.py` | `real_world_eval/evaluation_matrix.json` | `python real_world_eval/run_eval.py` | Evaluates authentic GitHub repos: `flasgger` (`163a753` and `ee62207`) and `cookiecutter` (`c88fbe9`). | `real_world_eval/EVALUATION_REPORT.md` |
| **8. Four Controlled Benchmark Scenarios** | `benchmarks/*`, `test_benchmarks.py` | `test_benchmarks.py` | `python test_benchmarks.py` | 4/4 passed: `deep_callchain` (GREEN), `unreachable_dead_code` (UNREACHABLE), `regression_sensitive` (GREEN), `inconclusive_guard` (INCONCLUSIVE). | `vulntrace_phase3_completion_report.md` |
| **9. Subprocess Sandbox Boundary & Sanitization** | `vulntrace/sandbox/runner.py` | `tests/test_sandbox_boundary.py` | `pytest tests/test_sandbox_boundary.py -v` | 3 passed. Credentials purged, %TEMP% workspace isolated, watchdog kills hung processes via `taskkill`. | `vulntrace_phase4_completion_report.md` (Sec. 9) |
| **10. Live OSV.dev Advisory Integration** | `vulntrace/intel/osv_client.py` | `tests/test_osv_client.py` | `pytest tests/test_osv_client.py -v` | 2 passed. Fetches CVE-2020-14343 structured advisory, CPEs, and git commit fix ranges without API key. | `vulntrace_phase1_completion_report.md` |
| **11. Live Tavily Contextual Search** | `vulntrace/intel/tavily_client.py` | `tests/test_api_endpoints.py` | `pytest tests/test_api_endpoints.py::test_cve_intel_endpoint -v` | 1 passed. Queries Tavily API for technical exploit references using local credentials (1,000 API credits/mo). | `vulntrace_phase1_completion_report.md` |
| **12. React Frontend Production Build & Delivery** | `ui/src/components/VerificationWorkbench.tsx`, `vulntrace/server.py` | `ui/package.json` | `npm run build` (in `ui/`) + `uvicorn` | Vite builds 1,571 modules in 19.95s; FastAPI serves static SPA at `/` with HTTP 200. | `vulntrace_phase4_completion_report.md` (Sec. 11 & 12) |
| **13. ConTree Cloud Status (Truthful 403)** | `vulntrace/server.py`, `vulntrace/sandbox/runner.py` | `vulntrace/server.py` | `curl http://127.0.0.1:8000/api/v1/health` | Status returns `BLOCKED / PERMISSION_DENIED (HTTP 403)`. Local fallback explicitly disclosed. | `vulntrace_phase4_completion_report.md` (Sec. 16) |

---

## Test Suite Execution Log Summary

- **Total Test Files:** 11
- **Total Test Cases:** 33
- **Pass Rate:** 100% (33 passed, 0 failed, 0 skipped)
- **Execution Time:** 17.51 seconds
- **Platform:** Windows 11 / Python 3.14.2 / Pytest 9.1.1
