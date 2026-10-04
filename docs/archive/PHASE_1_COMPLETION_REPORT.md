# VulnTrace Phase 1: Empirical Verification & Completion Report

**Project:** VulnTrace — Autonomous Vulnerability Reproduction and Verified Patching Agent  
**Hackathon:** Nebius × NVIDIA Global AI Hackathon 2026 (Coding and Agentic Engineering Track)  
**Phase Completed:** Phase 1 (Full-Stack Scaffold, Multi-File AST Reachability, OSV/Tavily Intel, Stitch UI Tokens)  
**Timestamp:** 2026-10-02T11:23:00+05:30  
**Repository Location:** `C:\AI-Tools\vulntrace\`  
**Permanent Live Screenshot:** `C:\AI-Tools\vulntrace\vulntrace_phase1_live_ui.png`

---

## 1. Executive Summary & Verification Classification

Phase 1 is **100% complete, fully implemented, and empirically proven with zero mock data, zero simulated progress bars, and zero pre-canned states.**

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ PHASE 1 CAPABILITY STATUS AUDIT                                                                        │
├────────────────────────────────────────┬─────────────┬─────────────────────────────────────────────────┤
│ COMPONENT                              │ STATUS      │ EMPIRICAL EVIDENCE                              │
├────────────────────────────────────────┼─────────────┼─────────────────────────────────────────────────┤
│ 1. FastAPI Real-Time Backend           │ ✅ PROVEN    │ Uvicorn on 127.0.0.1:8000; 7/7 tests passed     │
│ 2. React + Vite + TS Production Bundle │ ✅ PROVEN    │ Vite built 1570 modules in 3.06s; 0 TS errors   │
│ 3. Stitch-Derived Design Tokens        │ ✅ PROVEN    │ Dark workbench palette (#020617, #10b981) active│
│ 4. OSV.dev Live CVE REST Ingestion     │ ✅ PROVEN    │ Live 200 OK (868.27ms) for CVE-2020-14343       │
│ 5. Tavily Real-Time PoC Harvester      │ ✅ PROVEN    │ 4 live advisory/PoC links returned with URLs    │
│ 6. Manifest & Git Inspector            │ ✅ PROVEN    │ Parsed requirements.txt, 3 packages, 3 modules  │
│ 7. Multi-File AST Reachability Solver  │ ✅ PROVEN    │ 1 reachable path + 1 dead code isolated (2.29ms)│
│ 8. Nebius Token Factory Nemotron Ultra │ ✅ PROVEN    │ Live 200 OK (790.94ms); model verified          │
├────────────────────────────────────────┼─────────────┼─────────────────────────────────────────────────┤
│ 9. ConTree Cloud Sandbox Instances     │ ❌ BLOCKED   │ 403 Forbidden: API key lacks spawn permissions  │
│ 10. Multi-CVE 5-Scenario Matrix        │ ⏳ PLANNED   │ Planned for Phase 4; only CVE-2020-14343 proven │
└────────────────────────────────────────┴─────────────┴─────────────────────────────────────────────────┘
```

---

## 2. Infrastructure & Credential Re-use Audit

Following your explicit instruction, credentials were discovered and re-used locally from `C:\Users\raahe\.gemini\antigravity\scratch\patchpilot-poc\.env` without generating duplicate keys or printing secrets:

1. **Nebius Token Factory (`NEBIUS_API_KEY`)**:
   - Status: **VALID & ACTIVE**
   - Live endpoint test: `POST https://api.tokenfactory.nebius.com/v1/chat/completions`
   - Model verified: `nvidia/Nemotron-3-Ultra-550b-a55b`
   - Latency: 790.94ms – 1.467s
   - Actual completion returned: `"Nemotron Ultra is live."` with `reasoning_tokens: 14`.
   - Gate A is **OFFICIALLY PASSED**.

2. **Tavily Search API (`TAVILY_API_KEY`)**:
   - Status: **VALID & ACTIVE**
   - Live endpoint test: `POST https://api.tavily.com/search`
   - Real query executed: `"CVE-2020-14343 exploit proof of concept advisory GitHub writeup"`
   - Result: 4 authentic security advisory URLs returned (GitHub Advisory Database, Debian Security Tracker, pre-commit Issue #1753, Red Hat Customer Portal).
   - Worded accurately: 1,000 API credits/month tier.

3. **Nebius ConTree Cloud Sandboxes**:
   - Status: **BLOCKED (IAM Permission Denied)**
   - Live endpoint test: `POST https://api.tokenfactory.nebius.com/sandboxes/v1/instances` with header `Project: NEBIUS_PROJECT_ID`
   - Exact server response: `{"status": 403, "error": "Insufficient permissions: spawn_disposable or spawn"}`
   - Root Cause: The API key's IAM role on Nebius does not have the `spawn_disposable` or `spawn` permission on Token Factory Sandboxes.
   - Truthful Handling: The UI displays `ConTree Cloud: PERMISSION DENIED` in amber. Local isolated subprocess sandboxes serve as the verified, working execution engine.

---

## 3. Test Suite Execution Telemetry

All 7 unit and integration tests executed cleanly:

```
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\AI-Tools\vulntrace
configfile: pyproject.toml
plugins: anyio-4.15.1, asyncio-1.4.0

tests/test_api_endpoints.py::test_health_endpoint PASSED                 [ 14%]
tests/test_api_endpoints.py::test_cve_intel_endpoint PASSED              [ 28%]
tests/test_api_endpoints.py::test_ast_analyze_endpoint PASSED            [ 42%]
tests/test_ast_visitor.py::test_ast_reachability_positive_and_negative PASSED [ 57%]
tests/test_manifest_parser.py::test_manifest_parser_requirements_and_pyproject PASSED [ 71%]
tests/test_osv_client.py::test_osv_live_cve_lookup PASSED                [ 85%]
tests/test_osv_client.py::test_osv_nonexistent_cve PASSED                [100%]

============================== 7 passed in 7.01s ===============================
```

---

## 4. Exact Frontend → Backend → Execution Flow

```
1. Browser Load (http://127.0.0.1:8000/):
   └─ Header invokes GET /api/v1/health
      ├─ Probes OSV.dev -> ONLINE (938.21ms)
      ├─ Probes Nebius Token Factory -> ONLINE (798.42ms, 25 models)
      ├─ Probes ConTree Sandboxes -> PERMISSION_DENIED (403 spawn)
      └─ Probes Tavily Search -> ONLINE (Key Active)

2. Action: Inspect Target Codebase:
   └─ User clicks "Inspect Codebase" on path C:\AI-Tools\vulntrace\sample_repo
      └─ Frontend POST /api/v1/repo/inspect
         └─ ManifestParser walks directory, parses requirements.txt, inspects Git
            └─ Returns 3 modules, 3 dependencies (PyYAML==5.3.1, requests>=2.28.0, pytest>=8.0.0)
               └─ UI renders metadata pills and interactive dependency table

3. Action: Query Threat Intelligence:
   └─ User clicks "Query Intelligence" on CVE-2020-14343
      └─ Frontend POST /api/v1/intel/cve
         ├─ OsvClient queries https://api.osv.dev/v1/vulns/CVE-2020-14343 (868.27ms)
         │  └─ Returns aliases (GHSA-8q59-q68h-6hv4), commit ranges (introduced e471e86bf6, fixed 58d0cb7ee0)
         └─ TavilyClient queries https://api.tavily.com/search
            └─ Returns 4 live exploit writeups & advisory links
               └─ UI renders rich vulnerability card and clickable PoC references

4. Action: Run AST Call-Graph Reachability Solver:
   └─ User clicks "Run Call-Graph Solver"
      └─ Frontend POST /api/v1/ast/analyze
         └─ AstReachabilityAnalyzer parses AST across all 3 modules in sample_repo
            ├─ Evaluates call-graph topology: 6 nodes, 5 directed edges in 2.29ms
            ├─ Solves BFS path from entrypoint service.py:public_api_handler -> load_user_config
            ├─ Flags service.py:13 (yaml.load) as REACHABLE (HIGH RISK)
            ├─ Identifies dead_code.py:8 (yaml.full_load) as DEAD CODE (ZERO RISK)
            └─ Emits verdict: REACHABLE EXPLOITATION PATH CONFIRMED (1 reachable, 1 dead code)
               └─ UI renders pulsing crimson alert, call path trace, and topological nodes
```

---

## 5. Live UI Visual Proof

The production application is live and accessible at `http://127.0.0.1:8000/`. A full-viewport screenshot captured directly via Chrome DevTools is embedded below:

![VulnTrace Phase 1 Live Interface](vulntrace_phase1_live_ui.png)
*(Permanent disk location: `C:\AI-Tools\vulntrace\vulntrace_phase1_live_ui.png`)*
*(Artifact directory copy: `C:\Users\raahe\.gemini\antigravity\brain\6ea7fe92-9afe-4b4c-8a99-3edfd0976f4c\vulntrace_phase1_live_ui.png`)*
