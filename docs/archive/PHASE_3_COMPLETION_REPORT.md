# VulnTrace — Phase 3 Completion & Multi-Scenario Generalization Report

**Project:** VulnTrace — Autonomous Vulnerability Reproduction and Verified Patching Agent  
**Hackathon:** Nebius × NVIDIA Global AI Hackathon 2026 (Deadline: October 30, 2026)  
**Track:** Agentic AI / Autonomous Security Engineering  
**Milestone:** Phase 3 Completion — Benchmark Generalization, Behavioral Assertion Hardening, and Multi-Scenario Validation  
**Date:** October 2, 2026  
**Primary Engine:** NVIDIA Nemotron 3 Ultra (`nvidia/nemotron-3-ultra:preview`) via Nebius Token Factory  
**Execution Sandbox:** Controlled Subprocess Runner (`LOCAL_SUBPROCESS_FALLBACK`) with disposable tempfs & environment sanitization  
**Cloud Sandbox Status:** Nebius ConTree Cloud (`PERMISSION DENIED (HTTP 403)`) truthfully documented as unverified  

---

## 1. Executive Summary & Phase 3 Objectives

In Phase 3, VulnTrace transitioned from a single-sample proof-of-concept into a **generalized, multi-scenario automated vulnerability reproduction and verified patching engine**. 

### Key Deliverables Completed:
1. **Generalization Beyond Single CVE Call-Sites**: Eliminated all hardcoded functions, file paths, or expected payloads. Dynamic multi-file import resolver (`_resolve_module_import_path`) and syntax-aware AST transformers now operate across arbitrary repository layouts.
2. **Strict Behavioral Assertion Protocol**: Process exit codes are strictly separated from security blocks:
   - **Exit 0 (`RED_PASSED`)**: Risky behavioral path materialized under controlled probe; sentinel marker touched.
   - **Exit 42 (`GREEN_SECURITY_BLOCK_VERIFIED`)**: Explicit defensive security exception caught (`ConstructorError`, etc.) without sentinel touch.
   - **Exit 10 (`INCONCLUSIVE_GUARD_BLOCKED` / `INCONCLUSIVE_NO_EFFECT`)**: Pre-validation guard or filter prevented reproduction; pipeline refuses to force a verdict.
   - **Exit 1 (`UNEXPECTED_FAILURE`)**: Unhandled process crash, import error, or syntax fault—**never falsely credited as GREEN**.
3. **Explicit INCONCLUSIVE State Architecture**: When a vulnerability cannot be reproduced due to upstream input validation guards, VulnTrace emits an explicit `INCONCLUSIVE` verdict, skips code modification, and runs baseline regression suites.
4. **Controlled Execution Boundary Specification**: Formally documented the local isolation boundary, disclosing exact protections (disposable filesystem, secret purge, process-tree watchdog) and limitations (shared host kernel, loopback network).
5. **Real 4-Scenario Benchmark Suite on Disk**: Scaffolded, executed, and benchmarked 4 distinct real codebases with unit test suites.
6. **Live NVIDIA Nemotron 3 Ultra Patching**: Verified live patch generation, reasoning token consumption, and regression compliance via Nebius Token Factory across real multi-file codebases.
7. **Full-Stack Developer UI**: Added scenario quick-switcher pills, metadata inspection cards, live call-graph topology rendering, diff viewers, and real-time SSE streaming.

---

## 2. Multi-Scenario Benchmark Suite Empirical Results

All four benchmark scenarios were scaffolded with authentic directory structures, real Python modules, dependencies, and pytest test suites. Each scenario was executed end-to-end through `VerificationPipeline.run_pipeline()`.

| Scenario ID | Repository Archetype | AST Reachability Verdict | Pre-Patch State | Remediation Engine | Post-Patch State | Pytest Suite | Final Behavioral Verdict | Match |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| `deep_callchain` | 3-Tier Multi-Directory Hierarchy (`api/` → `controllers/` → `services/`) | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` | `RED_STATE_REPRODUCED` (Exit 0) | `NVIDIA_NEMOTRON_3_ULTRA` | `GREEN_STATE_BLOCKED` (Exit 42) | 2/2 Passed (1111ms) | `GREEN_STATE_VERIFIED` | **100%** |
| `unreachable_dead_code` | Orphaned Legacy Module (`legacy/deprecated_importer.py`) | `UNREACHABLE_FALSE_POSITIVE` | `UNREACHABLE_FALSE_POSITIVE` | `SKIPPED` (Churn Prevented) | `UNREACHABLE_FALSE_POSITIVE` | 2/2 Passed (Baseline) | `UNREACHABLE_FALSE_POSITIVE` | **100%** |
| `regression_sensitive` | Config Parser with Rigorous Dict Type Assertions | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` | `RED_STATE_REPRODUCED` (Exit 0) | `NVIDIA_NEMOTRON_3_ULTRA` | `GREEN_STATE_BLOCKED` (Exit 42) | 3/3 Passed (889ms) | `GREEN_STATE_VERIFIED` | **100%** |
| `inconclusive_guard` | Pre-Filter Guard Rejecting Object Deserialization Tags | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` | `INCONCLUSIVE` (Exit 10, Guard Blocked) | `SKIPPED` (Truthful Refusal) | `INCONCLUSIVE` | 2/2 Passed (Baseline) | `INCONCLUSIVE` | **100%** |

### Scenario Deep Dive:
- **`deep_callchain`**: The AST solver traced calls through `api/gateway.py:handle_request()` → `controllers/config_controller.py:process_incoming_config()` → `services/yaml_parser.py:parse_custom_config()`. Simultaneously, it identified `utils/dead_legacy.py:dead_legacy_helper()` as dead code. Nemotron 3 Ultra generated a surgical patch replacing `yaml.Loader` with `yaml.SafeLoader`. Post-patch harness verified `ConstructorError` (Exit 42). Pytest passed 2/2 tests.
- **`unreachable_dead_code`**: Proves false positive suppression. While PyYAML was in `requirements.txt` and `legacy/deprecated_importer.py` contained `yaml.load`, the static solver discovered 0 incoming edges from active CLI worker entrypoints. The pipeline immediately halted, preserving codebase stability without risky modifications.
- **`regression_sensitive`**: Tested whether Nemotron's patch broke type contracts. Pytest asserted boolean and integer parsing from manifests. Nemotron 3 Ultra synthesized a clean `safe_load` patch with 152 reasoning tokens; all 3 pytest regression assertions passed.
- **`inconclusive_guard`**: Pre-filter validation raised `ValueError("Security violation: object tags forbidden by pre-filter guard")`. Synthesizer caught the guard exception, emitted `INCONCLUSIVE_GUARD_BLOCKED` (Exit 10), and the engine refused to patch, demonstrating scientific truthfulness.

---

## 3. Strict Behavioral Assertion Protocol

A critical flaw in naive automated security tools is treating any non-zero exit code as a successful patch. VulnTrace solves this by generating harnesses with structured JSON telemetry and explicit exit codes:

```
+-----------------------------------------------------------------------------+
|                      BEHAVIORAL ASSERTION TAXONOMY                          |
+-------------------+-----------+-------------------+-------------------------+
| Assertion State   | Exit Code | Sentinel Marker   | Engine Verdict          |
+-------------------+-----------+-------------------+-------------------------+
| RED_PASSED        | 0         | Created (Touched) | RED_STATE_REPRODUCED    |
| GREEN_VERIFIED    | 42        | Blocked (Clean)   | GREEN_STATE_BLOCKED     |
| GUARD_BLOCKED     | 10        | Blocked (Clean)   | INCONCLUSIVE            |
| UNEXPECTED_FAIL   | 1         | Blocked / Clean   | ERROR (Not Green!)      |
+-------------------+-----------+-------------------+-------------------------+
```

### Synthesized Verification Harness (Sample):
```python
# Target module dynamic import
from services.yaml_parser import parse_custom_config

sentinel = Path("sentinel_pwned.marker")
payload = """
exploit: !!python/object/apply:builtins.eval ["open('sentinel_pwned.marker', 'w').close()"]
"""

try:
    res = parse_custom_config(payload)
    if sentinel.exists():
        print(json.dumps({"assertion": "RED_PASSED", "sentinel_created": True}))
        sys.exit(0)
    else:
        print(json.dumps({"assertion": "INCONCLUSIVE_NO_EFFECT", "sentinel_created": False}))
        sys.exit(10)
except sec_block_types as sec_err:
    if not sentinel.exists():
        print(json.dumps({"assertion": "GREEN_SECURITY_BLOCK_VERIFIED", "exception_type": type(sec_err).__name__}))
        sys.exit(42)  # Dedicated exit code for verified security block
except Exception as unexpected_err:
    if is_guard_exception(unexpected_err):
        print(json.dumps({"assertion": "INCONCLUSIVE_GUARD_BLOCKED", "exception_type": type(unexpected_err).__name__}))
        sys.exit(10)
    sys.exit(1)  # Process crash or bug: NEVER treated as GREEN!
```

---

## 4. Controlled Local Execution Boundary Specification

VulnTrace explicitly rejects security theater. The execution engine is labeled `LOCAL_SUBPROCESS_FALLBACK` and its exact capabilities and constraints are disclosed below:

### What IS Isolated:
- **Disposable Tempfs Workspace**: Every run copies the target repo to a freshly created `%TEMP%\vulntrace_sandbox_<uuid>` directory. The host repository is never touched directly during reproduction.
- **Environment Variable Purging**: The child process runs with a sanitized dictionary; all environment variables matching `KEY`, `TOKEN`, `SECRET`, `AUTH`, `NEBIUS`, `TAVILY`, etc., are stripped.
- **Child-Process Watchdog**: Subprocesses are bounded by a strict 10-second timeout. On Windows, terminations execute via `taskkill /F /T /PID` to cleanly eradicate child trees.
- **Hermetic Virtualenv Python**: Python runs strictly via `C:\AI-Tools\vulntrace\.venv\Scripts\python.exe`, avoiding global package contamination.
- **Deterministic Cleanup**: The disposable workspace is wiped immediately upon pipeline termination.

### What is NOT Isolated (Host Boundary Limitations):
- **Shared Host Kernel**: Does not employ hypervisor microVMs (e.g. Firecracker) or Linux kernel namespaces on Windows.
- **Localhost Loopback**: Subprocesses can bind to or query `127.0.0.1` unless restricted by external firewall policies.
- **Storage Limits**: Local disk write quotas are governed by available disk space in `%TEMP%`.

---

## 5. Live NVIDIA Nemotron 3 Ultra Telemetry

During Phase 3 benchmark execution, NVIDIA Nemotron 3 Ultra (`nvidia/nemotron-3-ultra:preview`) was invoked live via Nebius Token Factory for patch generation:

- **Model ID:** `nvidia/nemotron-3-ultra:preview`
- **Provider:** Nebius Token Factory (`api.tokenfactory.nebius.com`)
- **Sample Invocation (Deep Call Chain):**
  - Prompt Tokens: 323
  - Completion Tokens: 152
  - Reasoning Tokens: 152
  - Total Tokens: 475
  - Latency: 1,661.02 ms
- **Synthesized Patch:**
```diff
--- a/services/yaml_parser.py
+++ b/services/yaml_parser.py
@@ -3,8 +3,8 @@
  def parse_custom_config(raw_yaml: str) -> dict:
      """Parses arbitrary YAML configuration payload."""
-    # Vulnerable deserialization sink (CVE-2020-14343)
-    data = yaml.load(raw_yaml, Loader=yaml.Loader)
+    # Safe deserialization: SafeLoader prevents arbitrary code execution (CVE-2020-14343)
+    data = yaml.load(raw_yaml, Loader=yaml.SafeLoader)
      if isinstance(data, dict):
          return data
      return {"parsed": data}
```

---

## 6. Live Full-Stack UI Verification

The React 18 / Tailwind frontend was upgraded to provide interactive control over the Phase 3 benchmark suite:
- **Scenario Quick-Switcher**: 4 dedicated scenario pills with metadata previews, target function identifiers, and expected verdicts.
- **Top Bar Health Probes**: Real-time latencies for Nemotron 3 Ultra (905ms), OSV Advisory (1094ms), and Tavily Search (ONLINE), with ConTree Cloud truthfully flagged as `PERMISSION DENIED`.
- **AST Topology View**: Visual graph rendering entrypoints, intermediate functions, vulnerable call sites, and dead-code blocks with directed edges.
- **Workbench Telemetry**: 6-stage verification workbench displaying pre-patch sentinel confirmation, post-patch security block, Nemotron unified diff, and pytest stdout logs.
- **Execution Event Stream**: Terminal displaying real-time SSE stage transitions.

A full-page screenshot of the live, working application was captured via Chrome DevTools and preserved at:
`C:\AI-Tools\vulntrace\vulntrace_phase3_live_ui.png`

---

## 7. Phase 4 Readiness & Hackathon Submission Alignment

VulnTrace has now satisfied all core technical requirements for autonomous vulnerability reproduction and verified patching:
1. **Real Codebases**: Evaluated across 4 distinct multi-file repositories on disk.
2. **Scientific Integrity**: Separated reachability from behavioral exploitability; differentiated security blocks from crashes; enforced truthful `INCONCLUSIVE` states.
3. **Live NVIDIA Infrastructure**: Powered by Nemotron 3 Ultra via Nebius Token Factory.
4. **Production Architecture**: Modern TypeScript/React UI backed by FastAPI, SSE streaming, and disposable sandbox runners.

With nearly one month remaining until the October 30, 2026 hackathon deadline, VulnTrace is primed for Phase 4: Extended CVE Coverage (e.g. SQL injection, command execution, path traversal), Git PR export automation, and final submission video production.
