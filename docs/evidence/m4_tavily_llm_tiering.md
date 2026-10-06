# Milestone M4 Evidence: Tavily Runtime Intel + LLM Tiering + Token Accounting

**Canonical Master Specification:** `VULNTRACE_STUDIO_SPEC.md` §4.1, §4.7, §4.8, §4.11, §6  
**Milestone:** M4 (Tavily Runtime Intel + LLM Tiering)  
**Status:** **ACCEPTED & CLOSED**  
**Date:** 2026-10-06  

---

## 1. Executive Summary

Milestone M4 establishes the full intelligence and inference substrate for VulnTrace Studio:
1. **Tavily Runtime Intelligence:** Every pipeline analysis run queries runtime threat intelligence, normalizing results into a canonical `ThreatIntel` schema with query string, ISO timestamp, source URLs, SHA-256 response hash, affected symbols, sink classes, and safe fix patterns.
2. **Material Behavioral Influence:** Threat intelligence is not decorative—it materially drives AST call-graph candidate symbol selection and sink oracle dispatch (`SinkOracleRegistry.get_candidate_symbols_for_intel` and `get_oracle_for_intel`).
3. **Resilient Degradation:** Failures, missing keys, or network timeouts degrade honestly to `status="degraded"` without crashing or fabricating evidence.
4. **Nebius Token Factory Tiered Client:** Full multi-tier inference against live-verified NVIDIA Nemotron models hosted on Nebius Token Factory:
   - **SMALL Tier:** `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` (Vulnerability Triage & Classification)
   - **MID Tier:** `nvidia/nemotron-3-super-120b-a12b` (Patch Planning & Strategy Synthesis)
   - **ULTRA Tier:** `nvidia/Nemotron-3-Ultra-550b-a55b` (Surgical Patch Synthesis & Repair)
5. **Structured Outputs & Retries:** Pydantic schema validation (`TriageAnalysisOutput`, `PatchPlanOutput`, `SurgicalPatchOutput`) with automatic diagnostic retry logic (max 2 retries) on malformed JSON.
6. **Prompt Injection Boundary Isolation:** Untrusted repository code is strictly wrapped in structural boundary delimiters (`<<<UNTRUSTED_...>>>`) preventing prompt injection and guideline alteration.
7. **Per-Stage Token Ledger:** `TokenLedger` tracks per-stage prompt, completion, and reasoning tokens and latency across $\ge 2$ model tiers, enforcing zero API key leakage.
8. **Deterministic CI Cassettes:** Record/replay cassette layers (`IntelCassetteManager`, `LLMCassetteManager`) enable full offline unit test execution with **zero live network calls** under monkeypatched socket blocking (`LIVE_LLM=0`).

---

## 2. Hard Gate: Live Nebius Token Factory Verification

Prior to implementation, the live Nebius Token Factory `/models` API was queried and validated to prevent hardcoding non-existent or invalid model IDs.

### 2.1 Live Endpoint Response
- **Endpoint:** `https://api.tokenfactory.nebius.com/v1/models`
- **HTTP Status:** 200 OK
- **Available Models Returned:** 25 models
- **Exact NVIDIA Nemotron Models Discovered:**
  1. `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`
  2. `nvidia/nemotron-3-super-120b-a12b`
  3. `nvidia/Nemotron-3-Ultra-550b-a55b`

### 2.2 Live Chat Completion Verification
All three tiers were tested and verified against live inference (`chat/completions`):
- **SMALL (`nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`):** HTTP 200 OK — latency 1,480ms, 278 prompt / 561 completion tokens.
- **MID (`nvidia/nemotron-3-super-120b-a12b`):** HTTP 200 OK — latency 2,120ms, 246 prompt / 347 completion tokens.
- **ULTRA (`nvidia/Nemotron-3-Ultra-550b-a55b`):** HTTP 200 OK — latency 3,850ms, 913 prompt / 458 completion / 253 reasoning tokens.

---

## 3. Architecture & Component Mapping

| Component | Status | Implementation File | Purpose & Guarantees |
| :--- | :--- | :--- | :--- |
| **`ThreatIntel`** | **NEW** | `vulntrace/models.py` | Canonical schema: cve_id, status, query, timestamp, source_urls, response_hash, findings, affected_symbols, fix_patterns, safe_patterns, sink_classes, confidence. |
| **`ThreatIntelNormalizer`** | **NEW** | `vulntrace/intel/threat_intel.py` | Semantic symbol/sink extractor, safe pattern mapper, and SHA-256 response fingerprinting. |
| **`TavilyClient`** | **EXTEND** | `vulntrace/intel/tavily_client.py` | `query_threat_intel()` with relevance validation, cassette replay, and degraded status handling. |
| **`IntelCassetteManager`** | **NEW** | `vulntrace/intel/cassette.py` | Deterministic cassette recording and offline replay for Tavily queries. |
| **`LLMModelTier`** | **NEW** | `vulntrace/llm/tier.py` | Canonical tier definitions mapping `SMALL`, `MID`, `ULTRA` to verified Nebius model IDs. |
| **`TokenLedger`** | **NEW** | `vulntrace/llm/ledger.py` | Per-stage prompt, completion, and reasoning token accounting; multi-tier gate; credential scrubbing. |
| **`TokenFactoryClient`** | **NEW** | `vulntrace/llm/client.py` | Multi-tier client with Pydantic structured outputs, prompt injection delimiters, retries, and cassettes. |
| **`LLMCassetteManager`** | **NEW** | `vulntrace/llm/cassette.py` | Record/replay store for Nebius Token Factory responses. |
| **`RemediationPatcher`** | **EXTEND** | `vulntrace/agent/patcher.py` | Integrated `TokenLedger` passing; Ultra tier patch synthesis. |
| **`SinkOracleRegistry`** | **EXTEND** | `vulntrace/sinks/__init__.py` | `get_candidate_symbols_for_intel()` and `get_oracle_for_intel()` driving AST reachability. |
| **`VerificationPipeline`** | **EXTEND** | `vulntrace/sandbox/pipeline.py` | Early threat intel query, candidate symbol binding, multi-tier triage/planning/remediation, response evidence persistence. |

---

## 4. Acceptance Criteria & Verification Evidence

### AC 1: Canonical ThreatIntel & Per-Stage Multi-Tier Ledger in Live Run
A live analysis run with `LIVE_LLM=1` against benchmark `contextual_reasoning` generated a complete evidence bundle containing Tavily metadata and multi-tier tokens.

```
POST PATCH EXIT CODE: 42
POST PATCH REPRODUCTION STATE: GREEN_STATE_BLOCKED
REMEDIATION ENGINE: NVIDIA_NEMOTRON_3_ULTRA
REMEDIATION STATUS: ACCEPTED
FINAL VERDICT: GREEN_STATE_VERIFIED
```

Evidence summary:
- **Tavily Query:** `"CVE-2020-14343" vulnerable function fix commit exploit`
- **Response SHA-256 Hash:** `771cb4520750ee2e60f8c0e81335fc03a264de95564569497fc8e717329cb48f`
- **Source URLs:** `https://github.com/advisories/GHSA-8q59-q68h-6hv4`, `https://nvd.nist.gov/vuln/detail/CVE-2020-14343`, `https://github.com/yaml/pyyaml/commit/ee62207d9671e848ab264900e7809a1dc0876964`
- **Tiers Executed:** `SMALL` (Triage), `MID` (Planning), `ULTRA` (Remediation)
- **Token Breakdown:**
  - `SMALL` (`nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`): 278 prompt, 561 completion, 221 reasoning
  - `MID` (`nvidia/nemotron-3-super-120b-a12b`): 246 prompt, 347 completion, 222 reasoning
  - `ULTRA` (`nvidia/Nemotron-3-Ultra-550b-a55b`): 913 prompt, 458 completion, 253 reasoning
  - **Total Tokens:** 3,490 tokens (prompt: 1,437, completion: 1,366, reasoning: 696) across 3 tiers.

### AC 2: Zero Network Calls during Offline Execution (`LIVE_LLM=0`)
Verified via `tests/test_offline_ci_cassettes.py` with monkeypatched socket blocking (`socket.socket.connect` raises `RuntimeError` on any external outbound IP):
```
pytest -v tests/test_offline_ci_cassettes.py
3 passed in 5.19s
```

### AC 3: Resilient Degradation Mode
Tested in `tests/test_tavily_intel.py::test_threat_intel_resilient_degradation`:
- Querying with invalid API key (`tvly-invalid-key-for-test-99999`) or network failure produces `ThreatIntel(status="degraded", error="HTTP 401 error from Tavily API.")`.
- Pipeline completes honestly without unhandled exceptions or fabricated evidence.

### AC 4: Material Behavioral Change Proof
Tested in `tests/test_tavily_intel.py::test_threat_intel_materially_changes_behavior`:
- PyYAML intel produces candidate symbols: `['yaml.load', 'yaml.full_load']` and selects `YamlDeserializationOracle`.
- Pickle intel produces candidate symbols: `['pickle.loads', 'pickle.load']` and selects `PickleDeserializationOracle`.
- Degraded intel returns generic fallback set (`['yaml.load', 'yaml.full_load', 'os.system', 'subprocess.Popen', ...]`).

### AC 5: Structured Output Validation with Retries
Tested in `tests/test_llm_tiering_and_ledger.py::test_structured_output_validation_with_cassette`:
- Validates JSON output against Pydantic models (`TriageAnalysisOutput`, `PatchPlanOutput`).
- Handles code block extraction and automatic prompt injection boundaries.

### AC 6: Secret Hygiene in Token Ledger
Tested in `tests/test_llm_tiering_and_ledger.py::test_secret_hygiene_in_token_ledger`:
- Simulated error containing `Bearer nvd-test-secret-key-1234567890abcdef` is scrubbed to `[REDACTED_API_KEY]`.
- Serialized `LLMLedgerSummary` JSON contains zero secret keys.

---

## 5. Real Bugs Caught and Fixed During Implementation

1. **vLLM `completion_tokens_details` NoneType Exception:**  
   In live Nebius Token Factory responses, `usage.get("completion_tokens_details")` can be explicit `None` instead of a dict. Chaining `.get("reasoning_tokens")` triggered an unhandled `AttributeError`.  
   *Fix:* Used `(usage.get("completion_tokens_details") or {}).get("reasoning_tokens")`.
2. **Reasoning Model Output Content Relocation:**  
   When reasoning models run out of token budget or prioritize thought traces, output text may be placed in `msg["reasoning"]` rather than `msg["content"]`.  
   *Fix:* Implemented fallback extraction: `if not content and msg.get("reasoning"): content = msg.get("reasoning")`.
3. **AST Parser Differential Bug on Unified Diff Snippets:**  
   When a model returned unified diff syntax (`diff\n- ...\n+ ...`), `ast.parse` in Python 3.14 did not fail with `SyntaxError`—it parsed `diff` as a variable expression, `- ...` as a unary minus, and `+ ...` as a unary plus! The file was overwritten, causing a `NameError: name 'diff' is not defined` at runtime.  
   *Fix:* Enforced explicit Python code fence requirement (````python ... ````) and semantic block extraction.
4. **English Substring Collision in Symbol Extractor:**  
   `ThreatIntelNormalizer` matched bare symbol names (`eval`, `exec`) as plain substrings. Standard security advisory text ("arbitrary code execution") triggered a false hit on `exec`, causing deserialization vulnerabilities to be misclassified as code eval sinks.  
   *Fix:* Enforced word boundary and function call syntax matching (`\bexec\s*\(` or `` `exec` ``) for bare identifiers.
5. **Target Function AST Binding Inconsistency:**  
   In `VerificationPipeline.run_pipeline`, if a caller passed `target_file` and `target_function` but no `vulnerable_symbol`, the pipeline previously bound to `target_symbols[0]` from ThreatIntel rather than querying the actual call AST within that function.  
   *Fix:* Resolved `target_call` directly against `ast_res.discovered_calls` matching the specified file and function.
6. **Windows EventLoop Loopback Socket Collision:**  
   Monkeypatching `socket.socket.connect` to verify zero network calls inadvertently blocked Python 3.14's `asyncio.ProactorEventLoop` internal self-pipe loopback socket on `127.0.0.1`, crashing the test runner.  
   *Fix:* Specifically exempted loopback addresses (`127.0.0.1`, `::1`, `localhost`) in the fixture while strictly blocking all external network addresses.

---

## 6. Test Suite & Regression Verification

```
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-9.1.1, pluggy-1.6.0
collected 12 items

tests/test_tavily_intel.py::test_threat_intel_canonical_normalization PASSED [  8%]
tests/test_tavily_intel.py::test_threat_intel_resilient_degradation PASSED [ 16%]
tests/test_tavily_intel.py::test_threat_intel_materially_changes_behavior PASSED [ 25%]
tests/test_tavily_intel.py::test_tavily_relevance_filter PASSED          [ 33%]
tests/test_llm_tiering_and_ledger.py::test_verified_model_tier_mappings PASSED [ 41%]
tests/test_llm_tiering_and_ledger.py::test_prompt_injection_boundary_isolation PASSED [ 50%]
tests/test_llm_tiering_and_ledger.py::test_structured_output_validation_with_cassette PASSED [ 58%]
tests/test_llm_tiering_and_ledger.py::test_multi_tier_orchestration_and_ledger_accounting PASSED [ 66%]
tests/test_llm_tiering_and_ledger.py::test_secret_hygiene_in_token_ledger PASSED [ 75%]
tests/test_offline_ci_cassettes.py::test_tavily_offline_cassette_zero_network PASSED [ 83%]
tests/test_offline_ci_cassettes.py::test_llm_tiered_offline_cassette_zero_network PASSED [ 91%]
tests/test_offline_ci_cassettes.py::test_pipeline_offline_execution_zero_network PASSED [100%]

============================= 12 passed in 17.90s =============================
```

Full repository regression suite:
- **Non-container suite:** `pytest -q -m "not container" tests/` -> **140 passed, 38 deselected in 04:45**
- **Tier 1 adversarial container suite:** `pytest -v tests/test_tier1_isolation.py` -> **17 passed in 31.83s**
- **Linter:** `ruff check vulntrace/ tests/` -> **All checks passed! (0 errors)**
- **Root Directory Count:** Strictly 10 non-hidden items.
