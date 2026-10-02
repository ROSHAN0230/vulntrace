# VulnTrace — Live End-to-End Execution Evidence

**Audit Timestamp:** October 2, 2026, 22:14:45 UTC+05:30  
**Target Repository:** `benchmarks/contextual_reasoning`  
**Target Vulnerability:** `CVE-2020-14343` (`PyYAML` unsafe object deserialization)  
**Target Call Site:** `service/custom_loader.py:parse_app_config()`  
**Vulnerable Symbol:** `yaml.load`  
**Verification Verdict:** **`GREEN_STATE_VERIFIED`**  
**Sandbox Engine:** `LOCAL_SUBPROCESS_FALLBACK` (Disposable copy, isolated environment, timeout watchdog)

---

## 1. Executive Summary

This document provides sanitized, empirical runtime telemetry proving that the submitted VulnTrace security engine invokes and incorporates **Tavily Search API** (with strict automated CVE-relevance validation) and **Nebius Token Factory (NVIDIA Nemotron 3 Ultra)** in a live, defensive verification pipeline.

```
       [AST Call-Graph Traversal]
                   │
                   ▼
  [Tavily Real-Time Threat Intelligence]
    Endpoint: https://api.tavily.com/search
    Query: "CVE-2020-14343" exploit proof of concept advisory GitHub writeup
    Raw Results Returned: 6
    Strict Relevance Filter: 5 retained, 1 excluded
    Retention Rate: 5 / 6 verified relevant to CVE-2020-14343 (2,963ms)
                   │
                   ▼
   [Pre-Patch Sandbox Behavioral Verification]
    Isolated Runner: harness_verify.py
    Reproduction State: RED_STATE_REPRODUCED
    Sentinel Marker: created on disk (Exit 0)
                   │
                   ▼
  [NVIDIA Nemotron 3 Ultra Contextual Remediation]
    Endpoint: https://api.tokenfactory.nebius.com/v1/chat/completions
    Model: nvidia/Nemotron-3-Ultra-550b-a55b
    Context: Target code + verified CVE-2020-14343 advisory sources
    Tokens: 1,410 total (377 reasoning tokens)
    Patch Generated: Replaces unsafe Loader with AppSafeLoader
                   │
                   ▼
   [Post-Patch Sandbox Behavioral Verification]
    Re-test in isolated runner: harness_verify.py
    Sentinel Marker: NOT created (0 markers on disk)
    Defensive Block: ConstructorError caught
    Reproduction State: GREEN_STATE_BLOCKED (Exit 42)
                   │
                   ▼
       [Full Regression Test Suite]
    Runner: pytest inside sandbox
    Result: 3 / 3 test cases PASSED (Exit 0)
    Custom Tag Handlers: !env_var preserved
                   │
                   ▼
   [Centralized Verdict: GREEN_STATE_VERIFIED]
```

---

## 2. Real-Time Threat Intelligence Telemetry (Tavily Search)

During Stage 0.5 of the verification pipeline, VulnTrace contacts the **Tavily Security Intelligence Search API** with an exact-quoted query. To maintain strict evidentiary integrity and prevent cross-CVE contamination, every raw search result is evaluated against a relevance check: it must explicitly reference the target `CVE-2020-14343` in its title, URL, or body content.

```json
{
  "provider": "Tavily Search API",
  "endpoint": "https://api.tavily.com/search",
  "http_status": "HTTP_200_OK",
  "query": "\"CVE-2020-14343\" exploit proof of concept advisory GitHub writeup",
  "latency_ms": 2963.5,
  "raw_results_count": 6,
  "retained_relevant_count": 5,
  "filtered_out_count": 1,
  "relevance_criterion": "Must explicitly mention target 'CVE-2020-14343' in title, URL, or body content",
  "retained_sources": [
    {
      "title": "GitHub - saina15/cve-2020-14343-lab: Controlled vulnerability research and reproduction lab for CVE-2020-14343 in PyYAML",
      "url": "https://github.com/saina15/cve-2020-14343-lab"
    },
    {
      "title": "Improper Input Validation in PyYAML · CVE-2020-14343 · GitHub Advisory Database",
      "url": "https://github.com/advisories/GHSA-8q59-q68h-6hv4"
    },
    {
      "title": "CVE-2020-14343",
      "url": "https://security-tracker.debian.org/tracker/CVE-2020-14343"
    },
    {
      "title": "CVE-2020-14343 - RCE vulnerability in pyYAML dependency · Issue #1753 · pre-commit/pre-commit",
      "url": "https://github.com/pre-commit/pre-commit/issues/1753"
    },
    {
      "title": "NVD-CVE-2020-14343",
      "url": "https://nvd.nist.gov/vuln/detail/cve-2020-14343"
    }
  ],
  "filtered_out_reasons": [
    "Excluded: 'Cobham Satcom's maritime VSAT router has a public exploit and no fix...' (https://severitydaily.com/cobham-satcom-vsat7090-cve-2026-83772-no-fix-no-vendor-reply) does not reference target CVE-2020-14343"
  ]
}
```

---

## 3. Pre-Patch Sandbox Execution (RED STATE)

The synthesizer generates an isolated verification harness (`harness_verify.py`) containing a benign sentinel payload. The pre-patch run executes inside a disposable workspace copy with purged environment secrets.

```json
{
  "exit_code": 0,
  "latency_ms": 144.29,
  "sentinel_created": true,
  "reproduction_state": "RED_STATE_REPRODUCED",
  "assertion_result": "RED_PASSED",
  "parent_validated": true,
  "validation_notes": "Parent verified: exit code 0, physical sentinel marker created on disk.",
  "sandbox_engine": "LOCAL_SUBPROCESS_FALLBACK"
}
```

---

## 4. Model Inference Telemetry (Nebius Token Factory / Nemotron)

VulnTrace injects the target source code together with the **verified CVE-2020-14343 threat references** into the prompt sent to **NVIDIA Nemotron 3 Ultra** via the Nebius Token Factory chat completions endpoint.

```json
{
  "provider": "Nebius Token Factory",
  "endpoint": "https://api.tokenfactory.nebius.com/v1/chat/completions",
  "model": "nvidia/Nemotron-3-Ultra-550b-a55b",
  "latency_ms": 2745.39,
  "tokens_used": 1410,
  "reasoning_tokens": 377,
  "validation_status": "ACCEPTED",
  "synthesized_engine": "NVIDIA_NEMOTRON_3_ULTRA"
}
```

### Contextual Remediation Diff Produced by Nemotron:
```diff
--- a/service/custom_loader.py
+++ b/service/custom_loader.py
@@ -18,8 +18,8 @@
     Must maintain support for !env_var custom tag.
     Vulnerable sink: currently uses unsafe yaml.load with default Loader.
     """
-    # Vulnerable sink (CVE-2020-14343)
-    data = yaml.load(raw_yaml, Loader=yaml.Loader)
+    # Fixed: use AppSafeLoader (extends SafeLoader) to prevent arbitrary code execution
+    data = yaml.load(raw_yaml, Loader=AppSafeLoader)
     if isinstance(data, dict):
         return data
-    return {"config": data}
+    return {"config": data}
```

> **Why Contextual Reasoning Matters:** A blind deterministic codemod (`yaml.safe_load`) strips the custom `!env_var` constructor registered on `AppSafeLoader`, which causes subsequent regression test suites to fail. NVIDIA Nemotron 3 Ultra reasoned over the surrounding AST context, preserved the custom loader, and bound the safe loader base class.

---

## 5. Post-Patch Sandbox Execution (GREEN STATE)

The modified module is re-tested in the disposable sandbox. The exploit is rejected with `ConstructorError`, the sentinel file is not created, and the harness emits exit code 42.

```json
{
  "exit_code": 42,
  "latency_ms": 131.9,
  "sentinel_created": false,
  "reproduction_state": "GREEN_STATE_BLOCKED",
  "assertion_result": "GREEN_SECURITY_BLOCK_VERIFIED",
  "exception_type": "ConstructorError",
  "parent_validated": true,
  "validation_notes": "Parent verified: exit code 42, zero sentinel markers, typed security exception evaluated."
}
```

---

## 6. Regression Test Suite Execution

The application's regression test suite (`tests/test_custom_loader.py`) is executed inside the sandbox to verify zero business-logic regressions.

```text
============================= test session starts =============================
collecting ... collected 3 items

tests/test_custom_loader.py::test_standard_yaml PASSED                   [ 33%]
tests/test_custom_loader.py::test_custom_env_tag PASSED                  [ 66%]
tests/test_custom_loader.py::test_nested_dictionary PASSED               [100%]

============================== 3 passed in 0.05s ==============================
```

```json
{
  "passed": true,
  "test_count": 3,
  "exit_code": 0,
  "latency_ms": 1080.93
}
```

---

## 7. Repeatability Audit Across Consecutive Live Runs

Consecutive live runs were executed to evaluate repeatability. Both runs produced the same observed verification outcome:

| Metric | Run 1 | Run 2 | Observed Outcome |
| :--- | :--- | :--- | :--- |
| **Pipeline Verdict** | `GREEN_STATE_VERIFIED` | `GREEN_STATE_VERIFIED` | Verified across both runs |
| **Pre-Patch State** | `RED_STATE_REPRODUCED` (Exit 0) | `RED_STATE_REPRODUCED` (Exit 0) | Verified across both runs |
| **Tavily Raw Results** | 6 raw results | 6 raw results | Consistent search response |
| **Tavily Retained Relevant** | 5 retained (`CVE-2020-14343`) | 5 retained (`CVE-2020-14343`) | Consistent relevance filter |
| **Tavily Excluded Results** | 1 excluded (`CVE-2026-83772`) | 1 excluded (`CVE-2026-83772`) | 100% irrelevant suppression |
| **Nemotron Model** | `nvidia/Nemotron-3-Ultra-550b-a55b` | `nvidia/Nemotron-3-Ultra-550b-a55b` | Same model queried |
| **Post-Patch State** | `GREEN_STATE_BLOCKED` (Exit 42) | `GREEN_STATE_BLOCKED` (Exit 42) | Verified across both runs |
| **Regressions Passed** | 3 / 3 (100%) | 3 / 3 (100%) | Verified across both runs |
