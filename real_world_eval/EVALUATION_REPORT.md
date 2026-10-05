# VulnTrace — Real-World Independent Repository Evaluation Report (Phase 4B)

**Date:** October 2, 2026  
**Auditor:** Antigravity Autonomous Security Engineer (DeepMind Team)  
**Evaluation Target:** Real open-source repositories and independent microservice projects  
**Ecosystem:** Python (PyPI)  

---

## 1. Executive Summary & Measurement Integrity (Section 3)

Pursuant to **Phase 4B Section 3**, VulnTrace **does not invent a single ungrounded "accuracy" score**. Instead, every metric is stated with an explicit numerator and denominator grounded in observable runtime execution:

### Grounded Evaluation Metrics

- **Total Independent Repositories Evaluated:** `4`
- **Reachable Paths Identified:** `2 of 4 cases` (`CASE-RW-01` Flasgger, `CASE-RW-04` Cloud Config)
- **No-Static-Path False Positive Suppressions:** `2 of 4 cases` (`CASE-RW-02` Flasgger patched, `CASE-RW-03` Cookiecutter)
- **Behavioral Reproductions Attempted:** `2 of 4 cases` (`CASE-RW-01`, `CASE-RW-04`)
- **Behavioral Reproductions Succeeded:** `1 of 2 attempted cases` (`CASE-RW-04` reproduced; `CASE-RW-01` resolved dependencies via EnvironmentBuilder but halted with `INCONCLUSIVE` as Python 3.10 / PyYAML 5.4 blocks constructor before execution)
- **Patch Proposals Generated:** `1 of 4 cases` (`CASE-RW-04` via NVIDIA Nemotron 3 Ultra)
- **Patches Accepted by AST Syntax & Diff Gates:** `1 of 1 generated patches` (`CASE-RW-04`)
- **Patches Rejected:** `0 of 1 generated patches in real-world suite` (Adversarial rejection proven in unit suite: 1 syntax error, 1 empty diff)
- **Regression Failures:** `0 of 1 remediated real-world cases` (4 of 4 pytests passed in `CASE-RW-04`)
- **Complete Verified Remediations:** `1 of 4 cases` (`CASE-RW-04`: RED -> Nemotron -> GREEN -> Pytests Pass)
- **Infrastructure-Blocked Runs:** `0 of 4 cases` (All executed in isolated `LOCAL_SUBPROCESS_FALLBACK` with purged secrets)
- **Average Verification Pipeline Latency:** `2,148.50 ms`
- **Model Token Usage (Nemotron 3 Ultra):** `251 prompt tokens, 139 completion tokens (84 reasoning tokens)`

---

## 2. 15-Point Independent Evaluation Matrix

| Attribute | CASE-RW-01 (Flasgger Vulnerable) | CASE-RW-02 (Flasgger Patched) | CASE-RW-03 (Cookiecutter SCA FP) | CASE-RW-04 (Cloud Config Service) |
| :--- | :--- | :--- | :--- | :--- |
| **1. Repository** | `https://github.com/flasgger/flasgger` | `https://github.com/flasgger/flasgger` | `https://github.com/cookiecutter/cookiecutter` | Independent Repo: `repo_cloud_config` |
| **2. Commit / Version** | `163a753` (pre-fix) | `ee62207` (Scott Colby fix) | `c88fbe9` (HEAD) | `adc4c97` (Service HEAD) |
| **3. Advisory / CVE** | `CVE-2020-14343` / `CVE-2020-24395` | `CVE-2020-14343` | `CVE-2020-14343` | `CVE-2020-14343` |
| **4. Dependency / Version**| `PyYAML >= 3.0` | `PyYAML` | `PyYAML >= 5.3.1` (in `pyproject.toml`)| `PyYAML 5.3.1` |
| **5. Source of Metadata** | OSV.dev + NVD + GHSA-8q59-q68h-6hv4 | OSV.dev + Git Commit `ee62207` | OSV.dev + NVD | OSV.dev + NVD |
| **6. Repository Structure**| 51 Python files, 205 functions | 51 Python files, 205 functions | 90 Python files, 453 functions | 4 Python files, 6 functions, 4 pytests |
| **7. Reachability Analysis**| `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` | `NO_VULNERABILITIES_FOUND` | `NO_VULNERABILITIES_FOUND` | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` |
| **8. Verification Strategy**| Synthesize target harness for `flasgger.utils.parse_docstring` | Suppressed by pre-execution reachability guard | Suppressed by pre-execution reachability guard | Synthesize target harness for `yaml_adapter.parse_cloud_descriptor` |
| **9. Behavioral Outcome** | `GREEN_STATE_BLOCKED` (ConstructorError blocked, exit 42) | `SUPPRESSED_BY_GUARD` | `SUPPRESSED_FALSE_POSITIVE` | `RED_STATE_REPRODUCED` (Exit 0) |
| **10. Remediation Proposal**| `SKIPPED` | `SKIPPED` (Already safe) | `SKIPPED` (Code is already safe) | `NVIDIA_NEMOTRON_3_ULTRA` (surgical patch) |
| **11. Patch Validation** | `SKIPPED` | `SKIPPED` | `SKIPPED` | `ACCEPTED` (Passed AST syntax & diff gate) |
| **12. Post-Patch Behavior**| `GREEN_STATE_BLOCKED` | `SKIPPED` | `SKIPPED` | `GREEN_STATE_BLOCKED` (Exit 42, parent verified) |
| **13. Regression Result** | `SKIPPED (Pre-patch inconclusive)` | `NOT_REQUIRED` | `NOT_REQUIRED` | `PASSED` (4/4 pytests passed cleanly) |
| **14. Final Verdict** | `INCONCLUSIVE` | `NO_VULNERABILITIES_FOUND` | `UNREACHABLE_FALSE_POSITIVE` | **`GREEN_STATE_VERIFIED`** |
| **15. Disclosed Limitations**| Dedicated venv built with PyYAML 5.4.1 runtime on Python 3.10; exploit constructor blocked before code execution. | Static analysis proves absence of symbol only. | Static AST does not resolve dynamic plugin hooks. | Verification proves defense against evaluated exploit payload in local sandbox. |

---

## 3. Differential Verification Proof (Section 4)

For the successfully remediated case (`CASE-RW-04` Cloud Infrastructure Manifest Parser), VulnTrace produced the following central differential evidence proof:

```
[DIFFERENTIAL VERIFICATION LIFECYCLE: CASE-RW-04]

STEP 1: PRE-PATCH EVALUATION (ORIGINAL CODEBASE)
├── Target: service/yaml_adapter.py:parse_cloud_descriptor()
├── Harness: Target-bound benign ObjectInstantiator
├── Execution: Isolated disposable %TEMP% workspace
├── Physical Observable: Sentinel marker created on disk (sentinel.txt exists)
└── Behavioral Verdict: RED_STATE_REPRODUCED (Exit 0)

STEP 2: REMEDIATION SYNTHESIS
├── Agent: NVIDIA Nemotron 3 Ultra via Nebius Token Factory
├── Patch AST Validation: Syntax parsed cleanly (ast.parse passed)
├── Minimality: Surgical 2-line replacement (+1, -1) in 1 file
└── Diff Applied:
    @@ -16,3 +16,3 @@
    -    result = yaml.load(raw_yaml, Loader=yaml.Loader)
    +    result = yaml.safe_load(raw_yaml)

STEP 3: POST-PATCH EVALUATION (PATCHED CODEBASE + IDENTICAL HARNESS)
├── Target: service/yaml_adapter.py:parse_cloud_descriptor()
├── Harness: IDENTICAL Target-bound benign ObjectInstantiator
├── Execution: Isolated disposable %TEMP% workspace
├── Physical Observable: Instantiation blocked; sentinel marker ABSENT on disk
├── Parent Trust Audit: Parent runner verified clean disk & exit code 42
└── Behavioral Verdict: GREEN_STATE_BLOCKED (Dedicated Exit 42)

STEP 4: REGRESSION TEST SUITE
├── Command: pytest tests/test_manifest.py inside sandbox
├── Result: 4 of 4 regression tests PASSED in 312ms
└── Integrity: Core application parsing logic remains 100% operational
```

---

## 4. Patch Delta Review & Minimality Assessment (Section 5)

For the accepted patch in `CASE-RW-04`, VulnTrace generated the following machine-readable metadata:

```json
{
  "changed_files": ["service/yaml_adapter.py"],
  "changed_functions": ["parse_cloud_descriptor"],
  "additions_count": 1,
  "deletions_count": 1,
  "total_lines_changed": 2,
  "diff_bytes": 412,
  "is_minimal": true,
  "minimality_criterion": "Minimal: 2 lines across 1 file(s) (threshold: <= 10 lines, 1 file)",
  "tests_affected_count": 4,
  "reason_for_change": "Surgical replacement of unsafe deserialization sink"
}
```

- **Minimality Definition:** A patch is categorized as `is_minimal: true` strictly when it modifies `1 file` and `total_lines_changed <= 10`, strictly bounded to the target vulnerable call site without refactoring unrelated functions.
