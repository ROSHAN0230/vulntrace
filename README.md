# VulnTrace

**Autonomous Vulnerability Reproduction and Verified Patching Agent**  
*Built for the Nebius × NVIDIA Global AI Hackathon 2026*

---

> **Product Positioning Statement:**  
> **VulnTrace investigates whether a reported vulnerability is actually relevant to a codebase, reproduces the relevant behavior in a controlled environment, uses Nemotron to propose remediation, and verifies the remediation before calling the issue fixed.**

---

## 1. The Core Problem: The SCA False-Positive Challenge

Modern Software Composition Analysis (SCA) scanners match package version strings in manifest and lockfiles against vulnerability databases. While effective for dependency inventory, this creates key operational challenges:
- **High False-Positive Volume in Manifest Matching:** Flagged dependencies often exist in uncalled dead code paths or unused library submodules that application entrypoints never execute.
- **Alert Fatigue & Blind Bumps:** Developers are frequently forced to triage dozens of static alerts or blindly bump dependency versions, risking breaking changes in production applications.
- **Absence of Empirical Proof:** Standard manifest matching does not verify whether a vulnerable call path is reachable or reproducible in the application's runtime context, nor whether a proposed fix preserves business logic.

**VulnTrace replaces heuristic alert noise with a deterministic, parent-audited evidence lifecycle:**

```
   DEPENDENCY_VULNERABLE (Live OSV.dev / Tavily Threat Intel)
             ↓
   REACHABILITY_CONFIRMED (Multi-File AST Call-Graph Solver from Entrypoints)
             ↓
   BEHAVIOR_REPRODUCED (Controlled Sandbox Detonation → RED State: Exit 0, Sentinel Created)
             ↓
   REMEDIATION_GENERATED (NVIDIA Nemotron 3 Ultra Contextual Codemod + AST Syntax Gate)
             ↓
   REMEDIATION_VERIFIED (Differential Re-Test with Identical Harness → GREEN State: Dedicated Exit 42)
             ↓
   REGRESSION_VERIFIED (Native Pytest Test Suite Executed in Sandbox)
             ↓
   FORMAL EVIDENCE BUNDLE (Deterministic SHA-256 Hashed JSON & Markdown Verification Bundle)
```

---

## 2. Competitive Advantage Matrix

| Capability / Dimension | Traditional SCA (Manifest Scanning) | LLM Coding Agents (Copilot Workspace) | VulnTrace |
| :--- | :--- | :--- | :--- |
| **Detection Source** | Lockfile / manifest version regex | User prompts / heuristics | Live OSV.dev + Tavily Threat Intel |
| **Reachability Analysis** | Manifest matching without call-graph verification | None | Multi-file AST Call-Graph from Entrypoints |
| **False Positive Suppression** | Manual developer triage | Heuristic / ungrounded | Automated (uncalled dead code labeled FP) |
| **Behavioral Reproduction** | None | None (hallucination risk) | Automated in isolated disposable sandbox |
| **Remediation Method** | Major/minor version bump (often breaking) | Full-file LLM rewrite | Surgical minimal AST codemod |
| **Remediation Quality** | High regression rate | Hallucination / scope creep | Strictly scoped (<= 10 lines, 1 file) |
| **Post-Patch Trust Boundary** | None | Assumes build passes | **Parent Trust Audit**: Disk sentinel + Exit 42 |
| **Regression Guarantee** | None | Optional user prompt | Isolated sandbox pytest execution |
| **Audit Evidence** | Alert list CSV | Transient chat log | Deterministic SHA-256 Hashed JSON + Structured Markdown |

---

## 3. Grounded Evaluation Metrics (Independent Benchmark Suite)

Pursuant to strict evaluation integrity, VulnTrace **does not invent a single ungrounded "accuracy" percentage**. Every metric is reported with an explicit numerator and denominator grounded in observable runtime execution across 4 evaluation cases across 3 repositories (recorded on commit `0aa3e1e` benchmark run):

- **Total Evaluation Cases:** `4` (across 3 repositories: `flasgger`, `cookiecutter`, `repo_cloud_config`)
- **Reachable Paths Identified:** `2 of 4 cases` (`CASE-RW-01` Flasgger, `CASE-RW-04` Cloud Config)
- **No-Static-Path False Positive Suppressions:** `2 of 4 cases` (`CASE-RW-02` Flasgger patched, `CASE-RW-03` Cookiecutter)
- **Behavioral Reproductions Attempted:** `2 of 4 cases` (`CASE-RW-01`, `CASE-RW-04`)
- **Behavioral Reproductions Succeeded:** `1 of 2 attempted cases` (`CASE-RW-04` reproduced; `CASE-RW-01` halted with `UNEXPECTED_FAILURE` due to runtime dependency/environment incompatibility)
- **Patch Proposals Generated:** `1 of 4 cases` (`CASE-RW-04` via NVIDIA Nemotron 3 Ultra)
- **Patches Accepted by AST Syntax & Diff Gates:** `1 of 1 generated patches` (`CASE-RW-04`)
- **Patches Rejected:** `0 of 1 generated patches in real-world suite` (Adversarial rejection proven in unit suite: 1 syntax error, 1 empty diff)
- **Regression Failures:** `0 of 1 remediated real-world cases` (4 of 4 pytests passed in `CASE-RW-04`)
- **Complete Verified Remediations:** `1 of 4 cases` (`CASE-RW-04`: RED -> Nemotron -> GREEN -> Pytests Pass)
- **Infrastructure-Blocked Runs:** `0 of 4 cases` (All executed in isolated `LOCAL_SUBPROCESS_FALLBACK` with purged secrets)
- **Average Verification Pipeline Latency:** `2,148.50 ms`
- **Model Token Usage (Nemotron 3 Ultra):** `251 prompt tokens, 139 completion tokens (84 reasoning tokens)`

---

## 4. 15-Point Independent Repository Evaluation Matrix

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
| **9. Behavioral Outcome** | `UNEXPECTED_FAILURE` (missing `jsonschema`)| `SUPPRESSED_BY_GUARD` | `SUPPRESSED_FALSE_POSITIVE` | `RED_STATE_REPRODUCED` (Exit 0) |
| **10. Remediation Proposal**| `SKIPPED` | `SKIPPED` (Already safe) | `SKIPPED` (Code is already safe) | `NVIDIA_NEMOTRON_3_ULTRA` (surgical patch) |
| **11. Patch Validation** | `SKIPPED` | `SKIPPED` | `SKIPPED` | `ACCEPTED` (Passed AST syntax & diff gate) |
| **12. Post-Patch Behavior**| `UNEXPECTED_FAILURE` | `SKIPPED` | `SKIPPED` | `GREEN_STATE_BLOCKED` (Exit 42, parent verified) |
| **13. Regression Result** | `SKIPPED` | `NOT_REQUIRED` | `NOT_REQUIRED` | `PASSED` (4/4 pytests passed cleanly) |
| **14. Final Verdict** | `UNEXPECTED_FAILURE` | `NO_VULNERABILITIES_FOUND` | `UNREACHABLE_FALSE_POSITIVE` | **`GREEN_STATE_VERIFIED`** |
| **15. Disclosed Limitations**| Requires target repository runtime dependencies installed in environment. | Static analysis proves absence of symbol only. | Static AST does not resolve dynamic plugin hooks. | Verification proves defense against evaluated exploit payload in local sandbox. |

---

## 5. Differential Verification Proof

For the successfully remediated case (`CASE-RW-04`), VulnTrace provides side-by-side differential evidence proving that the exact same harness executed against both codebases:

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

## 6. Patch Delta Review & Minimality Assessment

To prevent LLM scope creep or unnecessary refactoring, VulnTrace enforces an explicit **Minimality Criterion**:

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

- **Definition of Minimal:** A patch is categorized as `is_minimal: true` strictly when it modifies `1 file` and `total_lines_changed <= 10`, strictly bounded to the target vulnerable call site.

---

## 7. Judge Evaluation Guide: 9 Core Questions Answered

### Q1. What core problem does VulnTrace solve?
SCA tools generate immense alert fatigue by warning on every library version in a lockfile, even when vulnerable functions are never called. VulnTrace establishes empirical reachability, reproduces the vulnerability behavior, synthesizes a surgical patch, and verifies that the patch stops the exploit without breaking existing tests.

### Q2. How does VulnTrace prove reachability?
VulnTrace analyzes all Python files using an AST Call-Graph Solver tracing from top-level repository entrypoints down to candidate vulnerable sink functions (e.g. `yaml.load`). If vulnerable functions are only found in uncalled dead code, VulnTrace classifies the alert as `UNREACHABLE_FALSE_POSITIVE`, preventing unnecessary work.

### Q3. What makes behavioral verification safe?
All execution occurs in disposable `%TEMP%` directories with completely purged environment secrets (stripping `NEBIUS_API_KEY`, `TAVILY_API_KEY`, AWS tokens, SSH keys) and strict network isolation during verification (setting offline pip flags, dummy proxy endpoints, and child socket blocking). The subprocess uses target-bound benign object instantiation (writing a timestamped sentinel marker) rather than destructive shell commands. Watchdog timers terminate orphaned child process trees. While isolated on the filesystem and network, the runner executes as a local subprocess sharing the host OS kernel and loopback interface (disclosed as `LOCAL_SUBPROCESS_FALLBACK`).

### Q4. Why is the post-patch check trusted?
VulnTrace implements a strict **Parent Trust Boundary**. The parent runner never trusts child-process stdout or self-reporting. It independently audits the physical filesystem to ensure the sentinel file was NEVER created, evaluates in-harness positive controls to ensure benign functionality survived, and mandates exit code 42 (indicating an intentional security block).

### Q5. How does VulnTrace prevent regressions?
After verifying the vulnerability is blocked, the engine automatically runs the repository's native test suite (via `pytest`) inside the disposable sandbox. If any test fails, the patch is rejected and the verdict is set to `REGRESSION_FAILURE`.

### Q6. How is NVIDIA Nemotron 3 Ultra utilized?
Nemotron 3 Ultra (hosted on Nebius Token Factory) generates surgical, AST-parsed codemods. In contextual benchmarks (such as custom YAML loaders registering application-specific tags), Nemotron reasons through the AST context to preserve application classes (`AppSafeLoader`), whereas naive find-replace breaks test suites.

### Q7. How is Tavily Search utilized?
Tavily Search API queries live CVE intelligence, NVD/OSV advisories, and technical PoC disclosures. Verified CVE-specific findings returned by Tavily are filtered for strict relevance and then injected directly into NVIDIA Nemotron 3 Ultra's reasoning context, providing the model with grounded real-world vulnerability context and exploit mechanics when synthesizing minimal, surgical remediations.

### Q8. What is the status of ConTree Cloud?
ConTree Cloud returns `PERMISSION_DENIED (HTTP 403)` due to token-level sandbox permissions. Rather than faking cloud execution, VulnTrace truthfully discloses `LOCAL_SUBPROCESS_FALLBACK` and documents shared host OS kernel boundaries.

### Q9. What are VulnTrace's terminal states?
VulnTrace enforces 7 mutually exclusive terminal verdicts:
1. `GREEN_STATE_VERIFIED`: Vulnerability reproduced, patched, blocked, positive controls intact, and regression tests passed.
2. `RED_STATE_PERSISTS`: Remediation failed to stop the exploit.
3. `INCONCLUSIVE`: Pre-conditions or vulnerability signal could not be observed.
4. `PATCH_REJECTED`: Patch failed AST syntax or semantic diff gates.
5. `REGRESSION_FAILURE`: Security fixed, but unit tests broke.
6. `VERIFICATION_REJECTED`: Forged child evidence or policy violation.
7. `UNEXPECTED_FAILURE`: Missing runtime dependency or environment incompatibility.

---

## 8. 3-Minute Demo Video Storyboard

| Timestamp | Phase | Visual / Screen Action | Voiceover Script |
| :--- | :--- | :--- | :--- |
| **0:00 - 0:30** | **The Problem** | Show SCA alert board with 50+ critical alerts for PyYAML. Point to Cookiecutter. | *"Every developer knows the pain of SCA alert fatigue. You get dozens of critical alerts, but which ones are actually reachable? Today, we introduce VulnTrace."* |
| **0:30 - 1:00** | **Reachability** | Click "Inspect Repository" on Cookiecutter. Click "Analyze AST Reachability". Graph displays `UNREACHABLE_FALSE_POSITIVE`. | *"VulnTrace maps the full AST call-graph from entrypoints. Cookiecutter requires PyYAML, but only calls safe_load. VulnTrace instantly suppresses this false positive."* |
| **1:00 - 1:45** | **Reproduction (RED)** | Select Cloud Config microservice. Click "Run Defensive Verification". Terminal streams pre-patch detonation. RED state Exit 0 confirmed. | *"On a genuinely vulnerable service, VulnTrace synthesizes a target-bound harness and detonates it in an isolated disposable sandbox. Sentinel created on disk: RED state confirmed."* |
| **1:45 - 2:20** | **Nemotron Patch** | Remediation card displays NVIDIA Nemotron 3 Ultra streaming diff. Patch Delta card shows 2 lines changed across 1 file. | *"Next, NVIDIA Nemotron 3 Ultra synthesizes a surgical 2-line codemod. The AST validator parses the syntax before anything touches disk. Minimality criterion met."* |
| **2:20 - 2:45** | **Differential Proof (GREEN)** | Differential Proof table shows Before Exit 0 vs After Exit 42. Parent Trust audit confirms sentinel absent on disk. | *"VulnTrace re-runs the identical harness against the patched code. The parent runner verifies Exit 42 and clean disk. Zero trust in child claims."* |
| **2:45 - 3:00** | **Regressions & Export** | Pytest passes 4/4 tests. Click "Export JSON". Download complete verification bundle. | *"Finally, pytest confirms zero regressions. With one click, developers export a verified SHA-256 hashed audit bundle and markdown report. VulnTrace: from alert to proven fix."* |

---

## 9. Clean-Room Setup Instructions

### Prerequisites
- Python 3.10+ (Tested on Python 3.14.2)
- Node.js 18+ and npm
- Git

### 1. Clone & Set Up Python Environment
```bash
# Clone repository with evaluation submodules
git clone --recurse-submodules https://github.com/ROSHAN0230/vulntrace.git
cd vulntrace

# If previously cloned without --recurse-submodules:
git submodule update --init --recursive

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\activate

# Install dependencies
pip install -e .
pip install pytest httpx sse-starlette fastapi uvicorn pyyaml
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env` and provide your API keys:
```env
NEBIUS_API_KEY=your_nebius_api_key_here
TAVILY_API_KEY=your_tavily_api_key_here
CONTREE_API_KEY=your_contree_api_key_here
```
*(Note: Never commit secret keys. Local fallback mode functions if cloud credentials are absent).*

### 3. Build Frontend & Launch Server
```bash
# Build React UI production bundle
cd ui
npm install
npm run build
cd ..

# Start FastAPI backend (serves API & React UI)
uvicorn vulntrace.server:app --host 127.0.0.1 --port 8001
```

Open your browser to:
**`http://127.0.0.1:8001`**

### 4. Run Test Suite
```bash
pytest -v tests/
```
All 33 test cases should pass in ~18 seconds.

---

## 10. Disclosures & Formal Limitations

1. **ConTree Cloud Sandboxing:** ConTree API returned `PERMISSION_DENIED (HTTP 403)` on `/sandboxes`. VulnTrace operates using `LOCAL_SUBPROCESS_FALLBACK`. No cloud responses are simulated or falsified.
2. **Local Subprocess Sandbox Boundary:** Local sandboxes execute in disposable `%TEMP%` directories with purged credentials, timeout guards, and process-tree cleanup. However, they share the host operating system kernel and local loopback interface.
3. **Static AST Reachability Scope:** The AST analyzer resolves static direct imports and aliased calls. It does not resolve dynamic runtime reflection (`getattr`), dynamic imports (`importlib`), or monkey-patching.

---

## 11. Open-Source License

VulnTrace is open-source software licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for the full terms, conditions, and copyright notices.

---

**Built with pride by the Autonomous Security Engineering Team for the Nebius × NVIDIA Global AI Hackathon 2026.**
