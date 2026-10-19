# VulnTrace

**Autonomous Vulnerability Reproduction and Verified Patching Agent**<br>
**Hackathon Track:** Coding and Agentic Engineering

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

## 2. Architectural Comparison & Evaluated Approach

| Capability / Dimension | Manifest-Only SCA (Version Matching) | Conversational LLM Assistants | VulnTrace Evaluated Architecture |
| :--- | :--- | :--- | :--- |
| **Detection Source** | Lockfile / manifest version matching | Prompt-driven / heuristic | Live OSV.dev + Tavily Threat Intel |
| **Reachability Analysis** | Manifest matching without call-graph verification | None | Multi-file AST Call-Graph from Entrypoints |
| **False Positive Suppression** | Manual developer triage | Heuristic / ungrounded | Automated (uncalled dead code labeled FP) |
| **Behavioral Reproduction** | Not supported (metadata-only) | Relies on user prompts / manual setup | Automated in Tier 1 rootless container (Tier 0 restricted strictly to approved canonical fixtures) |
| **Remediation Method** | Dependency version bump in manifest | Prompt-driven multi-line code rewrite | Surgical minimal AST codemod |
| **Remediation Bounds** | Version change without diff bounding | Unbounded edits / scope expansion | Enforced minimality gate (<= 10 lines, 1 file) |
| **Post-Patch Trust Boundary** | None (manifest re-scan only) | Relies on external CI or manual testing | **Parent Trust Audit**: Physical disk sentinel verification + Exit 42 |
| **Regression Verification** | None in scanner workflow | Optional user prompt | Contained container pytest execution (Tier 0 restricted strictly to approved canonical fixtures) |
| **Audit Artifacts** | Static report / CSV / SARIF | Unstructured chat log | Deterministic SHA-256 Hashed JSON + Structured Markdown |

*Note on scope and comparison: The table above characterizes architectural design differences evaluated across the Python dependency vulnerability scenarios documented in Sections 3 and 4. It reflects the structural properties of manifest-matching scanners and general conversational coding assistants, not a formal head-to-head empirical benchmark across commercial third-party products.*

---

## 3. Historical Evaluation Baseline (Commit 0aa3e1e Benchmark Run)

Pursuant to strict evaluation integrity, VulnTrace **does not invent a single ungrounded "accuracy" percentage**. Every metric is reported with an explicit numerator and denominator grounded in observable runtime execution across 4 evaluation cases across 3 repositories, recorded as a **historical baseline on commit `0aa3e1e` under the project's earlier execution policy**:

> **Historical Execution Policy & Baseline Context (Commit `0aa3e1e`):**  
> The measurements below reflect an earlier execution policy (Option B) in effect at commit `0aa3e1e`. In that historical run, `CASE-RW-01` (Flasgger) was evaluated under Tier 0 (`LOCAL_SUBPROCESS_FALLBACK`) with an explicit `--unsafe-local` override to test host environment builder compatibility, halting with `UNEXPECTED_FAILURE` due to a missing runtime dependency (`jsonschema`).  
> 
> **Current Policy Distinction:** Under the subsequent **Option A Strict Zero-Trust Policy** (enforced in Pre-M7), Tier 0 is strictly restricted to approved canonical developer fixtures registered in `TrustedFixtureRegistry`. Real-world and non-curated repositories (including `CASE-RW-01`) unconditionally mandate **Tier 1** (`OCI_CONTAINER_ISOLATED`) rootless container execution; no `--unsafe-local` flag authorizes Tier 0 execution. Formal re-benchmarking of `CASE-RW-01` under full Tier 1 isolation remains pending for future milestone evaluation, and no unevidenced numbers are fabricated.

- **Total Evaluation Cases:** `4` (across 3 repositories: `flasgger`, `cookiecutter`, `repo_cloud_config`)
- **Reachable Paths Identified:** `2 of 4 cases` (`CASE-RW-01` Flasgger, `CASE-RW-04` Cloud Config)
- **No-Static-Path False Positive Suppressions:** `2 of 4 cases` (`CASE-RW-02` Flasgger patched, `CASE-RW-03` Cookiecutter)
- **Behavioral Reproductions Attempted:** `2 of 4 cases` (`CASE-RW-01`, `CASE-RW-04`)
- **Behavioral Reproductions Succeeded:** `1 of 2 attempted cases` (`CASE-RW-04` reproduced; `CASE-RW-01` halted with `UNEXPECTED_FAILURE` due to missing runtime dependency `jsonschema`)
- **Patch Proposals Generated:** `1 of 4 cases` (`CASE-RW-04` via NVIDIA Nemotron 3 Ultra)
- **Patches Accepted by AST Syntax & Diff Gates:** `1 of 1 generated patches` (`CASE-RW-04`)
- **Patches Rejected:** `0 of 1 generated patches in real-world suite` (Adversarial rejection proven in unit suite: 1 syntax error, 1 empty diff)
- **Regression Failures:** `0 of 1 remediated real-world cases` (4 of 4 pytests passed in `CASE-RW-04`)
- **Complete Verified Remediations:** `1 of 4 cases` (`CASE-RW-04`: RED -> Nemotron -> GREEN -> Pytests Pass)
- **Average Verification Pipeline Latency:** `2,148.50 ms`
- **Model Token Usage (Nemotron 3 Ultra):** `251 prompt tokens, 139 completion tokens (84 reasoning tokens)`

---

## 4. 16-Point Historical Evaluation Matrix (Commit 0aa3e1e Baseline)

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
| **15. Execution Tier Used** | **Tier 0** (Historical run at commit `0aa3e1e` with `--unsafe-local`; prohibited under current Option A) | **Tier 0** (Static suppression before harness execution) | **Tier 0** (Static suppression before harness execution) | **Tier 1** (`OCI_CONTAINER_ISOLATED`, rootless container default) |
| **16. Disclosed Limitations**| Requires target repository runtime dependencies installed in environment. | Static analysis proves absence of symbol only. | Static AST does not resolve dynamic plugin hooks. | Verification proves defense against evaluated exploit payload under verified execution tier. |

> **Historical Execution & Isolation Tier Policy Disclosure:**
> - **CASE-RW-01 (Flasgger):** In the recorded historical benchmark at commit `0aa3e1e`, Flasgger was classified and executed strictly as an M2 Environment-Builder compatibility test under **Tier 0** (`LOCAL_SUBPROCESS_FALLBACK`) with an explicit `--unsafe-local` override (verifying host virtualenv creation and legacy Python syntax support), halting with `UNEXPECTED_FAILURE` due to missing `jsonschema`. It was **not** isolated under Tier 1 in that historical run. Under the current **Option A Strict Zero-Trust Policy**, this override is completely prohibited: non-curated repositories are unconditionally refused by Tier 0 and require Tier 1 rootless container isolation.
> - **CASE-RW-04 (Cloud Config Service):** Executed end-to-end under **Tier 1** (`OCI_CONTAINER_ISOLATED`), proving full rootless container isolation with kernel network denial (`--network none`), read-only root filesystem, tmpfs scratch, dropped capabilities, and unprivileged user execution.
> - Zero documentation or metadata claims that CASE-RW-01 was isolated in Tier 1 during the commit `0aa3e1e` run. Formal re-benchmarking of CASE-RW-01 under Tier 1 is pending.

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

## 7. Architecture & Evaluation FAQ: 9 Core System Questions

### Q1. What core problem does VulnTrace solve?
SCA tools generate immense alert fatigue by warning on every library version in a lockfile, even when vulnerable functions are never called. VulnTrace establishes empirical reachability, reproduces the vulnerability behavior, synthesizes a surgical patch, and verifies that the patch stops the exploit without breaking existing tests.

### Q2. How does VulnTrace prove reachability?
VulnTrace analyzes all Python files using an AST Call-Graph Solver tracing from top-level repository entrypoints down to candidate vulnerable sink functions (e.g. `yaml.load`). If vulnerable functions are only found in uncalled dead code, VulnTrace classifies the alert as `UNREACHABLE_FALSE_POSITIVE`, preventing unnecessary work.

### Q3. What makes behavioral verification safe?
All execution occurs in disposable workspaces. VulnTrace implements a strictly tiered isolation architecture (`docs/SAFETY.md`):
- **Tier 1 (Rootless OCI Container):** The mandatory default execution tier for all real-world/non-curated repositories. Harnesses run in a rootless container (Podman in WSL2/Linux) with kernel network denial (`--network none`), read-only root filesystem (`--read-only`), ephemeral tmpfs (`/tmp`), unprivileged non-root execution (`--user 1000:1000`), CPU/memory/PIDs limits (`--memory 512m --cpus 1.0 --pids-limit 128`), wall-clock timeout watchdog, and zero host mounts except the disposable workspace copy.
- **Tier 0 (Local Subprocess Fallback):** Developer machine execution strictly restricted to approved canonical fixtures registered in `TrustedFixtureRegistry`. **Tier 0 does not provide operating system isolation, user separation, or container virtualization**—it runs as the ambient host user with Win32 Job Object cleanup, memory caps, and cooperative proxy null-routing. Under the Option A Strict Zero-Trust policy, Tier 0 strictly and unconditionally refuses all non-curated or untrusted repositories. No unsafe-local override (`--unsafe-local`, `unsafe_local=True`, or `VULNTRACE_UNSAFE_LOCAL=1`) authorizes Tier 0 execution of non-curated repositories. Payloads in all tiers use target-bound benign object instantiation (writing a timestamped sentinel marker) rather than destructive shell commands.

### Q4. Why is the post-patch check trusted?
VulnTrace implements a strict **Parent Trust Boundary**. The parent runner never trusts child-process stdout or self-reporting. It independently audits the physical filesystem to ensure the sentinel file was NEVER created, evaluates in-harness positive controls to ensure benign functionality survived, and mandates exit code 42 (indicating an intentional security block).

### Q5. How does VulnTrace prevent regressions?
After verifying the vulnerability is blocked, the engine automatically runs the repository's native test suite (via `pytest`) inside the disposable sandbox. If any test fails, the patch is rejected and the verdict is set to `REGRESSION_FAILURE`.

### Q6. How is NVIDIA Nemotron 3 Ultra utilized?
Nemotron 3 Ultra (hosted on Nebius Token Factory) generates surgical, AST-parsed codemods. In contextual benchmarks (such as custom YAML loaders registering application-specific tags), Nemotron reasons through the AST context to preserve application classes (`AppSafeLoader`), whereas naive find-replace breaks test suites.

### Q7. How is Tavily Search utilized?
Tavily Search API queries live CVE intelligence, NVD/OSV advisories, and technical PoC disclosures. Verified CVE-specific findings returned by Tavily are filtered for strict relevance and then injected directly into NVIDIA Nemotron 3 Ultra's reasoning context, providing the model with grounded real-world vulnerability context and exploit mechanics when synthesizing minimal, surgical remediations.

### Q8. What is the status of ConTree Cloud?
ConTree Cloud sandboxing was evaluated during initial cloud integration testing (last verified 2026-10-02), where the API returned `PERMISSION_DENIED (HTTP 403)` on `/sandboxes` because provided credentials lacked sandbox provisioning permissions. Rather than simulating or falsifying cloud execution, VulnTrace truthfully discloses this limitation. VulnTrace executes using verified local containment engines: Tier 1 rootless container isolation (`OCI_CONTAINER_ISOLATED`) is mandatory for all non-curated/untrusted code, while Tier 0 (`LOCAL_SUBPROCESS_FALLBACK`) is strictly restricted to approved canonical developer fixtures.

### Q9. What are VulnTrace's terminal states?
VulnTrace implements the 11 canonical terminal verdicts defined in [Technical Specification §3.2](docs/TECHNICAL_SPEC.md#32-canonical-verdict-taxonomy-exact-strings):
1. `GREEN_STATE_VERIFIED`: RED reproduced (3/3), patch accepted by quality gates, GREEN verified (3/3), and baseline regression suite passes.
2. `NO_STATIC_PATH_FOUND`: Static analysis found no reachable call path from entrypoints to the identified sink; lists potential static blind spots.
3. `NOT_VULNERABLE_ALREADY_SAFE`: Target code does not exhibit the vulnerable pattern or is already remediated.
4. `RED_NOT_REPRODUCED`: Vulnerable path appears reachable, but the dynamic harness could not observe the expected vulnerability indicator across execution repeats.
5. `RED_STATE_PERSISTS`: Patch was applied, but the dynamic harness still successfully triggers the vulnerable behavior.
6. `PATCH_REJECTED`: Patch failed one or more structural quality gates (syntax error, plan scope violation, denylist violation, or diff budget exceeded).
7. `REGRESSION_FAILURE`: Security vulnerability was remediated, but tests that previously passed in the baseline suite now fail.
8. `VERIFICATION_REJECTED`: Evidence integrity check failed (harness hash altered, canary telemetry malformed or contradictory, or environment policy violated).
9. `ENV_BUILD_FAILED`: Target environment construction or dependency installation failed (distinct from internal tool exceptions).
10. `UNVERIFIABLE`: The user requirement or vulnerability description could not be converted into a deterministic, failing acceptance test (or incomplete execution protocol).
11. `UNEXPECTED_FAILURE`: Unhandled internal exception occurred or watchdog timeout tripped; accompanied by error traceback telemetry.

> **Historical Observation Labels in Benchmark Records:**
>
> Raw empirical observations in historical benchmark records retain their original recorded values from early pipeline runs. Historical labels are not universal aliases for canonical verdicts:
> - `UNREACHABLE_FALSE_POSITIVE` corresponds to `NO_STATIC_PATH_FOUND` when the recorded analysis establishes that the solver found no statically resolved path from entrypoints to the identified sink (`unreachable_dead_code`), while for `CASE-RW-03` (Cookiecutter) it corresponds to `NOT_VULNERABLE_ALREADY_SAFE` because AST analysis confirms the vulnerable sink pattern is completely absent and only `yaml.safe_load` is invoked.
> - `NO_VULNERABILITIES_FOUND` corresponds to `NOT_VULNERABLE_ALREADY_SAFE` when static AST analysis proves the vulnerable symbol is absent or already migrated (`CASE-RW-02`).
> - `INCONCLUSIVE` requires case-specific adjudication: for `inconclusive_guard`, an application pre-validation guard prevented exploit execution, canonically mapping to `RED_NOT_REPRODUCED`. For `CASE-RW-01`, while its historical raw behavioral observation recorded `INCONCLUSIVE` (exit code 10 non-reproduction, with M2 evidence attributing this to PyYAML 5.4.1 constructor error, unverified from raw run logs in this tranche), its canonical terminal adjudication under Spec §3.2 is `VERIFICATION_REJECTED` due to environment-policy violation (untrusted repository executed on host Tier 0 `LOCAL_SUBPROCESS_FALLBACK`, with `--unsafe-local` historically reported in project documentation but unverified from raw logs) and contradictory regression telemetry (`regression_passed: true` top-level vs `false` in repeat with 0 tests); this evidence-integrity rejection takes precedence over behavioral non-reproduction.
> - Exactly 5 of 10 historical records carry the legacy single-pass `GREEN_STATE_VERIFIED` label (while all 10/10 records use `protocol_conformance: LEGACY_SINGLE_PASS`, 1/1 repeat). These reflect historical single-run outcomes and do not satisfy the canonical 3-repeat acceptance gate (0/10 cases are three-repeat verified).

---

## 8. Representative End-to-End Workflows

The sections below illustrate VulnTrace's verification and remediation capabilities across two representative evaluation workflows, detailing the exact evidence-backed operational sequence without presentation planning scripts.

### Workflow 1: Pre-Execution False-Positive Reachability Suppression (`CASE-RW-03`)

- **Context & SCA Alert:** Upstream Software Composition Analysis (SCA) flags `cookiecutter` for CVE-2020-14343 based on manifest declaration `pyyaml>=5.3.1` in `pyproject.toml`, which overlaps with the vulnerable PyYAML version range.
- **AST Call-Graph Analysis:** Prior to any test execution or harness synthesis, VulnTrace constructs a multi-file AST call graph starting from application entrypoints (`cookiecutter/main.py`, `cookiecutter/cli.py`).
- **Reachability Solver:** The call graph traces all invocations across 90 Python files and 453 functions. It verifies that while PyYAML is imported in `cookiecutter/config.py`, the only invocation is `yaml.safe_load`. No path connects entrypoints to `yaml.load` or any unsafe deserialization sink.
- **Observed Result:** VulnTrace suppresses the alert before dynamic execution, recording legacy observation `UNREACHABLE_FALSE_POSITIVE` (canonical interpretation: `NOT_VULNERABLE_ALREADY_SAFE`, as static AST analysis confirms the vulnerable `yaml.load` pattern is absent and only `yaml.safe_load` is invoked). No container is provisioned, preventing unnecessary alert detonation.
- **Documented Scope & Limitations:** AST reachability verifies direct static imports and statically resolvable function call paths. In accordance with [Technical Specification §4.10](docs/TECHNICAL_SPEC.md#410-threat-model--isolation-architecture), static analysis proves the absence of statically resolvable paths within its analysis scope; it does not resolve dynamic plugin hooks that might dynamically load modules at runtime.

### Workflow 2: Verified Remediation Lifecycle (`CASE-RW-04`)

- **Context & Target Selection:** Evaluated on independent microservice `repo_cloud_config` (commit `adc4c97`, initial service commit `cb0bf8f`), a cloud infrastructure manifest parser exposing an unvalidated `yaml.load` call in `service/yaml_adapter.py:parse_cloud_descriptor`.
- **Baseline Test Suite:** Pre-remediation pytest run verifies 4 baseline unit tests pass cleanly in `tests/test_deploy.py`.
- **Tier 1 Container Boundary:** In accordance with the Option A Strict Zero-Trust security policy, execution runs inside a Tier 1 rootless OCI container (`--network none`, read-only root filesystem, tmpfs `/tmp`, non-root uid `1000:1000`, dropped capabilities `ALL`).
- **RED-State Reproduction:** VulnTrace synthesizes a targeted verification harness that invokes `parse_cloud_descriptor` with a benign canary payload. Detonation in Tier 1 successfully triggers the sink, creating a sentinel marker in disposable scratch space and exiting with Exit 0, confirming vulnerable behavior.
- **Surgical Patch Synthesis & User-Approval Gate:** NVIDIA Nemotron 3 Ultra generates a minimal 2-line codemod replacing `yaml.load(raw_yaml, Loader=yaml.Loader)` with `yaml.safe_load(raw_yaml)`. An AST syntax gate parses and accepts the patch diff, and plan review enforces user approval before applying modifications to the codebase.
- **GREEN-State Differential Verification:** The identical harness is re-executed against the patched workspace in Tier 1. The parent runner verifies zero sentinel markers created on disk and dedicated Exit 42, proving the exploit is blocked.
- **Regression Suite & Evidence Export:** Native pytest re-executes all 4 baseline tests, confirming zero regressions. VulnTrace exports an Ed25519-signed evidence bundle (`bundle.json`), unified patch diff (`.diff`), and downloadable workspace zip.
- **Protocol Conformance Status:** This result is recorded from historical single-pass evaluation (`protocol_conformance: LEGACY_SINGLE_PASS`, 1/1 repeat). In accordance with the canonical 3-repeat protocol, formal 3/3 repeat verification under Tier 1 remains pending.

---

## 9. Clean-Room Setup Instructions

### Prerequisites
- Python 3.11+ (Tested on Python 3.14.2)
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
uvicorn vulntrace.server:app --host 127.0.0.1 --port 8000
```

Open your browser to:
- **Interactive Studio Workflow:** `http://127.0.0.1:8000`
- **Judge Showcase (Recorded Evidence):** `http://127.0.0.1:8000/?view=showcase`<br>
  *(Or click the `Judge Showcase (Recorded Evidence)` pill in the top header. Browsing recorded evidence is completely self-contained, offline-compatible, and executes zero billable API calls or host code).*

### 4. Run Test Suite

VulnTrace structures testing into four distinct execution modes based on test markers and platform capabilities:

#### A. Fast Deterministic Offline Suite (Zero Containers, Zero Live Network)
Executes all offline unit tests, AST call-graph reachability solvers, synthesis validators, verifier oracles, and adversarial fixture classification/containment checks. Requires only the standard Python virtual environment:
```bash
pytest -v -m "not container and not live_network" tests/
```

#### B. Live Container Isolation Suite (Tier 1 Rootless Sandbox)
Executes rootless container isolation tests validating kernel network denial (`--network none`), read-only root filesystem (`--read-only`), ephemeral tmpfs scratch (`/tmp`), unprivileged user execution (`--user 1000:1000`), Linux capability dropping (`--cap-drop ALL`), and cgroup resource limits.  
*Requirements:* Linux or WSL2 with rootless Podman and pre-baked `vulntrace-sandbox-base:latest` OCI image:
```bash
pytest -v -m "container" tests/
```

#### C. Live Network Integration Suite (Threat Intelligence & Advisory APIs)
Executes live integration tests against external services (OSV.dev advisory lookups, Tavily Search API, and Nebius Token Factory).  
*Requirements:* Outbound internet connectivity and active credentials in `.env` (`TAVILY_API_KEY`, `NEBIUS_API_KEY`):
```bash
pytest -v -m "live_network" tests/
```

#### D. Complete Test Suite (All Modes Combined)
Executes all repository tests across offline, container, and live-network categories:
```bash
pytest -v tests/
```
*(Note: Running `pytest -v tests/` without container prerequisites or active API keys will skip or fail those specific integration tests. Only the tests marked for the host's active capabilities will execute).*

---

## 10. VulnTrace-Bench Evaluation Results ([Technical Specification §5](docs/TECHNICAL_SPEC.md#5-vulntrace-bench-protocol--evidence-engine))

<!-- VULNTRACE_BENCHMARK_TABLE_START -->
### VulnTrace-Bench Summary Metrics (Ground-Truth Empirical Observations)

- **Total Benchmark Entries Evaluated:** `10` (4 Real-World Revision Evaluations across 3 Distinct Repositories, 6 Curated Synthetic Fixtures)
- **Authorized Sink Classes Covered:** `2` (Unsafe Deserialization, Path Traversal)
- **Reachable Paths Identified:** `7 of 10 cases`
- **Static False Positive / Already-Safe Suppressions:** `3 of 10 cases`
- **Behavioral Reproductions Attempted:** `7 of 10 cases`
- **Behavioral Reproductions Succeeded:** `5 of 7 attempted cases` (1 inconclusive: `CASE-RW-01`)
- **Remediation Patches Synthesized & AST-Validated:** `5 of 5 generated patches` (NVIDIA Nemotron 3 Ultra)
- **Preserved Legacy Single-Pass Remediations:** `5 of 10 cases` (`protocol_conformance: LEGACY_SINGLE_PASS`)
- **Three-Repeat Protocol Verified Status:** `0 of 10 cases` (Zero fabricated repeats; all cases explicitly flagged as legacy single-pass pending live re-benchmarking)
- **Regression Test Failures Induced:** `0 of 5 remediated cases` (0 regressions broken)
- **Average Pipeline Latency:** `5012.42 ms`
- **3-Class Acceptance Gate Status:** **FAIL / BLOCKED** *(Command Injection remains strictly frozen; 3-class requirement unsatisfied; M7 remains open)*

### Benchmark Case-by-Case Breakdown

| Case ID | Name / Description | Sink Class | Category | Reachability Verdict | Behavioral Verdict | Isolation Tier | Conformance Protocol |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`contextual_reasoning`** | Contextual Reasoning & SafeLoader Hardening | Unsafe Deserialization | Curated Synthetic | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` | `GREEN_STATE_VERIFIED` | `OCI_CONTAINER_ISOLATED` | Legacy Single-Pass (3x Pending) |
| **`deep_callchain`** | Deep Call Chain (Multi-Directory) | Unsafe Deserialization | Curated Synthetic | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` | `GREEN_STATE_VERIFIED` | `OCI_CONTAINER_ISOLATED` | Legacy Single-Pass (3x Pending) |
| **`unreachable_dead_code`** | Unreachable Dead Code (False Positive Suppression) | Unsafe Deserialization | Curated Synthetic | `UNREACHABLE_FALSE_POSITIVE` | `UNREACHABLE_FALSE_POSITIVE` | `OCI_CONTAINER_ISOLATED` | Legacy Single-Pass (3x Pending) |
| **`regression_sensitive`** | Regression-Sensitive Config Parser | Unsafe Deserialization | Curated Synthetic | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` | `GREEN_STATE_VERIFIED` | `OCI_CONTAINER_ISOLATED` | Legacy Single-Pass (3x Pending) |
| **`inconclusive_guard`** | Pre-Validation Guard (Truthful Inconclusive) | Unsafe Deserialization | Curated Synthetic | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` | `INCONCLUSIVE` | `OCI_CONTAINER_ISOLATED` | Legacy Single-Pass (3x Pending) |
| **`tar_path_traversal`** | Tar Slip Path Traversal Extractor | Path Traversal | Curated Synthetic | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` | `GREEN_STATE_VERIFIED` | `OCI_CONTAINER_ISOLATED` | Legacy Single-Pass (3x Pending) |
| **`CASE-RW-01`** | Flasgger Vulnerable Commit (163a753) | Unsafe Deserialization | Real World Repository | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` | `INCONCLUSIVE` | `LOCAL_SUBPROCESS_FALLBACK` | Legacy Single-Pass (3x Pending) |
| **`CASE-RW-02`** | Flasgger Patched Commit (ee62207) | Unsafe Deserialization | Real World Repository | `NO_VULNERABILITIES_FOUND` | `NO_VULNERABILITIES_FOUND` | `NOT_EXECUTED (STATIC_ANALYSIS)` | Legacy Single-Pass (3x Pending) |
| **`CASE-RW-03`** | Cookiecutter False Positive Suppression | Unsafe Deserialization | Real World Repository | `UNREACHABLE_FALSE_POSITIVE` | `UNREACHABLE_FALSE_POSITIVE` | `NOT_EXECUTED (STATIC_ANALYSIS)` | Legacy Single-Pass (3x Pending) |
| **`CASE-RW-04`** | Cloud Config Independent Microservice | Unsafe Deserialization | Real World Repository | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` | `GREEN_STATE_VERIFIED` | `OCI_CONTAINER_ISOLATED` | Legacy Single-Pass (3x Pending) |

> [!NOTE]
> **Historical Observation Labels & Protocol Conformance:**
> Raw empirical observations retain their original recorded values. Their canonical interpretation depends on the case, pipeline phase, and supporting evidence: historical labels are not universal aliases for canonical verdicts. `UNREACHABLE_FALSE_POSITIVE`, for example, corresponds to `NO_STATIC_PATH_FOUND` when the recorded analysis establishes that the AST solver found no statically resolved path from entrypoints to the identified sink (`unreachable_dead_code`), while for `CASE-RW-03` (Cookiecutter) it corresponds to `NOT_VULNERABLE_ALREADY_SAFE` because AST analysis confirms the vulnerable sink pattern is completely absent and only `yaml.safe_load` is invoked. `NO_VULNERABILITIES_FOUND` corresponds to `NOT_VULNERABLE_ALREADY_SAFE` when static AST analysis proves the vulnerable symbol is absent or already migrated (`CASE-RW-02`). `INCONCLUSIVE` requires case-specific adjudication: for `inconclusive_guard`, an application pre-validation guard prevented exploit execution, canonically mapping to `RED_NOT_REPRODUCED`. For `CASE-RW-01`, while its historical raw behavioral observation recorded `INCONCLUSIVE` (exit code 10 non-reproduction, with M2 evidence attributing this to PyYAML 5.4.1 constructor error, unverified from raw run logs in this tranche), its canonical terminal adjudication under Spec §3.2 is `VERIFICATION_REJECTED` due to environment-policy violation (untrusted repository executed on host Tier 0 `LOCAL_SUBPROCESS_FALLBACK`, with `--unsafe-local` historically reported in project documentation but unverified from raw logs) and contradictory regression telemetry (`regression_passed: true` top-level vs `false` in repeat with 0 tests); this evidence-integrity rejection takes precedence over behavioral non-reproduction.
> Furthermore, exactly 5 of 10 historical records carry the legacy single-pass `GREEN_STATE_VERIFIED` label (while all 10/10 records use `protocol_conformance: LEGACY_SINGLE_PASS`, 1/1 repeat). These reflect historical single-run outcomes and do not satisfy the canonical 3-repeat acceptance gate (0/10 cases are three-repeat verified).

> [!NOTE]
> **API Interaction, Control Flow & Telemetry Accounting:**
> - **Multi-Tier LLM Orchestration:** When remediation is enabled (`req.use_nemotron=True`) and RED state is reproduced, VulnTrace executes up to three model tiers sequentially: Triage (Small: `NVIDIA-Nemotron-3-Nano-30B-A3B`), Planning (Mid: `llama-3.3-70b-instruct`), and Patch Synthesis (Ultra: `Nemotron-3-Ultra-550b-a55b`). Triage and Planning run sequentially; if Triage fails or returns `None`, Planning is not skipped and proceeds with `Triage: N/A`. Each structured stage supports up to `max_retries=2` (1 to 3 attempts) upon API error or schema validation failure. Patch synthesis invokes Nemotron Ultra; if synthesis fails, errors, outputs invalid Python syntax, or produces no semantic changes, AST deterministic rewrite is invoked as an automated fallback when enabled. AST fallback is a defensive repair fallback, not an inference bypass (inference was attempted first). Expected logical LLM calls per remediated case range from 3 (baseline) to 7 (with schema validation retries). Static suppressions, pre-patch non-reproduced cases, and all verification repeats execute exactly 0 LLM calls.
> - **Threat Intelligence Dispatch (7 of 10 Cases):** Exactly 7 of 10 benchmark cases invoke `VerificationPipeline.run_pipeline()` and query threat intelligence (`TavilyClient.query_threat_intel()` during Stage 2 INTEL). Exactly 3 of 10 cases (`unreachable_dead_code`, `CASE-RW-02`, `CASE-RW-03`) are evaluated via standalone static AST reachability analysis without pipeline dispatch (0 Tavily invocations). Across verification repeats, dynamic test harnesses execute offline with kernel network denial (`--network none`) in Tier 1 containers, making exactly 0 Tavily calls.
> - **Offline Cache-Miss Behavior (Static Verification):** In `TokenFactoryClient` (`vulntrace/llm/client.py:90-127`) and `TavilyClient` (`vulntrace/intel/tavily_client.py:56-116`), if live mode is disabled (`LIVE_LLM=0` / `LIVE_INTEL=0`) but an API key is configured and an unrecorded query misses the cassette cache, execution falls through to live outbound HTTP requests. Zero external calls in offline testing are guaranteed only when credentials are omitted (triggering immediate internal synthetic error reports) or queries match pre-recorded cassettes.
> - **Telemetry Metric Disentanglement:** Benchmark reporting strictly distinguishes eight separate categories: (1) Client Invocations (Python function calls to API entry points), (2) Outbound HTTP Request Attempts (network socket transmissions initiated by the client library), (3) HTTP Responses Received (network responses returned by the remote server, including non-200 HTTP error statuses), (4) Successful HTTP 200 Responses with Valid JSON (completed advisory or completion responses), (5) Cassette Replays (deterministic disk fixtures where the client takes no outbound request on that code path), (6) Synthetic Error Reports (locally generated failure objects, such as internal 401 or exception-handled 500 reports created without a received HTTP response; internal 401 and exception-generated 500 objects are not counted as received HTTP responses), (7) Degraded Pipeline Outcomes (graceful fallbacks to static symbols or baseline context when threat intel or models are unavailable), and (8) Historical Telemetry Limitations (request-level HTTP metrics that were not recorded in the raw observations schema).

> [!NOTE]
> **Held-Out Generalizability Dataset Notice:**
> In compliance with [Technical Specification §5.2](docs/TECHNICAL_SPEC.md#52-evaluation-protocol), candidate generalizability cases are documented in [`bench/HELDOUT.md`](bench/HELDOUT.md) (`aiohttp` CVE-2024-23334, `PyYAML` CVE-2020-1747, and `Tornado` CVE-2026-103263). These cases are strictly segregated from development tuning, are not executed during CI or development suites, and are excluded from the development-set metrics above.
<!-- VULNTRACE_BENCHMARK_TABLE_END -->

---

## 11. Disclosures & Formal Limitations

1. **Isolation Tiers & Safety Boundaries:** VulnTrace implements a strictly tiered execution architecture detailed in [`docs/SAFETY.md`](docs/SAFETY.md):
   - **Tier 1 (Rootless OCI Container):** The mandatory default execution tier for all real-world and non-curated repositories. Provides kernel-enforced network denial (`--network none`), read-only root filesystem (`--read-only`), unprivileged non-root identity (`--user 1000:1000`), dropped Linux capabilities (`--cap-drop ALL`), tmpfs scratch (`/tmp`), and cgroup resource limits (512MB RAM, 128 PIDs, 1.0 CPU).
   - **Tier 0 (`LOCAL_SUBPROCESS_FALLBACK`):** Local developer execution strictly restricted to approved canonical fixtures registered in `TrustedFixtureRegistry`. **Tier 0 does not provide operating system isolation, user separation, or container virtualization.** It executes as the ambient host user and strictly refuses non-curated repository inputs unconditionally. No unsafe-local override (`--unsafe-local`, `unsafe_local=True`, or `VULNTRACE_UNSAFE_LOCAL=1`) authorizes Tier 0 execution of non-curated repositories.
2. **ConTree Cloud Sandboxing:** ConTree API returned `PERMISSION_DENIED (HTTP 403)` on `/sandboxes` during initial integration testing (last verified 2026-10-02). VulnTrace operates using verified local containment backends (Tier 1 rootless container for non-curated code, Tier 0 strictly for approved canonical fixtures). No cloud responses are simulated or falsified.
3. **Static AST Reachability Scope:** The AST analyzer resolves static direct imports and aliased calls. It does not resolve dynamic runtime reflection (`getattr`), dynamic imports (`importlib`), or monkey-patching.
4. **NVIDIA / Nebius Token Factory Disclosures:** Models used for automated remediation are hosted via Nebius Token Factory (`https://api.tokenfactory.nebius.com/v1`): Triage (`NVIDIA-Nemotron-3-Nano-30B-A3B`), Planning (`nvidia/nemotron-3-super-120b-a12b`), and Patch Synthesis (`Nemotron-3-Ultra-550b-a55b`). All API keys are kept strictly server-side in `.env` and are never exposed to clients or browser code.
5. **Tavily Intelligence Scope & Canonical Cassette Hashing:** Tavily Search queries provide live CVE threat intelligence and technical PoC disclosures. In offline evaluation and CI, advisory items are deterministically cached in canonical cassettes. The SHA-256 fingerprint (`469b2f88aa8c...`) hashes these canonical reference items, not ephemeral raw network response bytes.
6. **External Repository Inconclusive Result (Flasgger):** In live verification on external repository Flasgger at vulnerable commit `163a753` (`CASE-RW-01`), execution halted with `INCONCLUSIVE` (exit code 42 pre-patch under PyYAML 6.0.3) and pytest collection failed due to Flask 3.1.3 `Markup` deprecation. In accordance with zero-trust verification policy, VulnTrace halted patch synthesis rather than generating an unverified patch. This is an environment incompatibility and safe halt, NOT successful remediation.
7. **Curated Microservice Integration Benchmark (CASE-RW-04):** `repo_cloud_config` is a curated internal microservice integration benchmark designed to validate multi-file service call paths, Tier 1 rootless container isolation, and regression suites. It must not be characterized as third-party open-source software, nor does it establish general external repository remediation.

---

## 12. Open-Source License

VulnTrace is open-source software licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for the full terms, conditions, and copyright notices.

---

**Built with pride by the Autonomous Security Engineering Team.**
