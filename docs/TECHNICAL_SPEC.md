# VulnTrace Studio — Technical Specification

**Spec version:** v1.0
**Base repository:** https://github.com/ROSHAN0230/vulntrace (Apache-2.0, Python + FastAPI + React)
**Audience:** Core engineers, contributors, and autonomous verification agents

---

## 0. How to use this document

**Golden rule: the repository implementation and empirical execution are the single source of truth.** If this specification disagrees with the repository's reality, STOP, report the exact discrepancy, and await confirmation. Do not silently alter either specification or code to mask discrepancies.

### Engineering & Agent Guidelines
1. **Agent Directives:** The rules defined in Section 8 must be maintained in `AGENTS.md` at the repository root and in workspace agent directives.
2. **Milestone Scoping:** Work should be scoped to one milestone (Section 6) at a time with strict acceptance criteria.
3. **Execution Evidence:** A milestone or feature is never complete until real command output confirms each acceptance criterion (AC), including at least one real failure caught and fixed through execution.
4. **Adversarial Review:** Scrutinize all verification and verifier behavior against the anti-gaming bad-patch zoo and edge-case suites. Never accept "looks correct" without an executed test that fails when incorrect.
5. **Merge Gate:** Merges and milestones require complete structured evidence reports and a passing CI workflow.

---

## 1. System Constraints & Requirements

| # | Requirement | Technical Implication |
|---|---|---|
| R1 | **Cloud Inference Infrastructure** | LLM inference calls are routed through Nebius Token Factory (OpenAI-compatible API client). Execution telemetry and token usage are logged. |
| R2 | **Open Foundation Models** | Uses NVIDIA open-source models (Nemotron family) for pipeline tasks (triage, planning/spec synthesis, patch generation, and repair). |
| R3 | **Open Source Licensing** | The repository is open source under the Apache-2.0 license, clearly documented at the project root. |
| R4 | **Autonomous Threat Intelligence** | Incorporates a functional runtime call to the Tavily API during analysis to enrich vulnerability triage with upstream advisories, fix patterns, and affected symbols. |
| R5 | **Empirical Proof-Carrying Remediation** | Patches are accepted only when an explicit RED/GREEN verification harness reproduces vulnerable behavior on the unpatched codebase, verifies remediation on the patched codebase, and confirms baseline regression tests pass. |
| R6 | **Strict Execution Isolation** | Untrusted or external target code must execute under rootless container isolation (Tier 1) with network access disabled (`--network none`) during verification. Tier 0 (local subprocess) is strictly limited to curated developer fixtures. |
| R7 | **Cryptographic Evidence Integrity** | Every run generates an evidence bundle signed with an Ed25519 key, recording hashes, test telemetry, environmental metadata, and verdict rationale. |
| R8 | **Reproducible Benchmark Suite** | Benchmark metrics and README status tables must be automatically reproducible via offline/deterministic execution gates in CI (`bench/run.py --ci`). |

---

## 2. System Design Principles & Decision Log

### 2.1 Engineering Roles & System Responsibilities

| Role | Mandate | Scrutinizes | Veto Authority |
|---|---|---|---|
| **Architecture Lead** | Ensures clean component boundaries, robust API contracts, and observable telemetry. | Shallow wrappers, unobservable execution, brittle dependencies. | Unmonitored or uninstrumented subsystems. |
| **AppSec Lead** | Validates sound security models, oracle correctness, and tamper-resistant verifiers. | Unsound static reachability, false-positive GREEN verdicts, weaponized payloads. | Verdict wording that overclaims security properties. |
| **Platform Safety** | Protects the host and runtime environments from untrusted code execution. | Local subprocess execution of untrusted repos, zip-slip, symlink escapes, uncontained resource usage. | Unsandboxed or insufficiently isolated execution of target code. |
| **Product & Design** | Maintains an intuitive, accessible, and information-dense 7-step user workflow. | Confusing multi-step UX, hidden evidence, unstructured raw terminal dumps. | UI designs that obscure verification evidence or token accounting. |
| **Evidence Auditor** | Validates that every metric, claim, and verdict maps directly to executed evidence. | Unsourced benchmark numbers, unverified claims, benchmark tuning on test cases. | Any unverified assertion or ungrounded performance claim. |
| **Systems & CI** | Guarantees deterministic, reproducible, and cross-platform automated test suites. | Flaky tests, network-dependent CI steps, drift between documentation and runtime data. | Any commit that breaks continuous integration. |
| **FinOps & Resource Manager** | Controls inference costs, token utilization, and execution budgets. | Excessive prompt sizes, unbounded retry loops, unbudgeted live LLM calls during tests. | Live model calls in unit tests or unmetered execution loops. |

### 2.2 Architectural Decision Log

| ID | Decision Question | Architectural Ruling | Technical Rationale |
|---|---|---|---|
| D1 | Breadth vs Depth | **Depth: Python only, focused sink classes** (Unsafe Deserialization, Path Traversal, Command Injection). | Rigorous verification, deterministic oracles, and zero false-positive claims require deep per-class semantics. |
| D2 | Harness Generation | **Templated sink-class oracles; LLM only parametrizes target symbols and inputs.** | Ensures determinism, prevents LLM from weakening assertions or gaming the test oracle. |
| D3 | Subprocess Sandbox | **Developer machine & curated fixtures only.** All real/untrusted repositories require Tier 1 rootless container isolation. | Prevents untrusted code from compromising the developer host or test runner. |
| D4 | Public/Demo Execution | **Curated fixtures and replay-backed analysis.** Arbitrary repository execution requires local or authenticated private deployment. | Protects public infrastructure from abuse, untrusted uploads, and denial-of-service risks. |
| D5 | Requirement Formulation | **Guided remediation (default) and structured requirement parsing.** If an acceptance test cannot be synthesized, return `UNVERIFIABLE`. | Prevents generating unverified code modifications; upholds proof-carrying remediation invariants. |
| D6 | Export Formats | **Standard `.diff`, `.zip`, `git apply` snippets, and signed `bundle.json`.** | Interoperable, auditable artifacts that fit standard developer workflows without requiring write access to remotes. |
| D7 | Cryptographic Verification | **Ed25519 signature on evidence bundles.** | Guarantees tamper-evidence for historical run records and benchmark outputs. |
| D8 | Negative Reachability | **`NO_STATIC_PATH_FOUND` with explicit blind spots.** | Avoids falsely claiming code is unreachable when dynamic imports, reflection, or monkey patching might exist. |
| D9 | Verification Integrity | **Ground claims on empirical test execution (RED/GREEN) rather than heuristic static claims.** | Dynamic execution proves exploitability and verified remediation objectively. |
| D10 | Threat Intelligence | **Runtime Tavily query enriches vulnerability context and candidate symbol selection.** | Dynamically guides sink selection with real-world CVE advisories while gracefully degrading if offline. |
| D11 | Tiered Model Routing | **Specialized Nemotron tiers:** fast model for triage, mid model for planning/spec, high-capability model for code repair. | Optimizes latency, cost, and reasoning capacity across distinct pipeline stages. |
| D12 | Reproducibility | **Deterministic offline cassettes for automated testing and CI; live inference for interactive runs.** | Eliminates flaky network tests and prevents inference credit exhaustion in continuous integration. |
| D13 | Change Control | **Strict milestone gates and frozen milestone boundaries.** | Maintains architectural stability, prevents scope creep, and ensures reliable delivery. |
| D14 | Definition of Done | **Executed evidence (reproducible commands and artifacts), never visual review alone.** | Ensures engineering honesty and rigorous reproducibility across all components. |

---

## 3. Product Definition & Verdict Taxonomy

### 3.1 Core Workflow
VulnTrace Studio is an automated, proof-carrying security remediation platform for Python codebases:
1. **Ingest:** Safely unpacks and validates a target Python repository.
2. **Analyze:** Performs dependency inventory, queries Tavily threat intelligence, constructs an AST call graph, and records baseline unit test status.
3. **Intent & Spec:** Converts a user requirement or vulnerability report into a structured `Spec` object and synthesized acceptance tests.
4. **Plan:** Proposes an explicit, bounded remediation plan (files to modify, diff budget, strategy) for user approval.
5. **Edit:** Synthesizes minimal search/replace edits within a disposable workspace copy, enforcing syntax, scope, and denylist gates.
6. **Verify:** Executes a 3-repeat RED harness on unpatched code, applies the patch, executes a 3-repeat GREEN harness, and verifies regression tests against baseline.
7. **Export:** Emits a signed Ed25519 evidence bundle, git-compatible `.diff`, and downloadable workspace zip.

### 3.2 Canonical Verdict Taxonomy (Exact Strings)

The following verdict strings are canonical and must not be altered:

| Verdict | Definition |
|---|---|
| `GREEN_STATE_VERIFIED` | RED reproduced (3/3), patch accepted by quality gates, GREEN verified (3/3), and baseline regression suite passes. |
| `NO_STATIC_PATH_FOUND` | Static analysis found no reachable call path from entrypoints to the identified sink; lists potential static blind spots. |
| `NOT_VULNERABLE_ALREADY_SAFE` | Target code does not exhibit the vulnerable pattern or is already remediated. |
| `RED_NOT_REPRODUCED` | Vulnerable path appears reachable, but the dynamic harness could not observe the expected vulnerability indicator. |
| `RED_STATE_PERSISTS` | Patch was applied, but the dynamic harness still successfully triggers the vulnerable behavior. |
| `PATCH_REJECTED` | Patch failed one or more structural quality gates (syntax error, plan scope violation, denylist violation, or diff budget exceeded). |
| `REGRESSION_FAILURE` | Security vulnerability was remediated, but tests that previously passed in the baseline suite now fail. |
| `VERIFICATION_REJECTED` | Evidence integrity check failed (harness hash altered, canary telemetry malformed or contradictory, or environment policy violated). |
| `ENV_BUILD_FAILED` | Target environment construction or dependency installation failed (distinct from internal tool exceptions). |
| `UNVERIFIABLE` | The user requirement or vulnerability description could not be converted into a deterministic, failing acceptance test. |
| `UNEXPECTED_FAILURE` | Unhandled internal exception occurred; always accompanied by error traceback telemetry. |

---

## 4. Component Architecture

### 4.1 Remediation Pipeline

```
[1 INGEST]    Archive upload / Git URL
      │       Guards: file size, zip-slip, symlink escape, shallow clone, hook strip
      ▼
[2 ANALYZE]
      ├─ Baseline test suite run (records passing/failing test registry)
      ├─ Dependency inventory & vulnerability mapping
      ├─ Tavily threat intelligence query (symbol & sink identification)
      └─ AST call-graph reachability analysis from entrypoints
      ▼
[3 INTENT]    Requirement / vulnerability → Spec { must_fix, must_preserve, constraints }
      │       Unable to generate failing test → UNVERIFIABLE
      ▼
[4 PLAN]      Candidate files, edit strategy, diff budget → User Approval Gate
      ▼
[5 EDIT]      Nemotron-driven search/replace edits in disposable copy (repair loop ≤ 3)
      │       Structural gates: AST syntax parse, plan-scope check, denylist check, line budget
      ▼
[6 VERIFY]    RED run (3/3) → Apply patch → GREEN run (3/3) → Baseline regression run
      ▼
[7 EVIDENCE]  Ed25519 signed JSON bundle + UI timeline + side-by-side diff
      ▼
[8 EXPORT]    Downloadable .diff, zip archive, and git apply verification snippet
```

### 4.2 Module Structure

| Subsystem | Location | Primary Responsibility |
|---|---|---|
| Ingest | `vulntrace/core/ingest.py` | Safe archive unpacking, repository cloning, zip-slip and symlink defense. |
| Analysis | `vulntrace/analysis/` | AST call-graph reachability, dependency extraction, baseline test discovery. |
| Intelligence | `vulntrace/intel/` | Tavily API client, advisory aggregation, `ThreatIntel` normalization. |
| Sink Oracles | `vulntrace/sinks/` | Parameterized dynamic oracles for Deserialization, Path Traversal, and Command Injection. |
| Verifier | `vulntrace/verifier/` | 3-repeat RED/GREEN runner, regression comparator, and anti-gaming verification gates. |
| Environment | `vulntrace/envbuild/` | Isolated per-case virtualenv/container construction with dependency caching. |
| Sandbox | `vulntrace/core/backend.py` | Execution backends: Tier 0 (LocalSubprocess) and Tier 1 (Rootless Container). |
| LLM Layer | `vulntrace/llm/` | Nebius Token Factory client, Nemotron model routing, token ledger, prompt management. |
| Intent Engine | `vulntrace/intent/` | Requirement parsing, acceptance test synthesis, and behavior-preservation assertions. |
| Agent Loop | `vulntrace/agent/` | Search/replace edit application, scope guarding, and multi-turn repair loop. |
| Evidence | `vulntrace/evidence/` | Schema validation, SHA-256 telemetry hashing, and Ed25519 bundle signing. |
| Server | `vulntrace/server/` | FastAPI REST endpoints, SSE event streams, run persistence. |
| UI | `ui/` | React single-page 7-step guided workflow with real-time streaming state. |
| Benchmark | `bench/`, `benchmarks/` | VulnTrace-Bench execution engine, multi-repeat evaluation, markdown report generation. |

### 4.3 Sink-Class Oracle Library

Each oracle is a strictly reviewed, deterministic Python test module. Dynamic test code is never generated entirely freeform by an LLM; the model only populates structured parameters (target module, entry symbol, benign arguments).

| Vulnerability Class | Representative Sinks | Benign Verification Probe | Expected Block Signal |
|---|---|---|---|
| **Unsafe Deserialization** | `yaml.load` (unsafe loader), `pickle.loads` | Instantiation probe attempting to create a canary file in an isolated tempdir | Specific constructor exception (`yaml.constructor.ConstructorError`, `_pickle.UnpicklingError`), canary absent |
| **Path Traversal** | `tarfile.extractall`, `zipfile.extractall`, path joiners | Path payload attempting to escape target directory root into parent directory | Explicit traversal refusal (`PathTraversalError`, `ValueError`), canary absent outside root |
| **Command Injection** | `subprocess.Popen(..., shell=True)`, `os.system` | Command argument containing a benign marker command attempting canary creation | Command rejected or argument escaped; marker command not executed; canary absent |

#### Oracle Safety Invariants
1. **Behavioral Probes Only:** Payloads must never open reverse shells, make external network requests, exfiltrate host data, or alter files outside designated temporary test scratch directories.
2. **Positive Control Requirement:** The oracle must verify that legitimate, non-malicious inputs continue to function correctly under the patched code.
3. **Specific Error Signature:** Remediation must raise the precise, expected exception class. Silently swallowing errors with broad `except Exception: pass` is rejected.

### 4.4 Verifier & Anti-Gaming Gates

To prevent accidental false-positives or deliberate gaming of the verification harness, `GREEN_STATE_VERIFIED` requires:
1. **3/3 RED Reproduction:** The vulnerable behavior must reproduce 3 consecutive times on the baseline code with the expected observable.
2. **Immutable Harness:** The test harness and oracle files reside outside the mutable workspace. Their SHA-256 hashes are verified pre- and post-patch and must match identically.
3. **Specific Signature Verification:** The GREEN run must produce the designated exception type, confirm canary absence, and pass positive control validation. An exit code 0 or generic catch-all exception is insufficient.
4. **Patch Denylist Enforcement:** Rejects patches introducing forbidden constructs (`sys.exit`, `os._exit`, `os.kill`, broad `except: pass` wrapping the sink, modifications to test files, or writes outside the approved plan).
5. **Regression Verification:** All tests passing in the baseline test run must pass on the patched codebase.
6. **3/3 GREEN Verification:** The patched codebase must succeed across 3 independent, clean verification runs.

#### Bad-Patch Zoo (Negative Controls)
The verifier is continuously evaluated against a zoo of adversarial patches that must never be classified as `GREEN_STATE_VERIFIED`:
- Unconditional `sys.exit(0)` or `sys.exit(42)`.
- Empty diff / no-op edits.
- Deletion of the vulnerable function.
- Broad `try...except: pass` wrapping the call site.
- Return `None` unconditionally.
- Modification of sentinel or canary paths.
- Edits targeting test harness files rather than source code.

### 4.5 Environment Builder

1. **Isolation:** Constructs a fresh, dedicated Python virtual environment per case outside the repository workspace.
2. **Dependency Boundary:** Target dependencies declared in `requirements.txt`, `pyproject.toml`, or `setup.py` are resolved and installed. Network access is restricted strictly to the dependency build phase; test execution is offline.
3. **Wheel Cache:** Reuses pre-built wheels to accelerate build cycles and reduce bandwidth consumption.
4. **Honest Failure Taxonomy:** If dependency resolution fails, the run terminates with `ENV_BUILD_FAILED` and records pip log telemetry. It must never mask environment errors as `UNEXPECTED_FAILURE`.
5. **Metadata Recording:** Records Python interpreter version, package manifest, and build duration in the evidence bundle.

### 4.6 Execution Isolation Tiers

| Tier | Technology | Authorized Workload | Security Boundaries |
|---|---|---|---|
| **Tier 0** | Local Subprocess | **Curated Developer Fixtures Only** | Executed directly on host OS using restricted subprocess wrappers. **Strict Zero-Trust Policy:** Untrusted or real external repositories are unconditionally refused under Tier 0. |
| **Tier 1** | Rootless Container (Docker / Podman / WSL2) | **All Real & Untrusted Repositories (Default)** | Rootless execution, read-only root filesystem, `--network none` during test execution, disposable `tmpfs` scratch at `/tmp`, unprivileged non-root UID/GID, memory/CPU/PIDs limits, and strict wall-clock timeout watchdog. |
| **Tier 2** | Remote Cloud Sandbox | Optional Extension Backend | Remote isolated microVM or container sandbox (e.g. Nebius Sandbox / Serverless Job) with isolated networking and hardware-enforced tenant boundaries. |

### 4.7 LLM Layer & Inference Integration

1. **Inference Provider:** Routed through Nebius Token Factory utilizing an OpenAI-compatible API client.
2. **Tiered Model Routing:**
   - **Triage & Classification:** Lightweight model for fast vulnerability categorization and dependency mapping.
   - **Spec & Test Synthesis:** Mid-tier model for intent extraction, acceptance test authoring, and plan generation.
   - **Remediation & Patching:** High-capability model (Nemotron-70B family) for targeted code generation and repair loops.
3. **Structured Output:** Model responses are constrained to Pydantic-validated JSON schemas with automatic retry on malformed outputs (up to 2 retries).
4. **Bounded Search/Replace:** Model generates targeted search/replace hunks requiring exact context matching. Whole-file rewrites are prohibited.
5. **Token Accounting:** Telemetry captures prompt, completion, and reasoning token counts and latencies per stage, persisted in the run record and presented in the UI.
6. **Cassette Layer:** Unit tests use recorded offline cassettes to guarantee deterministic test execution with zero live API calls. Live inference is enabled selectively via environment variables (`LIVE_LLM=1`).
7. **Prompt Injection Mitigation:** Repository contents (comments, docstrings, issue reports) are treated as untrusted data, enclosed within delimited boundary blocks. The model cannot execute shell commands or invoke tools outside the bounded edit operations.

### 4.8 Threat Intelligence (Tavily Integration)

1. **Query Construction:** Automatically forms structured queries based on package name, identified CVE, and suspected sink function.
2. **Data Normalization:** Converts external advisory information into a structured `ThreatIntel` record (advisory URLs, affected symbols, known fix patterns, and confidence scores).
3. **Pipeline Influence:** Candidate symbols and sink patterns extracted from threat intelligence directly prioritize call-graph exploration and oracle selection.
4. **Graceful Degradation:** If the threat intelligence service is unreachable or unconfigured, the pipeline marks `intel_status: degraded` and continues analysis, truthfully noting the degraded status in the evidence bundle.

### 4.9 Intent Engine & Requirement Synthesis

1. **Input Parsing:** Converts user natural-language requirements (e.g., "Fix yaml.load vulnerability while preserving custom tag constructors") into a formal specification:
   ```json
   {
     "must_fix": ["yaml.load with arbitrary object instantiation"],
     "must_preserve": ["custom Constructor tags registered on Loader"],
     "constraints": ["do not alter public function signatures"],
     "out_of_scope": ["refactoring unrelated endpoints"]
   }
   ```
2. **Acceptance Test Authoring:** Pairs security oracle probes with behavior-preservation tests exercising declared functional constraints.
3. **Test Quality Validation:** Synthesized acceptance tests must execute against the unpatched codebase and fail specifically on the intended behavior. Trivial tests (such as `assert True`) are statically detected and rejected with `UNVERIFIABLE`.

### 4.10 Agent Edit Loop & Scope Guard

1. **Plan Formulation:** Generates a structured plan defining exact target files, modification strategy, and a diff budget (default ≤30 changed lines across ≤3 files).
2. **Approval Gate:** The generated plan requires affirmative user confirmation prior to workspace modifications.
3. **Disposable Workspace Copy:** Edits are performed on an isolated clone of the repository. Original files remain untouched until verification passes.
4. **Execution Gates:**
   - Gate 1: AST syntax validation.
   - Gate 2: Plan-scope compliance (no unapproved files modified).
   - Gate 3: Patch denylist check (no exit calls, test modifications, or broad exception suppression).
   - Gate 4: Diff line-count budget.
5. **Iterative Repair Loop:** If verification fails, structured compiler or test failure output is returned to the model for up to 3 repair iterations. If all attempts fail, the run terminates with an honest non-GREEN verdict.

### 4.11 Evidence Bundle & Cryptographic Signing

Evidence bundles conform to JSON Schema v1 (`docs/evidence/schema_v1.json`):
```json
{
  "run_id": "uuid-v4",
  "created_at": "ISO-8601-UTC",
  "tool_versions": { "vulntrace": "...", "python": "..." },
  "source": { "type": "git|upload", "commit": "...", "repo_url": "..." },
  "sandbox": { "tier": 1, "network_policy": "none", "limits": { "memory_mb": 2048, "cpus": 2 } },
  "intel": { "status": "active|degraded", "queries": [], "references": [] },
  "analysis": { "findings": [], "reachability": { "paths": [], "blind_spots": [] }, "baseline_tests": {} },
  "spec": { "requirement": "...", "parsed_spec": {}, "acceptance_tests": [] },
  "llm": { "calls": [{ "stage": "patch", "model": "...", "tokens": {}, "latency_ms": 1200 }] },
  "verification": {
    "harness_sha256": "...",
    "red_runs": [{ "run": 1, "verdict": "VULNERABLE", "canary_detected": true }],
    "green_runs": [{ "run": 1, "verdict": "REPAIRED", "canary_detected": false }],
    "positive_control": { "passed": true },
    "regression": { "baseline_passed": 12, "post_passed": 12, "regressions": [] }
  },
  "attempts": [{ "attempt": 1, "diff": "...", "gates_passed": true, "result": "..." }],
  "verdict": "GREEN_STATE_VERIFIED",
  "signature": {
    "algorithm": "Ed25519",
    "public_key": "hex-encoded-key",
    "signature": "hex-encoded-signature"
  }
}
```

The bundle can be independently verified from the CLI:
```bash
vulntrace verify-bundle bundle.json
```
Verification recalculates canonical telemetry hashes and verifies the Ed25519 cryptographic signature.

### 4.12 API & Server Architecture

FastAPI backend exposing REST and SSE streaming endpoints:
- `POST /runs`: Initializes a run from an uploaded archive or Git URL.
- `GET /runs/{id}/events`: SSE stream broadcasting stage transitions, verifier logs, and token ledger metrics.
- `POST /runs/{id}/intent`: Submits natural language remediation requirement.
- `POST /runs/{id}/approve-plan`: Records user approval for the proposed edit plan.
- `GET /runs/{id}/bundle`: Retrieves complete signed evidence bundle JSON.
- `GET /runs/{id}/diff`: Returns standard Unified Diff of the verified patch.
- `GET /runs/{id}/export?format=diff|zip`: Downloads remediation artifacts.

### 4.13 User Interface Flow

A seven-step guided single-page React application:
1. **Source Selection:** Repository upload or Git URL entry with isolation tier indicator and safety advisories.
2. **Analysis Overview:** Interactive AST reachability graph, OSV dependency alerts, Tavily intelligence sources, and baseline test results.
3. **Requirement Input:** Intent configuration box with pre-built requirement templates and static feasibility warnings.
4. **Plan Review:** Side-by-side inspection of candidate files, proposed change strategy, and diff budget limits.
5. **Verification Pipeline:** Real-time streaming timeline rendering 3-repeat RED execution, patch application, 3-repeat GREEN execution, and token ledger metrics.
6. **Evidence Inspection:** Side-by-side RED vs GREEN trace view, unified patch diff, regression status table, and verdict badge.
7. **Export & Verification:** One-click downloads for `.diff`, `.zip`, signed `bundle.json`, and terminal verification snippet.

---

## 5. VulnTrace-Bench Protocol & Evidence Engine

### 5.1 Benchmark Case Set

VulnTrace-Bench evaluates remediation capability across an empirical dataset:
1. **Real Repositories (Reachable Vulnerabilities):** Pinned commit SHAs from public repositories across supported sink classes (e.g. Flasgger CVE-2018-1000156).
2. **Negative Reachability Cases:** Repositories containing vulnerable dependencies where AST analysis confirms the sink is uncalled from public entrypoints, yielding `NO_STATIC_PATH_FOUND`.
3. **Already-Safe Cases:** Patched or safe versions confirming `NOT_VULNERABLE_ALREADY_SAFE`.
4. **Contextual Patch Cases:** Cases requiring custom loaders or configuration preservation rather than naive dependency bumps.
5. **Adversarial Bad-Patch Zoo:** Negative controls evaluated to ensure 0 false-GREEN verdicts.
6. **Held-Out Test Cases:** Segregated test cases reserved exclusively for validation, never used for agent prompt tuning (`bench/HELDOUT.md`).

### 5.2 Evaluation Protocol

- **3 Repeats per Case:** Every benchmark entry is executed across 3 independent runs; results report the distribution of observed verdicts.
- **Automated CI Generation:** The benchmark runner (`python bench/run.py --ci`) generates `docs/evidence/benchmark_results.json` and updates the README benchmark table. Continuous integration verifies that committed documentation matches runtime benchmark observations with zero drift.

---

## 6. Engineering Roadmap & Acceptance Gates

### M0 — Baseline Audit & Repository Hygiene
- Complete architectural inventory (EXISTS/EXTEND/NEW mapping).
- Clean baseline test execution under containerized and host runners.
- Establishment of repository hygiene rules, CI skeleton, and safety guidelines.

### M1 — Verifier Hardening & Deserialization Oracle
- Implementation of YAML and pickle deserialization oracles with structured canary verification.
- Anti-gaming verifier gates and bad-patch zoo evaluation (0 false-GREENs).
- Evidence bundle generation with SHA-256 telemetry verification.

### M2 — Environment Builder & Real-Repository Evaluation
- Automated virtualenv builder with declared dependency resolution.
- Flasgger (CVE-2018-1000156) evaluation across 3 independent repeats.
- Explicit classification of environment build failures (`ENV_BUILD_FAILED`).

### M3 — Isolation Tier 1 (Rootless Container Execution)
- Rootless container execution backend (Podman/Docker/WSL2) with `--network none` and read-only root.
- Strict Zero-Trust policy: Tier 0 restricted to curated developer fixtures; untrusted code requires Tier 1.
- Adversarial isolation tests: network denial, filesystem write containment, resource limits.

### M4 — Threat Intelligence & Tiered LLM Inference
- Tavily API runtime query integration and `ThreatIntel` normalization.
- Nebius Token Factory client integration with tiered Nemotron models.
- Per-stage token ledger accounting and cassette-backed deterministic offline test suite.

### M5 — Studio Backend & Evidence Signing
- Ingest guards (zip-slip, absolute path, decompression bombs, git hook neutralization).
- Scope guard, diff budget, and AST syntax gates.
- Ed25519 evidence bundle signing and `vulntrace verify-bundle` validation CLI.

### M6 — Guided User Interface
- Seven-step guided single-page React frontend connected to SSE backend events.
- Real-time verification timeline, side-by-side diff viewer, and evidence inspection panels.
- Zero console errors, full accessibility support, and responsive layouts.

### M7 — Intent Synthesis & Additional Sink Classes
- Structured requirement parsing (`Spec` object) and acceptance test synthesis.
- Path Traversal and Command Injection sink-class oracles.
- Benchmark expansion with verified held-out test case segregation.

### M8 — Benchmark Stabilization & Evidence Documentation
- Full multi-repeat benchmark execution across all supported cases.
- Automated CI consistency verification between README benchmark table and raw observations.
- Finalization of architecture documentation and security operational guidance.

### M9 — Packaging, Verification Walkthrough & Operational Readiness
- End-to-end rehearsal of the complete guided remediation flow.
- Production build validation of frontend and backend packages.
- Final security and dependency audit.

---

## 7. Quality Gates & Continuous Integration

### Continuous Integration (`.github/workflows/ci.yml`)
1. **Linting & Type Safety:** `ruff check` and type conformance across core modules.
2. **Offline Hermetic Testing:** `pytest` executed with network sockets blocked; unit tests run via deterministic cassettes.
3. **Benchmark Consistency:** Verification that `bench/run.py --ci` produces zero drift against committed benchmark tables.
4. **Security Analysis:** Secret scanning and license compliance checks.

### Milestone Acceptance Gate (Definition of Done)
1. All acceptance criteria satisfied with empirical command output.
2. Continuous integration workflow green on `main`.
3. Architecture and safety documentation updated.
4. At least one empirical defect discovered through execution and resolved.
5. All untrusted code execution verified under Tier 1 isolation boundaries.

---

## 8. Agent Engineering Directives (`AGENTS.md`)

```
# VulnTrace Studio — Agent Rules

1. The repository is the single source of truth. If docs/spec and code disagree, STOP and report. Do not choose silently.
2. Before creating any component, inspect the repo and reuse or extend what exists. State what you found.
3. Flag any out-of-scope change BEFORE implementing it. Out of scope = anything not required by the current milestone's acceptance criteria.
4. Preserve exact specifications: verdict strings (spec §3.2), evidence schema field names (spec §4.11), CLI names, and API routes. Do not rename without owner approval.
5. "Done" requires executed evidence: paste real command output for every acceptance criterion. Code review alone is not evidence.
6. Prefer catching real bugs through execution. Run the tests, the benchmark, and the UI. Report at least one real failure you caught and fixed.
7. Never claim a number, capability, or security property that a command has not demonstrated. No unsourced percentages.
8. Untrusted-code rule: never execute target-repo code outside the sandbox tier required by the spec. Tier 0 is strictly for curated fixtures.
9. Secrets: never print, log, commit, or pass API keys into sandboxes or bundles.
10. Payload policy: behavioral probes only. No shells, no network callbacks, no destructive actions.
11. LLM calls: unit tests use cassettes and make zero live calls. Live calls only with LIVE_LLM=1.
12. Commit small. One logical change per commit. Message states the AC it satisfies.
13. End every milestone with the structured milestone report.
```

---

## 9. Reporting Standards & Verification Templates

### 9.1 Milestone Execution Report Template
```markdown
## Milestone <Mx> Report
**Status:** Completed / Blocked
**Components Changed/Added:** List of modified modules and EXISTS/EXTEND/NEW classification.
**Acceptance Criteria Verification:** Each AC with command invoked and actual terminal output.
**Real Bugs Caught by Execution:** Defect description, reproduction method, and implemented fix.
**Evidence Artifacts:** Generated bundles, diffs, logs, and screenshots.
**Out-of-Scope Items:** Any flagged items deferred or rejected.
**Discrepancies Encountered:** Spec vs code differences identified.
**Resource & Token Metrics:** Token ledger summary by pipeline stage.
```

### 9.2 Adversarial Review Checklist
1. Did the test harness execute outside the patched workspace?
2. Did the verification run confirm the specific exception signature rather than generic failure?
3. Did the positive control input succeed on the patched code?
4. Were baseline regression tests verified on the patched codebase?
5. Did the test execution observe Tier 1 container isolation for non-curated inputs?

---

## 10. Technical Risk Register & Mitigations

| Risk | Likelihood | Impact | Technical Mitigation | Trigger / Fallback |
|---|---|---|---|---|
| **Container isolation unavailable on host** | Medium | High | Support Podman/Docker on WSL2; detect environment capabilities cleanly. | If unavailable, refuse untrusted execution and operate in replay mode. |
| **Target repository dependencies fail to build** | Medium | Medium | Dedicated per-case virtualenvs with wheel caching and dependency isolation. | Emit honest `ENV_BUILD_FAILED` with build logs rather than masking. |
| **Verifier false-GREEN verdict** | Low | Critical | Multi-repeat runs, bad-patch zoo regression testing, and canary state assertions. | Any false GREEN immediately halts releases until resolved. |
| **External inference provider rate limits** | Medium | Medium | Cassette recording for testing; token budgeting and retry with backoff. | Fall back to cached recordings during test suites. |
| **Tavily threat intelligence service outage** | Low | Low | Graceful degradation to `intel_status: degraded` without failing pipeline. | Analysis continues with static heuristics; status noted in bundle. |
| **Prompt injection via target repository text** | Medium | High | Treat repo text as untrusted data blocks; restrict agent capabilities to bounded search/replace edits. | Flag suspicious content; enforce plan-scope guards. |
| **Specification and implementation drift** | Medium | Medium | Continuous integration benchmark verification (`bench/run.py --ci`). | CI fails on any drift between documentation and runtime data. |
