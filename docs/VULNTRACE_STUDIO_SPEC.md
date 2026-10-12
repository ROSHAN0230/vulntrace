# VulnTrace Studio — Flagship Implementation Spec

**Target:** NVIDIA × Nebius Global AI Hackathon (Devpost)
**Hard deadline:** Fri Oct 30, 2026, 10:00 PDT (= 22:30 IST). **Internal submit target: Wed Oct 28.**
**Spec version:** v1 — written Sat Oct 3, 2026
**Audience:** Antigravity agents, ChatGPT, and the owner (Roshan)
**Base repo:** https://github.com/ROSHAN0230/vulntrace (Apache-2.0, Python + FastAPI + React)

---

## 0. How to use this document

**Golden rule: the repo is the single source of truth.** If this spec disagrees with the repo's reality, STOP, report the discrepancy, and wait. Do not silently "fix" either side.

**Antigravity (builder):**
1. Put Section 8 (the rules block) into `AGENTS.md` at the repo root and into Antigravity's workspace rules (check current Antigravity docs for the exact location).
2. Give one agent **one milestone** (Section 6) at a time. Use the prompt template in Section 9.1.
3. A milestone is not done until the agent pastes real command output proving each acceptance criterion (AC), including at least one real failure it caught and fixed.
4. Use the browser agent to click through the UI for every UI milestone.

**ChatGPT (architect / reviewer / pair):**
1. Paste Sections 2–4 once as context, then one milestone at a time.
2. Use it for design review, test-first scaffolding of hard modules (verifier, sink oracles, environment builder), and adversarial review of Antigravity's milestone reports (template in Section 9.2).
3. Never accept "looks correct". Ask for the test that would fail if it were wrong.

**Owner:** you merge only after the milestone report (Section 9.3) is complete and the CI is green.

---

## 1. Competition constraints (hard requirements)

Items marked **[VERIFY]** came from secondary sources or memory. Re-check them on the official Devpost rules page before relying on them.

| # | Constraint | Implication for us |
|---|---|---|
| C1 | Project must run on **Nebius Token Factory or Nebius AI Cloud** | Every LLM call goes through Token Factory at runtime. Log it. |
| C2 | Must use at least one **NVIDIA open-source model** (Nemotron) | Nemotron does real work in the pipeline (triage, spec, patch), not decoration. |
| C3 | **Public repo with an OSI license visible at top of the repo page** | Apache-2.0 already present. Keep it visible in the About section. |
| C4 | **Demo video under 3 minutes**, public (YouTube) **[VERIFY]** | Script in Section 11.3. Never exceed 2:55. |
| C5 | Working demo / way for judges to test **[VERIFY exact wording]** | Hosted curated demo + one-command local run (Section 4.14). |
| C6 | One Overall award OR one Track award, plus one Bonus award | Target: Coding & Agentic Engineering track + Tavily bonus. |
| C7 | **Tavily bonus requires a functional runtime call to the Tavily API** | Tavily call in every analysis run; visible in evidence bundle and UI. OSV alone does not count. |
| C8 | Judged on Technological Implementation, Quality of the Idea, Design, Potential Impact (equally weighted) | Each criterion gets explicit features (Section 2.4). |
| C9 | Written feedback on Nebius/NVIDIA tooling may be required **[VERIFY]** | Keep a running `docs/FEEDBACK_NOTES.md` from day 1. |
| C10 | If the project existed before the submission period, explain what was significantly updated **[VERIFY]** | Keep `docs/CHANGELOG_HACKATHON.md`: one dated entry per milestone. |
| C11 | Nebius credits are limited (third-party sources mention ~$25 + ~$25 via the Builders Program) **[VERIFY]** | Budget plan in Section 12. Record/replay LLM calls in dev. |
| C12 | Coding & Agentic track reportedly emphasizes agents that write, run, and test code in Token Factory Sandboxes **[VERIFY]** | Ask organizers about sandbox access (the existing ConTree 403 may be related). If granted, it becomes Isolation Tier 2. |

Scale: roughly 16,000 registered participants. A generic coding agent will not stand out. Evidence-backed security remediation can.

---

## 2. The Council

### 2.1 Seats

| Seat | Mandate | Would attack | Veto power over |
|---|---|---|---|
| **S1 Judge Chair** (Nebius/NVIDIA view) | Does it use Token Factory + Nemotron meaningfully and visibly? | Thin API wrapper; Nemotron only used once; no cost/latency awareness | Anything that makes Nebius/Nemotron use invisible |
| **S2 AppSec Lead** | Are the security claims true? | Unsound reachability presented as proof; false-positive GREEN; weaponized PoCs | Any verdict wording that overclaims |
| **S3 Platform Safety** | Can untrusted repos/uploads hurt the host or other users? | Local-subprocess sandbox; zip-slip; running repo tests on host; prompt injection via repo text | Any feature that executes untrusted code without isolation |
| **S4 Product & Design** | Is it a complete, coherent product experience? | CLI-only feel; logs instead of evidence; confusing flow | UI that hides the evidence |
| **S5 Competitor Scout** | What do Snyk/Endor/Semgrep/Dependabot/Copilot Autofix and other entrants already do? | Strawman comparisons; "no one does reachability" claims | Any competitor claim without a hedge |
| **S6 Evidence Auditor** | Does every README claim map to a command and an artifact? | Unsourced percentages; "cryptographic" without signatures; toy-repo benchmarks | Any number not regenerated by CI |
| **S7 Delivery Manager** | Can this ship in 25 days with free tools? | Scope creep; late integration; no buffer | Any feature after the freeze (Oct 24) |
| **S8 FinOps** | Will credits last through development and judging? | Burning tokens in dev loops; no budget per run | Live LLM calls in unit tests |
| **S9 Demo Director** | Does the 3-minute video land and is the demo path reliable? | Flaky live runs; too many ideas in 3 minutes | Any demo step not rehearsed 5 times |

### 2.2 Decision log (conflicts and rulings)

| ID | Question | Ruling | Reason |
|---|---|---|---|
| D1 | Breadth (many languages/CVEs) vs depth | **Depth: Python only, 3 vulnerability classes** | Evidence beats breadth (S6, S7) |
| D2 | LLM-written harness vs templated oracle | **Templated sink-class oracles; LLM only fills parameters** (target symbol, input shape, expected exception) | Deterministic RED/GREEN; defends "deterministic" claim (S2) |
| D3 | Local subprocess sandbox | **Dev-only. Refuses untrusted input.** Real runs use rootless Docker (Tier 1) or Nebius sandbox (Tier 2) | S3 veto |
| D4 | Arbitrary uploads on the public hosted demo? | **No.** Hosted demo = curated sample repos + replay of recorded runs. Arbitrary upload/clone = local mode only | Cost, abuse, safety (S3, S8) |
| D5 | General "change request" prompts | **Two modes:** (a) Guided remediation (default); (b) Change request, **stretch**, only if acceptance tests can be synthesized, else `UNVERIFIABLE` | Honesty (S2, S6) |
| D6 | Auto-open GitHub PRs | **Cut from core.** Export `.diff` + zip + `git apply` snippet. PR = stretch after M8 | Token handling risk, time |
| D7 | "Cryptographic evidence" | **Sign bundles with Ed25519.** README explains: signature proves integrity, not truth | S6 |
| D8 | "UNREACHABLE" verdict | **Rename to `NO_STATIC_PATH_FOUND`** with a list of what static analysis cannot see | S2 |
| D9 | Competitor table | **Rewrite**: compare on "behavioral proof + verified patch", not "no reachability exists" | S5 |
| D10 | Tavily usage | **Real dependency, not decoration:** results select sink class/symbols and are cited in the evidence bundle. Failure degrades gracefully and is recorded | C7, S1 |
| D11 | Nemotron usage | **Tiered:** small model for triage, mid for planning/spec, Ultra for patching/repair. Token ledger per stage in UI | S1, S8 |
| D12 | Live demo vs recorded | **Both:** video uses a pre-verified real run; hosted demo can replay. One live run rehearsed 5x | S9 |
| D13 | Feature freeze | **Sat Oct 24.** After: bugfixes, benchmark, README, video only | S7 |
| D14 | What counts as "done" | **Executed evidence** (command output, artifact), never code review alone | S6 |

### 2.3 Idea selection recap

VulnTrace Studio scored 23/25 against five alternatives (TestForge 20, UpgradeProof 19, generic verified coding agent 16, legacy modernization 16, generic assistant 14). It wins on track fit, feasibility (existing pipeline), and measurable evidence. UpgradeProof's "verified dependency bump + call-site migration" may be added later as one remediation strategy, never as a separate product.

### 2.4 What "flagship" means per criterion

| Criterion | Target | Features that earn it |
|---|---|---|
| Technological Implementation | 9 | Anti-gaming verifier with red-team zoo; env builder for real repos; Tier-1 isolation; tiered Nemotron use with token ledger; signed evidence |
| Quality of the Idea | 8.5 | Proof-carrying remediation; requirement-to-acceptance-test loop; honest verdict taxonomy incl. `UNVERIFIABLE` |
| Design | 8.5 | Guided 7-step flow, evidence timeline, side-by-side RED/GREEN, diff view, one-click export |
| Potential Impact | 8.5 | Cuts alert triage; patches come with proof; works on real repos; CI-reproducible benchmark |

**Definition of 9/10 (all must be true by Oct 27):**
1. ≥3 real public repos reach a verified verdict (GREEN or honest, explained non-GREEN) with pinned commits.
2. ≥3 vulnerability classes in the benchmark.
3. Bad-patch zoo: 0 false GREENs.
4. Tavily call present in 100% of analysis bundles.
5. All LLM calls via Token Factory; token ledger visible in UI.
6. Tier-1 isolation active for every non-curated run.
7. README numbers regenerated by CI from `benchmark_results.json`.
8. Video < 3:00, one reliable end-to-end path.

---

## 3. Product definition

**Name:** VulnTrace Studio
**One line:** *Upload a Python repo, state a requirement, and get a patch that is only called fixed when a RED test turns GREEN and the repo's baseline tests still pass.*

**Positioning:** proof-carrying remediation. Not "AI that edits code", but "AI whose edits come with evidence".

**Users:** developers and small teams drowning in dependency alerts; maintainers who need a verified minimal fix.

**Hero demo (3 min):** upload repo → analysis shows findings, Tavily intel, reachability → user types "fix the YAML deserialization but keep my custom tags" → plan approval → RED → Nemotron patch → GREEN → regressions vs baseline → export patch.

**Non-goals (do not build):** multi-language support; auto-merge; auto-PR in core; SaaS accounts/auth; persistent multi-tenant hosting; arbitrary upload on the public demo; weaponized exploit payloads; "AI finds zero-days".

### 3.1 Verdict taxonomy (exact strings; do not rename without owner approval)

| Verdict | Meaning |
|---|---|
| `GREEN_STATE_VERIFIED` | RED reproduced (3/3), patch accepted, GREEN blocked (3/3), baseline tests not regressed |
| `NO_STATIC_PATH_FOUND` | Static analysis found no call path from entrypoints; lists blind spots (reflection, dynamic import, monkey-patching) |
| `NOT_VULNERABLE_ALREADY_SAFE` | Vulnerable pattern absent or already patched |
| `RED_NOT_REPRODUCED` | Reachable but behavior not observed; inconclusive, with reason |
| `RED_STATE_PERSISTS` | Patch applied but vulnerable behavior still observed |
| `PATCH_REJECTED` | Syntax, scope, denylist, or diff-budget gate failed |
| `REGRESSION_FAILURE` | Security fixed but tests that passed at baseline now fail |
| `VERIFICATION_REJECTED` | Evidence integrity failure (harness hash changed, forged output, policy violation) |
| `ENV_BUILD_FAILED` | Could not build the target's environment (distinct from tool failure) |
| `UNVERIFIABLE` | Requirement could not be converted into a failing acceptance test |
| `UNEXPECTED_FAILURE` | Internal error; always includes traceback reference |

---
## 4. Architecture

> **Before building any component below: inspect the repo and reuse what exists.** Mark each component EXISTS / EXTEND / NEW in the M0 audit. Do not create a parallel implementation of something already in `vulntrace/`.

### 4.1 Pipeline

```
[1 INGEST]  zip upload | GitHub URL (public)
    │  guards: size, zip-slip, symlinks, no git hooks, shallow clone
    ▼
[2 ANALYZE]
    ├─ baseline test run (record pass/fail per test)      ← regression reference
    ├─ dependency inventory + OSV lookup
    ├─ Tavily intel (RUNTIME CALL, logged)                ← selects sink class + symbols
    └─ AST call-graph reachability from entrypoints
    ▼
[3 INTENT]  user requirement → structured Spec → acceptance test(s)
    │  cannot produce a failing test → UNVERIFIABLE
    ▼
[4 PLAN]    files to touch, strategy, budget → USER APPROVES
    ▼
[5 EDIT]    Nemotron edits a DISPOSABLE COPY (search/replace ops, repair loop ≤3)
    │  gates: syntax, plan-scope, denylist, diff budget
    ▼
[6 VERIFY]  RED×3 → patch → GREEN×3 (identical harness hash) → regressions vs baseline
    ▼
[7 EVIDENCE] signed bundle + UI timeline + diff
    ▼
[8 EXPORT]  .diff | zip | `git apply` snippet   (PR = stretch)
```

### 4.2 Components

| Component | Responsibility | Status (fill in at M0) |
|---|---|---|
| `ingest/` | Safe zip/clone, workspace creation | |
| `analysis/` | Dependency inventory, OSV, baseline tests, call graph | |
| `intel/` | Tavily + OSV client, `ThreatIntel` object | |
| `sinks/` | Sink-class oracle library (4.3) | |
| `verifier/` | RED/GREEN runner, anti-gaming checks (4.4) | |
| `envbuild/` | Per-case venv builder (4.5) | |
| `sandbox/` | Isolation tiers (4.6) | |
| `llm/` | Token Factory client, model tiering, schemas, cassettes (4.7) | |
| `intent/` | Requirement → Spec → acceptance tests (4.9) | |
| `agent/` | Edit loop, scope guard (4.10) | |
| `evidence/` | Bundle schema, hashing, Ed25519 signing (4.11) | |
| `server/` | FastAPI + SSE | |
| `ui/` | React flow (4.13) | |
| `bench/` | VulnTrace-Bench runner (Section 5) | |

### 4.3 Sink-class oracle library

Each sink class is a small, reviewed module. The LLM never writes the oracle.

| Class | Sink patterns (examples) | Benign oracle | Expected block signal |
|---|---|---|---|
| **Unsafe deserialization** | `yaml.load` with unsafe Loader, `pickle.loads` | Object instantiation that creates a **canary file inside the workspace temp dir** | Specific constructor/unpickling error class, not just any exception |
| **Path traversal** | `tarfile.extractall`, `zipfile.extractall`, file-serving helpers | Archive with an entry that would escape the target dir; oracle checks a canary path outside extraction root | Extraction refused or path normalized; canary absent |
| **Command injection** | `subprocess(..., shell=True)`, `os.system` with user data | Argument containing a benign marker command that writes a canary | Marker not executed; canary absent |

Every oracle ships with:
- **Positive control:** benign valid input must still work after the patch.
- **Expected-failure signature:** the exact exception class/message family that means "blocked".
- **Safe-pattern list:** what a correct fix looks like (used by the plan stage and by the denylist).
- **Unit tests** against a vulnerable fixture, a fixed fixture, and the bad-patch zoo.

Payload policy: **behavioral probes only.** No shells, no network callbacks, no destructive actions, no data exfiltration. Document this in `docs/SAFETY.md`.

### 4.4 Verifier (anti-gaming)

Required checks before any `GREEN_STATE_VERIFIED`:
1. RED reproduced **3/3** runs with the **expected** failure/observable (not an import error).
2. Harness and test files are **outside the patched tree**; their SHA-256 is recorded pre- and post-patch and must match.
3. GREEN must show the **expected block signature** (specific exception class) **and** the positive control passes **and** canary absent. A bare exit code 42 is never sufficient.
4. Patch denylist: no new `sys.exit`, `os._exit`, `os.kill`, `exit(`, broad `except: pass` around the sink, edits to harness/test/config files, or writes outside the target file set.
5. Regression compare: per-test baseline vs after (new failures only count against the patch; pre-existing failures are reported separately).
6. Flake check: GREEN 3/3.

**Bad-patch zoo (≥8, all must be non-GREEN):** raise unconditionally; return `None`; delete the function; comment out the sink; wrap in `try/except: pass`; inject `sys.exit(42)`; modify the harness; patch tests only; change sentinel path; empty diff.

Known limit, to be stated in the README: the oracle defends against common failure modes, not against an adversarial patch author with full knowledge of the harness.

### 4.5 Environment builder

- One venv per case, outside the workspace.
- Install target dependencies from the repo's declared files with a **network window only during install**; run harness and tests **offline**.
- Wheel cache to keep runs fast and credits low.
- Failure classes: `ENV_BUILD_FAILED` (with pip log excerpt), never `UNEXPECTED_FAILURE`.
- Python version recorded in the bundle.

### 4.6 Isolation tiers

| Tier | Mechanism | Used for |
|---|---|---|
| 0 | Local subprocess | **Developer machine & curated fixtures only.** Refuses non-curated or untrusted repositories unconditionally. Tier 1 is mandatory for all real/non-curated runs; `--unsafe-local` overrides are prohibited. |
| 1 | Rootless Docker (Docker Desktop/WSL2 on Windows): no network at run time, read-only root FS, tmpfs scratch, non-root user, CPU/memory/pids limits, wall-clock timeout, no host mounts except the workspace copy | Default for all real runs |
| 2 | Nebius sandbox / Serverless Job if access is granted **[VERIFY]** | Stretch; strongest story for the Nebius criterion |

> **Owner Policy Decision (Oct 12, 2026 — Option A Strict Zero-Trust Policy):**
> Per explicit owner authorization, non-curated or untrusted repositories must never execute using Tier 0, regardless of `unsafe_local=True`, `--unsafe-local`, or `VULNTRACE_UNSAFE_LOCAL=1`. Tier 1 rootless container isolation is mandatory for all real/untrusted repositories. Tier 0 execution is strictly restricted to curated developer fixtures.

The README must state the **real** boundary of the tier used in each benchmark run. Never write "isolated sandbox" for Tier 0.

If Docker is unavailable on the owner's machine by Oct 12: fall back to replay-only hosted demo plus documented Tier 1 instructions, and flag the risk in the milestone report.

### 4.7 LLM layer

- All calls to **Nebius Token Factory** (OpenAI-compatible client). Model IDs from config; confirm exact Nemotron model IDs in the Token Factory catalog **[VERIFY]**.
- **Tiering:** small model for triage and classification; mid model for planning and spec/test synthesis; Ultra for patch generation and repair.
- **Structured output:** JSON validated against Pydantic schemas; reject and retry (max 2) on invalid output.
- **Edit format:** search/replace blocks with exact-match requirement. No whole-file rewrites.
- **Token ledger:** per stage prompt/completion/reasoning tokens and latency, shown in UI and stored in the bundle.
- **Cassettes:** record/replay layer so unit tests and CI make **zero** live LLM calls; `LIVE_LLM=1` enables live calls for the benchmark and demo runs.
- **Injection policy:** repository text (README, comments, docstrings, issue text) is untrusted data. Prompts wrap it in delimited data blocks, and the agent has no tools beyond "propose edit ops in the workspace".

### 4.8 Tavily layer

- Called in every analysis run with queries like `<CVE-ID> vulnerable function fix commit`.
- Output normalized into a `ThreatIntel` object: affected symbols, fix patterns, references (URLs), confidence.
- `ThreatIntel` **changes behavior:** it selects/validates the sink class and candidate symbols. It is not decoration.
- Bundle records: query, timestamp, result URLs, response hash. UI shows "Intel sources" with links.
- Failure mode: run continues with `intel_status: degraded`; the verdict is unaffected but the degraded state is displayed.

### 4.9 Requirement → acceptance test

1. Parse the requirement into `Spec { must_fix, must_preserve[], constraints[], out_of_scope[] }`.
2. Map to a sink-class oracle when it is a security requirement. For behavior-preservation constraints (e.g. "keep custom YAML tags"), generate a pytest acceptance test using existing repo fixtures.
3. **Test-quality gates:** the test must fail on the original code **for the expected reason**; must exercise the target symbol (coverage of target lines); must contain real assertions (static check; no `assert True`).
4. If any gate fails: `UNVERIFIABLE` with the reason. Never fake a test.
5. **Change-request mode (stretch):** same flow; only attempted for requirements whose behavior is observable via a deterministic test.

### 4.10 Agent edit loop and scope guard

1. Plan: files to touch, strategy, diff budget (default ≤30 changed lines, ≤3 files, configurable). User approves.
2. Edit ops applied to the disposable copy.
3. Gates in order: syntax parse → plan-scope (files outside the approved plan are flagged and blocked unless the user approves) → denylist → diff budget.
4. Run verifier. On failure, feed the structured failure back for up to **3** repair attempts, then stop with the honest verdict.
5. Every attempt is stored in the bundle (diff + result), including failed ones.

### 4.11 Evidence bundle

JSON schema v1 (`docs/evidence/schema_v1.json`):

```
run_id, created_at, tool_versions, python_version
source: {type, url|upload_sha256, commit}
sandbox: {tier, limits, network_policy}
intel: {status, queries[], urls[], response_hashes[]}
analysis: {findings[], reachability{paths[], blind_spots[]}, baseline_tests{}}
spec: {requirement, parsed_spec, acceptance_tests[]}
llm: {calls[{stage, model, prompt_tokens, completion_tokens, reasoning_tokens, latency_ms}]}
verification: {harness_sha256, red_runs[3], green_runs[3], positive_control, regression{new_failures[], preexisting_failures[]}}
attempts[]: {diff, gates{}, result}
verdict, limitations[]
signature: {alg: "Ed25519", public_key_fingerprint, sig}
```

CLI: `vulntrace verify-bundle bundle.json` recomputes hashes and checks the signature. Signing key is generated on first run and stored locally, never committed.

### 4.12 API and data model

- `POST /runs` (source) → `run_id`
- `GET /runs/{id}/events` (SSE stage events + token ledger)
- `POST /runs/{id}/intent` (requirement)
- `POST /runs/{id}/approve-plan`
- `GET /runs/{id}/bundle`, `GET /runs/{id}/diff`, `GET /runs/{id}/export?format=diff|zip`
- SQLite tables: `runs`, `events`, `artifacts`, `llm_calls`. Workspaces on disk under a configurable root, deleted after TTL.

### 4.13 UI spec (single-page guided flow)

Seven-step stepper with persistent run header (verdict badge, token ledger, sandbox tier).

| Step | Screen | Must show |
|---|---|---|
| 1 Source | Upload / GitHub URL | Safety notice (what executes where), curated sample repos |
| 2 Analysis | Findings table, reachability graph | Baseline test result, Tavily sources with links, blind-spot panel |
| 3 Requirements | Prompt box + templates ("fix but preserve X") | Parsed Spec preview; `UNVERIFIABLE` warning before running |
| 4 Plan | Files/strategy/budget | Approve / edit / cancel |
| 5 Live run | Streaming stage timeline | RED 1/3..3/3, patch attempt N/3, token ledger |
| 6 Evidence | Side-by-side RED vs GREEN, diff view, regression table (baseline vs after) | Verdict with exact taxonomy string and limitations |
| 7 Export | Download `.diff`, zip, bundle, `git apply` snippet | Verify-bundle command |

Non-negotiables: empty/loading/error states on every step; keyboard accessible; dark/light; no layout shift during streaming; copy-to-clipboard on commands; mobile-readable evidence page. Browser-agent smoke test in CI-adjacent script.

### 4.14 Platform security (the tool must be safe itself)

- Upload: max size, max file count, zip-slip and absolute-path rejection, symlink rejection or neutralization, decompression-ratio limit.
- Clone: HTTPS public repos only, `--depth 1`, hooks and `core.fsmonitor` disabled, no submodule recursion unless allowlisted, no credentials.
- Secrets: child processes get a scrubbed environment; API keys never enter sandboxes or bundles.
- Hosted demo: curated repos + replay only; rate limit; no arbitrary execution (D4).
- Logs: no secrets, no raw repo text beyond excerpts needed for evidence.
- `docs/SAFETY.md` documents threat model, boundaries per tier, and known limits.

### 4.15 Target repo layout

```
vulntrace/
  AGENTS.md                 # rules block (Section 8)
  README.md                 # TL;DR, screenshot/GIF, quickstart, benchmark table (CI-generated)
  LICENSE                   # Apache-2.0
  pyproject.toml
  vulntrace/                # package (ingest, analysis, intel, sinks, verifier, envbuild, sandbox, llm, intent, agent, evidence, server, bench)
  ui/
  tests/                    # unit, verifier/, sinks/, e2e/ (cassette-backed)
  bench/                    # VulnTrace-Bench cases + pinned commits
  docs/
    SAFETY.md
    ARCHITECTURE.md
    FEEDBACK_NOTES.md
    CHANGELOG_HACKATHON.md
    evidence/               # schema, sample bundles, verifier red-team report
    archive/                # old PHASE_* reports and audits moved here
  .github/workflows/ci.yml
```

---
## 5. VulnTrace-Bench (the evidence engine)

**Goal:** a CI-reproducible benchmark whose numbers go into the README automatically.

### 5.1 Case set (minimum 10)

| Type | Count | Notes |
|---|---|---|
| Real public repo, vulnerable commit, reachable | ≥3 | Pinned commit SHAs; at least one per sink class; includes Flasgger (RW-01) |
| Real repo, dependency present but no static path | ≥2 | Must yield `NO_STATIC_PATH_FOUND` with blind spots listed |
| Already-patched version | ≥1 | `NOT_VULNERABLE_ALREADY_SAFE` |
| Contextual-patch case (custom loader / `AppSafeLoader`) | ≥1 | Run **naive baseline** (regex/`safe_load` swap or version bump) next to VulnTrace; report which passes harness + tests |
| Bad-patch zoo | ≥8 patches | 0 false GREEN |
| Curated synthetic fixtures | any | Allowed, but **labeled synthetic** and excluded from headline numbers |

### 5.2 Protocol

- Each case: 3 repeats; report verdict distribution, not just best run.
- Headline table reports numerator/denominator for: reachable identified, RED reproduced, patch accepted, GREEN verified, regressions, false GREEN (zoo), env-build failures, tokens per case, latency per stage.
- Never tune on a case and then report it as held-out. Keep a `bench/HELDOUT.md` list of ≥3 cases not used during development.
- `bench/run.py --ci` regenerates `benchmark_results.json` and the README table; CI fails if the committed README table differs from the generated one.
- Report honest failures. A well-explained `ENV_BUILD_FAILED` beats a hidden one.

---

## 6. Milestones

Calendar: Oct 3 (Sat) → Oct 30 (Fri). **Feature freeze Sat Oct 24.** Each milestone ends with the report in Section 9.3. "Cut-line" says what to drop first if the milestone slips; the Delivery Manager seat enforces it.

### M0 — Baseline audit and hygiene (Oct 3–4)

**Tasks**
- Inspect repo; fill the EXISTS/EXTEND/NEW column in 4.2.
- Run current tests and benchmark; save outputs to `docs/evidence/baseline_run.md`.
- Fix README clone URL (`ROSHAN0230/vulntrace`) and add `--recurse-submodules` if `.gitmodules` is used.
- Move `PHASE_*`, `FINAL_*_AUDIT.md`, screenshots, stray root scripts into `docs/archive/` or `docs/`.
- Add `AGENTS.md` (Section 8), CI skeleton, `docs/FEEDBACK_NOTES.md`, `docs/CHANGELOG_HACKATHON.md`.
- Fill GitHub About: description, topics, website placeholder.
- Owner: claim credits; ask Nebius/organizers about Token Factory Sandboxes and the ConTree 403; verify all **[VERIFY]** items in Section 1.

**AC**
- `git clone --recurse-submodules <url> && cd vulntrace && pip install -e . && pytest -q` passes in a clean container (paste output).
- Repo root has ≤10 files/dirs besides hidden files.
- `baseline_run.md` contains real command output, not summaries.

**Cut-line:** none; this is cheap and mandatory.

### M1 — Verifier hardening + deserialization oracle (Oct 5–7)

**Tasks:** implement 4.3 (deserialization class) and 4.4 fully; build the bad-patch zoo.

**AC**
- `pytest tests/verifier/ -q` passes.
- Every zoo patch → non-GREEN verdict (print the verdict table).
- Good patch → GREEN 3/3.
- A harness crash that exits 42 does **not** produce GREEN (explicit test).
- `docs/evidence/verifier_redteam.md` generated from a real run.

**Cut-line:** zoo can shrink to 6 patches; the positive control and expected-signature checks cannot be cut.

### M2 — Environment builder and first real-repo success (Oct 7–10)

**Tasks:** implement 4.5; fix the RW-01 (Flasgger) `jsonschema` failure properly via the builder, not a one-off install.

**AC**
- Flasgger vulnerable commit: run 3×; verdicts identical; either `GREEN_STATE_VERIFIED` or an honest verdict with root cause documented.
- Environment build time and Python version recorded in the bundle.
- A deliberately broken `requirements` file yields `ENV_BUILD_FAILED`, not `UNEXPECTED_FAILURE`.

**Cut-line:** if Flasgger cannot reach GREEN by Oct 10, pick another real repo and keep Flasgger as a documented honest failure. Do not hide it.

### M3 — Isolation Tier 1 (Oct 8–12)

**Tasks:** rootless Docker runner per 4.6; Tier-0 refusal of untrusted input; `docs/SAFETY.md`.

**AC**
- From inside the sandbox: outbound network request fails; write to host path fails; fork bomb/memory hog is killed by limits; both proven by tests with real output.
- Same verifier suite passes under Tier 1.
- README states the tier used for each benchmark case.

**Cut-line:** if Docker is unavailable, switch to the fallback in 4.6 on Oct 12 and record the risk. If Tier 2 access arrives, implement it after M7, not before.

### M4 — Intel (Tavily) and LLM layer (Oct 11–14)

**Tasks:** 4.7 and 4.8: Token Factory client, tiering, schemas, cassettes, token ledger; Tavily + OSV into `ThreatIntel`.

**AC**
- Live analysis run (`LIVE_LLM=1`) produces a bundle containing ≥1 Tavily call with URLs and hashes, and a per-stage token ledger with ≥2 different model tiers.
- `pytest` runs with zero network calls (verified by blocking sockets in the test harness).
- Killing Tavily (bad key) yields `intel_status: degraded` and the run completes.
- `ThreatIntel` demonstrably changes behavior: a test shows different symbol/sink selection with and without intel.

**Cut-line:** a third model tier can be dropped; Tavily runtime call and ledger cannot.

### M5 — Studio backend and evidence signing (Oct 12–17)

**Tasks:** ingest guards (4.14), baseline test run, plan approval flow, disposable workspace, scope guard, export (`.diff`, zip), API/SSE (4.12), evidence signing and `verify-bundle` (4.11).

**AC**
- Malicious zip fixtures (zip-slip, symlink escape, decompression bomb) are rejected with tests.
- GitHub clone of a public repo works with hooks disabled (test with a repo containing a hook).
- Out-of-plan file edit is blocked and flagged (test).
- `vulntrace verify-bundle` passes on a fresh bundle and **fails** after flipping one byte.
- `git apply --check` succeeds for the exported diff on a clean checkout.

**Cut-line:** zip export can slip; `.diff` export and signing cannot.

### M6 — UI flow (Oct 15–19)

**Tasks:** implement 4.13 end to end against real backend events. Run the frontend design skill/guidance in your toolchain for typography and spacing.

**AC**
- Browser-agent walkthrough (screen recording) completes steps 1–7 on a curated repo.
- Empty/loading/error states demonstrated for each step (screenshots).
- Evidence page shows verdict badge, RED/GREEN side by side, baseline-vs-after regression table, Tavily sources, token ledger, tier.
- No console errors; Lighthouse accessibility ≥90 on the evidence page (paste score).

**Cut-line:** reachability graph can be a simple tree/list; evidence page cannot be cut.

### M7 — Intent → acceptance tests, two more sink classes (Oct 18–23)

**Tasks:** 4.9; implement path-traversal and command-injection oracles; add benchmark cases.

**AC**
- Requirement "fix the deserialization but keep custom tags" produces a Spec and a pytest acceptance test that **fails on the original** for the expected reason (show output).
- A vague requirement ("make it better") yields `UNVERIFIABLE` with reasons (test).
- Test-quality gate rejects `assert True` tests (test).
- Each new sink class: vulnerable fixture RED, fixed fixture GREEN, zoo non-GREEN.
- Benchmark has ≥10 cases across 3 classes.

**Cut-line:** drop **change-request mode entirely**; keep guided remediation. Command-injection class can drop before path-traversal.

### 🔒 FEATURE FREEZE — Sat Oct 24

After this: bug fixes, benchmark, docs, video, submission only. New feature requests go to `docs/POST_HACKATHON.md`.

### M8 — Benchmark, README, hosted curated demo (Oct 24–26)

**Tasks:** run VulnTrace-Bench live (3 repeats); CI-generated README table; competitor section rewritten per D9; hosted demo with curated repos and replay; `docs/ARCHITECTURE.md`; feedback notes finalized.

**AC**
- `python bench/run.py --ci` reproduces the README table; CI is green on `main`.
- 0 false GREENs in the zoo; held-out cases reported separately.
- Hosted demo URL loads, runs a curated replay without credentials, and shows a verified bundle.
- README has TL;DR, screenshot/GIF, correct quickstart (tested from a clean machine), license, safety statement, honest limitations.
- No unsourced percentages; no "cryptographic" without "Ed25519"; no "isolated sandbox" for Tier 0.

### M9 — Video, submission, buffer (Oct 26–28)

**Tasks:** record video (Section 11.3), publish to YouTube (public), fill Devpost fields, submit feedback form, final repo check.

**AC**
- Video ≤2:55; rehearsed live path succeeded 5/5 before recording; backup recording exists.
- Devpost draft saved by Oct 27; **final submission Oct 28**.
- Submission checklist (Section 11.4) fully checked by the owner.

**Oct 29–30:** emergency fixes only. No new work.

---

## 7. Quality gates

**CI (`.github/workflows/ci.yml`, free for public repos):** ruff, mypy (on core modules), pytest with sockets blocked, secrets scan (e.g. gitleaks), license-header check, bench smoke (cassette-backed), README-table consistency check.

**Definition of Done (per milestone):**
1. All AC met with pasted real output.
2. CI green.
3. Docs updated (`ARCHITECTURE.md`, `SAFETY.md` if relevant, `CHANGELOG_HACKATHON.md`).
4. At least one real bug found by execution and fixed, reported.
5. Out-of-scope changes listed and approved by the owner before merge.
6. Milestone report complete (Section 9.3).

---

## 8. Rules block for `AGENTS.md` / Antigravity workspace rules

```
# VulnTrace Studio — Agent Rules

1. The repository is the single source of truth. If docs/spec and code disagree, STOP and report. Do not choose silently.
2. Before creating any component, inspect the repo and reuse or extend what exists. State what you found.
3. Flag any out-of-scope change BEFORE implementing it. Out of scope = anything not required by the current milestone's acceptance criteria.
4. Preserve exact specifications: verdict strings (spec §3.1), evidence schema field names (spec §4.11), CLI names, and API routes. Do not rename without owner approval.
5. "Done" requires executed evidence: paste real command output for every acceptance criterion. Code review alone is not evidence.
6. Prefer catching real bugs through execution. Run the tests, the benchmark, and the UI. Report at least one real failure you caught and fixed.
7. Never claim a number, capability, or security property that a command has not demonstrated. No unsourced percentages.
8. Untrusted-code rule: never execute target-repo code outside the sandbox tier required by the spec. Tier 0 is for curated fixtures only.
9. Secrets: never print, log, commit, or pass API keys into sandboxes or bundles.
10. Payload policy: behavioral probes only. No shells, no network callbacks, no destructive actions.
11. LLM calls: unit tests use cassettes and make zero live calls. Live calls only with LIVE_LLM=1.
12. Feature freeze Oct 24: after it, no new features.
13. Commit small. One logical change per commit. Message states the AC it satisfies.
14. End every milestone with the structured milestone report (spec §9.3).
```

---

## 9. Prompt templates

### 9.1 Antigravity milestone prompt

```
Read AGENTS.md and the attached spec sections 2–4 and milestone <Mx>.
Step 1: inspect the repo and list which components for this milestone already exist, which need extension, and which are new. Do not write code yet. Flag any discrepancy with the spec.
Step 2: wait for my "go", then implement test-first.
Step 3: run every acceptance criterion command and paste the real output.
Step 4: use the browser agent for any UI criterion and attach a recording or screenshots.
Step 5: finish with the milestone report template. List out-of-scope items you wanted to change but did not.
```

### 9.2 ChatGPT adversarial review prompt

```
You are the Evidence Auditor and AppSec Lead for VulnTrace Studio. Below are the milestone spec, the diff summary, and the milestone report.
1. For each acceptance criterion, say whether the pasted output actually proves it. Quote the line.
2. List claims in the report or README not supported by an executed command.
3. Propose three ways the verifier or oracle could still produce a false GREEN or false NO_STATIC_PATH_FOUND, with a test for each.
4. List scope creep.
5. Give verdict: ACCEPT / ACCEPT WITH FIXES / REJECT, with the exact fixes.
```

### 9.3 Milestone report template (required)

```
## Milestone <Mx> report
**Done:** components changed/added; EXISTS/EXTEND/NEW status
**Acceptance criteria:** each AC → PASS/FAIL → command → pasted output
**Real bug(s) caught by execution:** what failed, how found, how fixed
**Evidence artifacts:** file paths (bundles, screenshots, recordings)
**Out-of-scope items flagged (not implemented):**
**Spec discrepancies found:**
**Open risks for next milestone:**
**Credits used this milestone:** tokens by stage (from ledger)
```

---

## 10. Risk register and kill switches

| Risk | Likelihood | Impact | Mitigation | Kill switch / trigger |
|---|---|---|---|---|
| Docker unavailable/unstable on owner machine | Med | High | Early M3; WSL2 setup; fallback replay-only hosted demo | Oct 12: switch to fallback |
| Flasgger (or another real repo) won't reach GREEN | Med | Med | Env builder; swap repos; publish honest failure | Oct 10: pick alternate |
| Verifier false GREEN discovered late | Low | Very high | Zoo + ChatGPT adversarial review each milestone | Any false GREEN stops all feature work |
| Credits exhausted | Med | High | Cassettes, token caps, tiering, live runs only for bench/demo | 60% spent before Oct 20 → freeze live runs to demo only |
| Tavily/Token Factory outage during demo | Low | High | Replay mode; backup video recorded early | Use replay + video |
| Prompt injection from repo text | Med | Med | Data-block prompts, no extra tools, scope guard | Block run + `VERIFICATION_REJECTED` |
| Scope creep (change-request mode, PRs) | High | High | Cut-lines; freeze; `POST_HACKATHON.md` | Oct 24 freeze |
| Overclaiming in README/video | Med | High | Evidence Auditor review; CI-generated numbers | Any unverified claim removed before submit |
| Antigravity/ChatGPT diverge from spec | Med | Med | Rule 1; discrepancy reports; small milestones | Owner arbitrates |
| Late-night submission failure (Devpost/YouTube issue) | Low | Very high | Submit Oct 28; checklist; draft saved Oct 27 | Never wait for Oct 30 |

---

## 11. Submission package

### 11.1 README skeleton (top to bottom)

1. One-line pitch + 15-second GIF of the full flow
2. TL;DR: what it does, verdict example, link to demo and video
3. **Why Nebius + NVIDIA:** Token Factory calls, Nemotron tiers, token ledger, Tavily runtime call (diagram)
4. Quickstart (tested on a clean machine) — local and hosted demo
5. How it works (pipeline diagram, verdict taxonomy)
6. Benchmark table (CI-generated, with numerators/denominators and held-out cases)
7. Safety model (tiers, probes-only policy, limits)
8. Honest limitations (static analysis blind spots, Python-only, oracle limits)
9. Related tools (hedged comparison, per D9)
10. License, acknowledgements

### 11.2 Devpost text outline

Problem → insight (proof-carrying remediation) → what we built → how we use Nebius Token Factory, Nemotron, Tavily (explicit, with where in the pipeline) → benchmark highlights (real numbers) → challenges (env builds, verifier gaming) → what's next. Select the Coding & Agentic Engineering track. Add the "what was significantly updated" note if applicable (C10).

### 11.3 Video script (target 2:50)

| Time | Beat | Screen |
|---|---|---|
| 0:00–0:20 | Problem: alerts without proof | Alert list, "reachable? exploitable? fixed?" |
| 0:20–0:50 | Upload real repo; analysis; Tavily sources; reachability | UI steps 1–2 |
| 0:50–1:10 | Requirement typed; plan approval | Steps 3–4 |
| 1:10–1:55 | RED 3/3 → Nemotron patch → GREEN 3/3 → regressions vs baseline | Steps 5–6 live stream, ledger visible |
| 1:55–2:15 | Contextual-patch case vs naive baseline | Side-by-side result |
| 2:15–2:40 | Stack and proof: Token Factory, Nemotron tiers, Tavily, Ed25519 bundle, benchmark numbers | Architecture + table |
| 2:40–2:50 | Pitch line + export | Step 7 |

Rehearse the exact path 5×. Use a pre-verified real run as backup footage.

### 11.4 Final checklist (owner)

- [ ] Public repo; Apache-2.0 visible at top; About filled
- [ ] README quickstart verified on a clean machine
- [ ] CI green on `main`; README table matches CI output
- [ ] Hosted demo URL works without credentials
- [ ] Video public on YouTube, <3:00
- [ ] Track selected: Coding and Agentic Engineering
- [ ] Tavily runtime call present in the demo bundle
- [ ] Token Factory + Nemotron use stated in README, Devpost text, and video
- [ ] Feedback form/notes submitted **[VERIFY requirement]**
- [ ] "Significantly updated" note added if applicable **[VERIFY]**
- [ ] No secrets in repo history (secrets scan clean)
- [ ] Submitted Oct 28; confirmation email saved

---

## 12. Credits and cost plan

- Config caps: `MAX_TOKENS_PER_RUN`, `MAX_REPAIR_ATTEMPTS=3`, `MAX_LIVE_RUNS_PER_DAY`.
- Development uses cassettes. Live runs only for: M4 acceptance, M7 acceptance, benchmark (3 repeats × cases), demo rehearsals, final recording.
- After each milestone, record credits used from the ledger in the report. Recompute the plan if >60% is spent before Oct 20.
- Check what free credits are available (Token Factory promo, Builders Program, Tavily) on the official resources page **[VERIFY]**.

---

## 13. Open items the owner must verify (before M3)

1. Exact Devpost "What to submit" wording: hosted demo requirement, video hosting, feedback form.
2. Exact Nemotron model IDs available on Token Factory and their pricing/limits.
3. Whether Token Factory Sandboxes (or ConTree) access can be enabled for your account; ask organizers about the 403.
4. Credit amounts and how Tavily credits are issued.
5. Whether the project counts as pre-existing and what the "significant update" statement must include.
6. Antigravity's current rate limits and how workspace rules are configured.

---

*End of spec. If any instruction here conflicts with the repo's reality or with the official rules, the repo and the official rules win. Report the conflict.*
