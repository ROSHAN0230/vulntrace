# VulnTrace Studio — Development Changelog

All major project updates and milestone completions throughout development.

## [Phase 8D] M7 Cut-Line Formalization, M8 Replay Stepper, In-Browser Ed25519 Verification & 3-Repeat Evidence — 2026-10-19
- **Milestone M7 Cut-Line Formalization (Spec §6 line 486):** Formally enacted Option B cut-line dropping Command Injection to uphold Rule 10 ("Behavioral probes only. No shells"). Documented that M7 is completed with two deeply verified, production-grade sink classes: `UNSAFE_DESERIALIZATION` and `PATH_TRAVERSAL`. Acknowledged that literal 3-class completeness is not claimed.
- **20/20 Bad-Patch Zoo Verification:** Maintained 100% detection of gaming attempts across 10 deserialization bad patches and 10 path-traversal bad patches with 0 false GREEN verdicts.
- **Interactive 7-Stage Curated Replay Stepper:** Upgraded `RecordedEvidenceViewer.tsx` to include an accessible, keyboard-navigable 7-stage pipeline replay (`ENVBUILD` -> `REPRODUCTION` -> `REMEDIATION` -> `SCOPE_GUARD` -> `VERIFICATION` -> `REGRESSION` -> `EVIDENCE`) preserving all 5 deep links.
- **In-Browser Ed25519 Cryptographic Verification:** Integrated client-side Web Crypto (`crypto.subtle`) verification validating RFC 8032 Ed25519 signatures and RFC 8785-compatible deterministic canonical hashes against the trusted VulnTrace authority public-key fingerprint (`fe9efb08...`).
- **In-Memory Tamper Simulation:** Added an interactive "Simulate Payload Tamper" demonstration in the showcase UI, allowing evaluators to verify immediate cryptographic rejection (`PAYLOAD_TAMPERED`) in real-time without modifying disk assets.
- **Genuine 3-Repeat Benchmark Protocol:** Implemented `bench/run_3repeat.py` and executed 3 independent passes per eligible case, recording results in `bench/observed_3x_runs.json` with unanimity semantics while strictly preserving `bench/raw_observations.json` and `bench/HELDOUT.md` byte-for-byte.

## [M7 Phase 2] Final Security-Evidence Closure — 2026-10-15
- **Structured Canary Telemetry & Cross-Validation:** Synthesizer emits structured telemetry JSON (`_acceptance_telemetry.json`) alongside stdout. The pipeline enforces dual-source canary verification: parent filesystem observation must strictly agree with container telemetry (`parent_canary_observed == telemetry_canary_observed`). Missing, malformed, or contradictory telemetry fails closed with explicit error classifications (`MALFORMED_TELEMETRY`, `CONTRADICTORY_CANARY_EVIDENCE`, `CANARY_NOT_CREATED`).
- **Exact Exception & Repaired GREEN Validation:** Replaced loose exception checks with exact constructor-blocking exception matching (`yaml.constructor.ConstructorError`). Valid repaired GREEN requires all acceptance assertions to pass, probe blocked (`probe_blocked=True`), canary absent on disk and in telemetry (`canary_created=False`), custom tags preserved (`test_preserve_custom_tags PASSED`), and benign config verified (`test_standard_benign_config_loads_cleanly PASSED`).
- **Custom Loader AST Codemod Preservation:** Enhanced `RemediationPatcher._ast_deterministic_patch` to inspect target modules for custom `yaml.SafeLoader` subclasses (e.g. `AppSafeLoader`). If found, surgical codemod replaces `Loader=yaml.Loader` with `Loader=AppSafeLoader` rather than naively stripping kwargs to `yaml.safe_load`, preserving registered domain constructors and preventing false regression failures.
- **Evidence Schema v1 Attributable Telemetry:** Populates structured telemetry into `bundle["spec"]["acceptance_tests"]` (`canary_created_pre_patch`, `probe_blocked_post_patch`, `expected_block_exception`) and `bundle["verification"]["positive_control"]` (`custom_tags_preserved`, `benign_config_verified`) conforming strictly to `docs/evidence/schema_v1.json`.
- **Bundle Tamper & Signature Verification:** Verified genuine signed bundles with `vulntrace verify-bundle` CLI (exit 0) and proved that arbitrary payload byte tampering or signature corruption is strictly rejected with exit code 1.
- **Real Execution Bugs Caught & Fixed:**
  1. *Missing `import json` in `vulntrace/sandbox/pipeline.py`:* Parsing telemetry in Stage 2 & Stage 4 raised `NameError: name 'json' is not defined`, resulting in `MALFORMED_TELEMETRY`. Added `import json` to pipeline imports.
  2. *Naive SafeLoader Destruction of Domain Constructors:* `_ast_deterministic_patch` previously replaced `yaml.load(..., Loader=yaml.Loader)` with `yaml.safe_load(...)`, breaking custom tag constructors. Enhanced AST transformer to detect and preserve module-defined `SafeLoader` subclasses (`Loader=AppSafeLoader`), achieving authentic `GREEN_STATE_VERIFIED`.
- **Test Coverage:** Added 5 focused security evidence and tamper rejection tests to `tests/test_intent_to_test.py` (33/33 passed). Verified full suite with 319 offline tests passing, 43 container tests passing (362 total tests passing).

## [M7 Phase 2] Runtime RED/GREEN Integration & Tier 1 Verification — 2026-10-15
- **End-to-End Pipeline Execution (Spec §4.9):** Integrated synthesized acceptance tests directly into `VerificationPipeline` (`vulntrace/sandbox/pipeline.py`), `VerificationPipelineRequest` (`vulntrace/models.py`), and the REST API server (`vulntrace/server/app.py`).
- **Bounded Canary Probe & Safe Exception Matching:** Replaced raw `eval` with bounded canary probe (`builtins.eval ["open('{canary_str}', 'w').close()"]`) in disposable Tier 1 scratch space without shell execution or host escapes. Replaced broad exception catching with exact loader-block exceptions (`yaml.constructor.ConstructorError`, `yaml.parser.ParserError`, `yaml.error.YAMLError`) and assertion of canary non-existence.
- **Harness Isolation & Bitwise Hash Immutability:** Generated `_acceptance_test.py` strictly outside the patchable source directory (`service/`), set `0o444` read-only permissions, and enforced bitwise byte-level SHA-256 immutability verification across pre-patch and post-patch execution phases.
- **Runtime RED/GREEN Verification on Flagship Target (`benchmarks/contextual_reasoning`):**
  - Pre-patch: 3/3 repeated cycles failed security probe (`DID NOT RAISE any of (ConstructorError, ParserError, YAMLError)`), created canary, while passing custom tag preservation and benign configuration controls.
  - Surgical remediation: patched `service/custom_loader.py` with `Loader=AppSafeLoader`.
  - Post-patch: 3/3 repeated cycles passed cleanly (ConstructorError caught on exploit payload, zero canary creation, custom tags preserved, benign config validated).
  - Naive patch: verified that naive `yaml.safe_load` correctly fails custom tag preservation (`ConstructorError: could not determine a constructor for the tag '!env_var'`).
- **Formal Signed Evidence Bundle Integration:** Emits authentic `spec` block in Schema v1.0.0 signed evidence bundle containing `must_fix`, `must_preserve`, `constraints`, `out_of_scope`, `acceptance_tests`, and acceptance SHA-256. Evaluated by `VerdictEngine` to yield terminal verdict `GREEN_STATE_VERIFIED`.
- **Real Bug Caught and Fixed:** Fixed newline translation discrepancy on Windows where `Path.write_text()` translated `\n` to `\r\n` whereas in-memory hashing used LF bytes, causing false hash mismatch between pre-patch and post-patch phases. Switched to `write_bytes()` and `read_bytes()` ensuring byte-level deterministic hash matching across all platforms.
- **Test Coverage:** Added `test_intent_acceptance_test_runtime_red_green_contextual_reasoning` and `test_pipeline_end_to_end_with_intent_via_server` to `tests/test_intent_to_test.py` (28/28 passed).

## [M7 Phase 2] Intent-to-Acceptance-Test Engine & Quality Gates — 2026-10-14
- **Modular Intent Architecture (Spec §4.4, §4.9):** Created `vulntrace/intent/` package providing typed Pydantic representation for repair specifications (`Spec`), individual acceptance tests (`AcceptanceTestDefinition`), requirement parser (`IntentParser`), test code synthesizer (`AcceptanceTestSynthesizer`), and validation gates (`IntentQualityValidator`).
- **Canonical Spec Schema Field Preservation:** Guaranteed explicit preservation of all 4 canonical fields: `must_fix`, `must_preserve`, `constraints`, and `out_of_scope`, alongside `acceptance_tests`, `is_verifiable`, and `warning`/`unverifiable_reason`. Serializes transparently to both typed models and legacy/API dictionary contracts (`to_api_dict()`).
- **Requirement-to-Acceptance-Test Flow ("fix deserialization but keep custom tags"):** Validated canonical scenario: parses natural-language intent into structured target defects (`must_fix`: unsafe deserialization), functional invariants (`must_preserve`: custom application tags `!custom_tag` and loader extensions), diff budget constraints, and synthesizes two distinct executable pytest assertions (security exploit probe rejection and custom tag domain object preservation).
- **Six Anti-Gaming & Isolation Quality Gates:**
  1. *Gate 1 (Verifiability Threshold):* Rejects vague requirements lacking concrete conditions ("make it better", "clean up", "fix bugs") with honest `UNVERIFIABLE` diagnostics.
  2. *Gate 2 (Non-Trivial Assertion AST Inspection):* Inspects test ASTs to reject trivial dummy tests containing only `assert True`, `assert 1 == 1`, empty `pass`, or missing assertions.
  3. *Gate 3 (Pre-Execution Syntax Validation):* Validates compiled AST and rejects malformed Python test code.
  4. *Gate 4 (Target Symbol Verification):* Enforces that synthesized test functions actually reference or exercise the target symbol (`target_function` or `vulnerable_symbol`).
  5. *Gate 5 (Untrusted Text & Prompt Injection Defense):* Neutralizes hostile prompt injection targeting isolation boundaries (`--unsafe-local`, `VULNTRACE_UNSAFE_LOCAL`, destructive shell commands, `rm -rf /`).
  6. *Gate 6 (Tier 1 Container Boundary Enforcement):* Strictly routes synthesized test execution on non-curated/untrusted codebases to Tier 1 rootless container isolation (`ContainerExecutionBackend`), refusing Tier 0 (`LocalSubprocessBackend`) execution under strict zero-trust policy.
- **Server API Integration:** Enriched `POST /runs/{run_id}/intent` in `vulntrace/server/app.py` to route through `vulntrace.intent`, recording structured specs with `out_of_scope` in SQLite database events and client responses.
- **Comprehensive Test Suite:** Added `tests/test_intent_to_test.py` with 26 focused tests covering all 6 quality gates, field preservation, prompt injection defense, and server endpoint integration.

## [M7 Phase 1] Path Traversal Oracle & Bad-Patch Zoo Evaluation — 2026-10-14 (Commit `d101632`)
- **Path Traversal Oracle (`vulntrace/sinks/path_traversal.py`):** Implemented `TarPathTraversalOracle` and `ZipSafeControlOracle` subclassing `BaseSinkOracle`. Evaluates archive extraction member traversal sequences with disposable canaries located strictly inside sandbox scratch and never on the host.
- **Python 3.11+ PEP 706 Compatibility:** Ensured safe extraction patterns use path resolution containment checks (`commonpath` / `is_relative_to`) compatible across Python 3.11 and Python 3.14+ (`data_filter`).
- **Curated Fixtures & Registration:** Created `tests/fixtures/path_traversal/tar_vulnerable` and `tar_fixed`; registered in `TrustedFixtureRegistry.CANONICAL_FIXTURE_RELPATHS` with broad container forbidden in `FORBIDDEN_BROAD_IN_PROJECT_RELPATHS`.
- **Harness Synthesizer Extension:** Added `SinkClass.PATH_TRAVERSAL` dispatch with argument forwarding and hash immutability in `vulntrace/agent/harness_synthesizer.py`.
- **Bad-Patch Zoo Evaluation:** Proved 0 false GREEN verdicts across 10 adversarial mutations and verified RED 3/3 on vulnerable fixture and GREEN 3/3 on fixed fixture in `tests/verifier/test_path_traversal_oracle.py`.

## [M6] VulnTrace Studio UI Flow — 2026-10-08
- **Seven-Step Guided Remediation Application (Spec §4.13):** Built and verified the complete frontend application in React 18, TypeScript, and TailwindCSS across 7 sequential stages:
  1. *Source (`StepSource.tsx`):* Curated benchmark selection (5 multi-file scenarios, including flagship Contextual Reasoning & SafeLoader Hardening for CVE-2020-14343), public GitHub HTTPS cloning, and safe Zip archive uploads with comprehensive ingest security notices.
  2. *Analysis (`StepAnalysis.tsx`):* Discovered vulnerable call site table (location, caller, sink, reachable status), AST call-graph reachability traversal hierarchies, baseline test suite results, Tavily CVE intelligence links, and static blind spots.
  3. *Requirements (`StepRequirements.tsx`):* Natural language repair intent capture, syntactic invariant parsing, parsed spec previews, and explicit `UNVERIFIABLE` warning card on vague/unconstrained prompts.
  4. *Plan (`StepPlan.tsx`):* Interactive scope-guard budgeting (approved files to touch, remediation strategy, diff budget slider $\le 30$ lines, and operator approvals).
  5. *Live Run (`StepLiveRun.tsx`):* Real-time SSE streaming terminal over `/runs/{id}/events` displaying 7-stage progress, 3x flake checks (RED 3/3, GREEN 3/3), token ledger telemetry, and fixed-height scrollable terminal with zero layout shifts.
  6. *Evidence (`StepEvidence.tsx`):* Primary trust surface showcasing canonical verdicts (Spec §3.1), side-by-side RED vs. GREEN execution results, syntax-highlighted unified diffs, baseline vs. after regression deltas, Tavily sources, and recorded limitations.
  7. *Export (`StepExport.tsx`):* 1-click `.diff`, `.zip`, and `bundle.json` artifact downloads, copyable `git apply` and `vulntrace verify-bundle` commands, and RFC 8032 Ed25519 public key fingerprint seals.
- **Flagship End-to-End Verified Run (`run_5f7e05adf654`):** Real browser-driven workflow through all 7 stages on `contextual_reasoning`:
  - RED state reproduced: 3/3 repeats confirmed (exit 0)
  - Surgical patch synthesized via NVIDIA Nemotron 3 Ultra (`AppSafeLoader` substitution)
  - Scope Guard enforced: 1 file (`service/custom_loader.py`), diff budget $\le 30$ lines
  - GREEN state verified: 3/3 repeats confirmed (exit 42, `GREEN_SECURITY_BLOCK_VERIFIED`)
  - Regression suite: 3/3 tests passed (0 regressions)
  - Final behavioral verdict: `GREEN_STATE_VERIFIED`
  - Signed bundle: Ed25519 verified with CLI `[OK]` (Fingerprint: `fe9efb08...`)
- **Persistent Header & Design System (`Header.tsx`, `index.html`):** Dark/light mode theme switching with localStorage persistence, persistent Run ID with 1-click clipboard copy, canonical verdict badge, sandbox tier badge (`TIER 1 (CONTAINER)`), live token ledger, and provider status chips (Nemotron: ONLINE, Tavily: ONLINE).
- **Backend Endpoints & AST Expansion (`vulntrace/server/app.py`):** Added `POST /runs/{id}/analyze` for on-demand AST call-graph traversal and threat intelligence aggregation; enriched `POST /runs/{id}/intent` with `parse_and_validate_intent` evaluating requirements for concrete verifiable targets vs. vague inputs (`is_verifiable: false` with explicit `UNVERIFIABLE` warning and reasons per Spec §3.1, §4.9).
- **Lighthouse Accessibility Gate (Spec §6 AC):** Exceeded accessibility gate with a verified **95/100 Accessibility score**, 100/100 Best Practices, 100/100 Agentic Browsing, and 0 console errors on the primary Step 6 Evidence page.
- **Real Execution Bugs Caught & Fixed:**
  1. *Pipeline Event Callback Arity Mismatch in `app.py`:* `VerificationPipeline.run_pipeline` passed a single `PipelineEvent` object to `on_event`, whereas `emit_event` expected 4 positional arguments (`ev_type`, `stage`, `msg`, `payload`), causing a `TypeError`. Updated `emit_event` to polymorphically handle both single `PipelineEvent` instances and positional arguments.
  2. *AST Model Property vs. Subscript:* `AstReachabilityAnalyzer` results use `discovered_calls` (`List[VulnerableCallSite]`) rather than `reachable_paths`, and `cve_data.affected_packages` items use `pkg.package_name`. Resolved and verified with pytest.
  3. *Evidence Bundle Signature Key Name:* Updated test assertion to check canonical `"alg": "Ed25519"` matching RFC 8032 conventions.
  4. *Missing Form Label Lint in Scope Guard Plan Form:* Added accessible `id`, `name`, and `aria-label` to custom file input in `StepPlan.tsx`.
- **Quality Gates & Evidence:**
  - 5 tests in `test_studio_server.py` passed (100% green).
  - 36 tests in `test_evidence_signing.py`, `test_ingest_guards.py`, and `test_tier1_isolation.py` passed (100% green).
  - Full non-container regression suite: 174 passed, 38 deselected in 5m 14s (100% green).
  - Ruff linter: 100% clean (0 errors).
  - Verified bundle: `vulntrace verify-bundle docs/evidence/sample_m6_bundle.json` -> `[OK]`.

## [M5] Studio Backend & Evidence Signing — 2026-10-07
- **Ingest Security Guards (Spec §4.14):** Implemented `vulntrace/ingest/` with `ZipUploadGuard` and `GitCloneGuard`. Enforces zip-slip rejection (`ZipSlipError`), symlink escape neutralization (`SymlinkEscapeError`), decompression bomb detection (`DecompressionBombError`, 100:1 ratio and 200MB limit, file count limit). Enforces git clone hardening: HTTPS-only protocol, embedded credential scrubbing, shallow clone (`--depth 1`), git hooks strictly disabled (`-c core.hooksPath=NUL|/dev/null`), filesystem monitoring disabled (`-c core.fsmonitor=false`), and submodules blocked (`--no-recurse-submodules`).
- **Plan Approval & Scope Guard (Spec §4.10):** Implemented `vulntrace/agent/scope_guard.py` with `RepairPlan` and `ScopeGuard`. Parses unified diff additions/deletions, enforces allowed files (`files_to_touch`), diff line budget ($\le 30$ lines), and maximum touched files ($\le 3$ files). Emits `SCOPE_VIOLATION_BLOCKED` when patches attempt out-of-plan modifications.
- **Unified Diff & Workspace Export (Spec §4.12):** Implemented `vulntrace/export/` with `DiffExporter` and `ZipExporter`. Normalizes unified diffs with LF line endings and verifies clean applicability via `git apply --check`. Safely packages disposable workspaces into portable zip distributions with default exclusions (`.git`, `__pycache__`, `.venv`, etc.).
- **Evidence Schema v1 & RFC 8032 Pure-Python Ed25519 Signing (Spec §4.11):** Formally authored `docs/evidence/schema_v1.json`. Implemented canonical JSON serialization (`canonical_json_bytes`) with RFC 8785 lexicographical key sorting, strict compact delimiters, and SHA-256 fingerprinting. Implemented zero-dependency pure-Python Ed25519 curve arithmetic (`EvidenceSigner` and `KeyManager`) generating keypairs in `~/.vulntrace/keys/`. Proved tamper detection: modifying even a single byte in any payload field causes cryptographic verification failure.
- **CLI Verification Tooling (Spec §4.11):** Added `vulntrace verify-bundle <bundle.json>` CLI entrypoint via `vulntrace/cli.py` and `pyproject.toml` console scripts. Exits 0 with human-readable summary on authentic bundles, and exits 1 with failure details on tampered bundles.
- **Studio Backend Server & SSE Streaming (Spec §4.12):** Implemented `StudioDatabase` (`vulntrace/server/db.py`) managing SQLite tables for `runs`, `events`, `artifacts`, and `llm_calls`. Consolidated backend routing in `vulntrace/server/app.py`, providing unified support for legacy `/api/v1/*` endpoints and Studio `/runs*` REST and SSE streaming endpoints.
- **Real Execution Bugs Caught & Fixed:**
  1. *Ambiguous Variable Name in Curve Arithmetic:* In `signing.py`, `I = pow(2, (P - 1) // 4, P)` triggered Ruff `E741`; renamed to `SQRT_M1`.
  2. *Package/Module Collision on `vulntrace/server`:* Subdirectory `vulntrace/server/` shadowed `vulntrace/server.py`, causing 404s on legacy `/api/v1/*` routes in `test_api_endpoints.py`; unified all routes into `vulntrace/server/app.py` and cleanly removed redundant `server.py`.
  3. *Unused Variable Assignment:* `record = db.create_run(...)` in `app.py` triggered Ruff `F841`; cleaned up assignment.
  4. *Key Directory Keyword Mismatch:* `test_evidence_signing.py` passed `keys_dir` instead of `key_dir` to `KeyManager.get_or_create_keys`; corrected parameter name.
  5. *Database Event Return Semantics:* `StudioDatabase.add_event` did not return the newly created event object, causing `NoneType` subscript errors in SSE event streaming; updated to return populated event record with `lastrowid`.
  6. *Pydantic v2 Query Pattern Compatibility:* Deprecated `regex` parameter in FastAPI `Query` updated to `pattern`.
- **Test Suites & Quality Gates:**
  - 29 new M5 tests across 5 test suites: `test_ingest_guards.py` (11 passed), `test_scope_guard.py` (5 passed), `test_diff_export.py` (4 passed), `test_evidence_signing.py` (5 passed), `test_studio_server.py` (4 passed).
  - Full non-container test suite: 170 passed, 38 deselected in 268.58s.
  - Tier-1 isolation test suite: 17 passed in 33.93s.
  - Ruff linter: 100% clean (0 errors).

---

## [M4] Tavily Runtime Threat Intel + LLM Tiering — 2026-10-06
- **Tavily Runtime Threat Intelligence (Spec §4.7):** Integrated runtime threat intel gathering into the core verification pipeline (`vulntrace/intel/tavily_client.py` and `vulntrace/intel/threat_intel.py`). Generates canonical `ThreatIntel` models containing raw search queries, ISO timestamps, source URLs, response SHA-256 fingerprint, findings, affected symbols, safe patterns, and sink classes.
- **Material AST & Oracle Influence:** Threat intelligence results actively guide static analysis and oracle dispatch: extracted candidate symbols expand AST reachability queries, and discovered sink classes resolve specific sink oracles via `SinkOracleRegistry.get_candidate_symbols_for_intel()` and `get_oracle_for_intel()`.
- **Resilient Degradation & Offline Replay:** Added `IntelCassetteManager` with SHA-256 keyed cassette storage (`vulntrace/intel/cassettes/`) enabling 100% offline CI runs. Handled network failures and missing API keys gracefully with `status: "degraded"` without fabricating evidence.
- **Nebius Token Factory Model Tiering (Spec §4.8):** Live-verified 25 available models from Nebius Token Factory `/models` API and mapped canonical LLM tiers to verified models:
  - `SMALL` (`nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`): Triage and initial vulnerability classification
  - `MID` (`nvidia/nemotron-3-super-120b-a12b`): Patch planning and strategy formulation
  - `ULTRA` (`nvidia/Nemotron-3-Ultra-550b-a55b`): Surgical patch synthesis and repair
- **Prompt Injection Defense & Structured Output:** Wrapped untrusted target code and CVE summaries in strict delimiters (`<<<UNTRUSTED_CODE_OR_ADVISORY>>>` / `<<<END_UNTRUSTED>>>`). Enforced Pydantic structured output models (`TriageAnalysisOutput`, `PatchPlanOutput`, `SurgicalPatchOutput`) with automatic schema extraction, error feedback retries (up to 2 attempts), and markdown code block extraction.
- **Token Accounting & Secret Hygiene (Spec §4.8 & §4.11):** Implemented `TokenLedger` tracking per-stage prompt tokens, completion tokens, reasoning tokens, and latencies across multiple tiers ($\ge 2$ tiers exercised in pipeline). Enforced regex-based API key redaction (`[REDACTED_API_KEY]`) ensuring zero secrets appear in ledgers, logs, or evidence bundles.
- **Offline Deterministic CI Cassettes:** Seeded verifiable offline cassettes in `vulntrace/llm/cassettes/` and created `tests/test_offline_ci_cassettes.py` to ensure complete E2E pipeline execution under 100% blocked external network socket calls.
- **Real Execution Bugs Caught & Fixed:**
  1. *vLLM `completion_tokens_details` NoneType Bug:* In Nebius Token Factory API, `usage.get("completion_tokens_details")` can return `None`. Fixed via `(usage.get("completion_tokens_details") or {}).get("reasoning_tokens")`.
  2. *Reasoning Model Content Relocation:* Output content placed in `message.reasoning` when completion tokens were consumed in thought trace; added fallback extraction.
  3. *AST Unified Diff Python Syntax False Positive:* Python 3.14 `ast.parse` treated diff lines (`diff`, `-func()`, `+func()`) as valid subtraction/addition expressions; enforced strict markdown Python code block extraction.
  4. *English Substring Collision in Symbol Extractor:* `ThreatIntelNormalizer` matched bare symbol names (`eval`, `exec`) as plain substrings in advisory prose (e.g. "arbitrary code execution"); fixed by requiring word boundaries and call syntax (`\bexec\s*\(` or `` `exec` ``).
  5. *Target Function AST Binding Inconsistency:* Pipeline bound to `target_symbols[0]` from ThreatIntel rather than checking the actual AST call site within the target function; fixed by resolving `target_call` directly against `ast_res.discovered_calls`.
  6. *Windows EventLoop Loopback Socket Collision:* Monkeypatching `socket.socket.connect` to verify zero network calls inadvertently blocked Python 3.14's `asyncio.ProactorEventLoop` internal self-pipe loopback socket on `127.0.0.1`; resolved by exempting loopback addresses (`127.0.0.1`, `::1`, `localhost`) in the fixture while strictly blocking external IPs.
- **Test Suites & Quality Gates:** Added 12 new M4 tests (all passed in 16.22s); full non-container test suite passed (140 passed, 38 deselected in 285.20s); Tier 1 container suite passed (17 passed in 40.76s); `ruff check` passed clean (0 errors).

---

## [M3] Isolation Tier 1: Rootless Container Isolation & Adversarial Containment Proofs — 2026-10-06
- **Rootless Container Execution (Spec §4.6):** Made Tier 1 rootless container isolation (`ContainerExecutionBackend` with Podman 5.7.0 / crun) the default execution tier for all real-world and non-curated repository execution via `BackendFactory.resolve_best_available_backend`.
- **Enforced Security Boundaries:** Enforced full Tier 1 runtime flags on all container executions: kernel network denial (`--network none`), read-only root filesystem (`--read-only`), ephemeral tmpfs scratch (`--tmpfs /tmp:rw,nosuid,nodev,size=64m`), unprivileged non-root user (`--user 1000:1000`), Linux capability dropping (`--cap-drop ALL`, `--security-opt no-new-privileges`), and cgroup resource limits (`--memory 512m`, `--cpus 1.0`, `--pids-limit 128`).
- **Tier 0 Degraded Refusal Guard:** Enforced strict non-curated repository refusal in `LocalSubprocessBackend`, raising `PermissionError` unless `unsafe_local=True` or `--unsafe-local` is explicitly passed; branded runtime engine attestation as `(DEGRADED_TIER_0)`.
- **Adversarial Containment Proof Suite:** Created `tests/test_tier1_isolation.py` (17 tests) verifying all 8 security conditions: outbound network denial, host filesystem write denial, fork process explosion containment, memory exhaustion OOM containment, wall-clock timeout watchdog descendant killing, host credential isolation, unforgeable attestation anti-spoofing, ephemeral tmpfs workspace isolation, setuptools egg-base build redirection on drvfs, pipeline tier preservation on patch rejection, and Verifier 3/3 RED and 3/3 GREEN execution under Tier 1.
- **Real Execution Bugs Caught & Fixed:**
  1. *WSL2 Container Leak on Timeout:* Terminating Windows `wsl.exe` left background container running; resolved by passing native Podman `--timeout <sec>` watchdog and unique container naming with `podman rm -f` fallback cleanup.
  2. *WSL Drvfs Pytest Cache Permission Crash:* Pytest writing `.pytest_cache` in `/workspace` as user `1000:1000` failed with `[Errno 1] Operation not permitted`; resolved by adding `-p no:cacheprovider` to container pytest invocations.
  3. *WSL Drvfs `copystat` and `egg_info` Build Crash:* `setuptools` build step failed when `shutil.copystat` attempted `chmod` on files created in `/workspace/build` and egg-info metadata wrote to `/workspace`; resolved by routing builds and egg-info to native tmpfs (`--build-base /tmp/build --build-lib /tmp/build/lib egg_info --egg-base /tmp`).
  4. *Timeout vs OOM Kill Code Collision:* Podman timeout exit code 255 was conflated with cgroups OOM kill code 137; resolved by isolating timeout handling to exit code 255.
  5. *BackendFactory Fallback Permission Loophole:* Resolving best available backend without specifying target repo unlocked `unsafe_local=True` in fallback; resolved by parameterizing fallback with `unsafe_local=effective_unsafe`.
  6. *Pipeline Tier Masking Bug on Patch Rejection:* Pipeline early-rejection path reported Tier 0 and omitted isolation attestation; resolved by dynamically binding backend tier and attestation records.
  7. *Real-World Eval Runtime Decoupling:* Resolved Flasgger CASE-RW-01 crash by explicitly routing M2 EnvironmentBuilder runs to `LOCAL_SUBPROCESS_FALLBACK` with `unsafe_local=True`, preserving `INCONCLUSIVE` verdict while CASE-RW-04 executes end-to-end on `OCI_CONTAINER_ISOLATED`.
- **Benchmark Suite & Matrix Updates:** Re-ran all 4 benchmark scenarios and updated `docs/evidence/benchmark_results.json` and `real_world_eval/evaluation_matrix.json` with explicit `isolation_tier: "OCI_CONTAINER_ISOLATED"`.
- **Documentation & Evidence:** Authored `docs/SAFETY.md` (boundaries, probe policy, threat model), generated `docs/evidence/m3_isolation_tier1.md`, and updated `README.md` benchmark isolation tier references and disclosures.
- **Test Suite & Linter:** 41/41 container/conformance tests passed; 128/128 non-container tests passed (169/169 total); 0 ruff lint errors.

---

## [M2] Dedicated Target Environment Builder & Real-Repo Evaluation — 2026-10-05
- **Dedicated Per-Case Environment Builder (Spec §4.5):** Implemented `vulntrace/envbuild/` with `EnvironmentBuilder` for provisioning isolated virtual environments per evaluation case strictly outside the workspace directory (`%TEMP%/vulntrace_case_envs/`).
- **Static Manifest Discovery:** Added dependency extraction across `requirements.txt`, `pyproject.toml`, and `setup.py` without code execution.
- **Wheel Caching & Offline Enforcement:** Provisioned shared wheel cache (`%TEMP%/vulntrace_wheel_cache/`) and enforced offline execution during harness runs.
- **Environment Evidence (Spec §4.11):** Added `EnvironmentEvidence` Pydantic model recording target Python version, exact executable path, build duration (ms), installed package inventory, pip log excerpts, and wheel cache hit metrics.
- **Truthful Failure Classification:** Mapped broken dependency installation to `ENV_BUILD_FAILED` with pip log excerpt, early-halting the verification pipeline before harness execution and preventing `UNEXPECTED_FAILURE` crashes.
- **Real-Repo Evaluation (Flasgger RW-01):** Evaluated Flasgger commit `163a753` across 3 consecutive runs, achieving 100% identical verdicts (`INCONCLUSIVE` due to PyYAML 5.4 runtime constructor hardening on Python 3.10) with complete root-cause documentation.
- **Harness & Engine Hardening:** Solved `SSLSocket` metaclass construction crash by implementing `_BlockedSocket(socket.socket)` subclass, added multi-parameter carrier wrapper in `HarnessSynthesizer`, added pre-patch `GREEN_STATE_BLOCKED` truthful handling in `VerdictEngine`, and configured multi-runtime Python resolution (3.10 + 3.11) with `/opt/hostedtoolcache/Python` discovery for legacy library compatibility.
- **Regression Suite & CI:** Verified 149/149 tests pass locally in 293.94s; linter `ruff check vulntrace/ tests/` clean (0 errors); GitHub Actions CI green.

---

## [M1] Verifier Hardening + Deserialization Oracle — 2026-10-05
- **Sink-Class Oracle Library (Spec §4.3):** Implemented `vulntrace/sinks/` package with reviewed oracles (`YamlDeserializationOracle`, `PickleDeserializationOracle`, `DeserializationSinkOracle`, and `SinkOracleRegistry`). Covers unsafe `yaml.load`/loaders, `pickle.loads`, behavioral probes (canary in workspace), expected exception signatures, safe patterns, and positive control contracts.
- **Anti-Gaming Verifier (Spec §4.4):** Implemented `vulntrace/verifier/` package with `AntiGamingVerifier`, `PatchDenylistValidator`, and `IntegrityAuditor`. Enforces RED 3/3 replication, SHA-256 integrity of harness and test files outside patched tree, AST patch denylist (rejects `sys.exit`, `os._exit`, `os.kill`, broad `except: pass`, target function deletion, empty diff), GREEN 3/3 flake check, and anti-spoofing guard against bare exit 42.
- **Bad-Patch Zoo (Spec §4.4):** Implemented 10 adversarial patch evaluations in `tests/verifier/test_bad_patch_zoo.py`, verifying 0 false GREENs across all bad patches, and proving genuine `yaml.safe_load` achieves `GREEN_STATE_VERIFIED` 3/3.
- **Test Fixtures & Acceptance Gates:** Added vulnerable and fixed fixtures for YAML and Pickle in `tests/fixtures/deserialization/`. Verified `pytest tests/verifier/ -q` passes (34/34 passed) and full regression suite passes (140/140 passed).
- **Evidence Documentation:** Generated `docs/evidence/verifier_redteam.md` recording the complete zoo verdict matrix, execution outputs, and real bugs resolved.

---

## [M0] Baseline Audit and Hygiene — 2026-10-04
- **Repository Hygiene:** Cleaned repository root to $\le 10$ items. Relocated historical pre-baseline audit documents and internal reports to project archives.
- **Agent Rules & Technical Spec:** Adopted `docs/TECHNICAL_SPEC.md` as the canonical technical specification and recorded Section 8 rules into `AGENTS.md` and `.agents/rules/directive.md`.
- **Fixtures & Tests Refactoring:** Relocated loose `sample_repo` into `tests/fixtures/sample_repo` and verified all 108 tests pass.
- **Continuous Integration:** Created initial GitHub Actions CI workflow skeleton (`.github/workflows/ci.yml`).
- **Baseline Evidence:** Recorded full 108-test command output and multi-scenario benchmark in `docs/evidence/baseline_run.md`.
- **Clean Container Proof:** Executed full clone, editable installation (`pip install -e .`), and test suite in clean unprivileged container (`python:3.11-slim` via Podman in WSL2), verifying 86 passed, 15 skipped, 0 failed.
- **Specification Verification Matrix:** Completed comprehensive audit of all specification verification items.
- **Repository Secrets Audit:** Scanned 22,638 diff lines across full git commit history, 143 tracked files, and `.gitignore` status, verifying 0 committed secrets.
- **GitHub Actions CI Green Closure:** Resolved CI runner failure (Workflow Run 37177315205 GREEN) by checking `podman image exists` in `ContainerExecutionBackend.is_available()`, registering pytest markers (`container`, `windows`, `asyncio`), and explicitly marking container tests.

---

## [P0.7] Execution Security Policy & Hardened Provisioning — 2026-10-03 (Commit `fb0deb1`)
- **Policy Engine:** Built `SecurityPolicyEngine` defining operations, capabilities, and assurance levels (`ASSURANCE_HIGH_CONTAINED`, `ASSURANCE_DEGRADED_FALLBACK`, `ASSURANCE_INSUFFICIENT_ISOLATION`).
- **OCI Offline Provisioning:** Added offline base image substrate (`vulntrace-sandbox-base:latest`) and in-container `setup.py build` running under `--network none`, `--cap-drop ALL`, and resource caps.
- **Policy Tests:** Added `tests/test_security_policy.py`, `tests/test_provisioning_security.py`, and `tests/test_backend_conformance.py`.

---

## [P0.6] Execution Substrate & OCI Container Isolation — 2026-10-03 (Commit `039ee08`)
- **Backend Abstraction:** Created `vulntrace/core/backend.py` with `ExecutionBackend`, `BackendCapabilities`, `ExecutionAttestation`, and `IsolationTier`.
- **Rootless OCI Backend:** Implemented `ContainerExecutionBackend` via Podman rootless containers in WSL2 Ubuntu with `--network none` and anti-spoofing sentinels.
- **Container Tests:** Added `tests/test_container_backend.py`.

---

## [P0.5] Hostile-Code Trust Boundary Closure — 2026-10-03 (Commit `67719d8`)
- **Process Containment:** Added Win32 Job Objects with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` to kill detached child processes.
- **Sanitized Provisioning:** Purged ambient host API keys (`TAVILY_API_KEY`, `NEBIUS_API_KEY`, cloud credentials) during target venv creation.
- **Filesystem Boundaries:** Redirected `APPDATA`, `LOCALAPPDATA`, and `TEMP` into disposable workspaces.

---

## [P0.1 - P0.4] Verifier Red-Teaming & Target Environment — 2026-10-02 (Commit `aa37af1`)
- **Bad-Patch Zoo:** Added 15 adversarial tests in `tests/test_verifier_redteam.py` rejecting broken patches (generic exceptions, function deletion, return None, empty dicts, anti-evasion argv/stack tampering).
- **Target Env Manager:** Added `TargetEnvironmentManager` in `vulntrace/sandbox/target_env.py`.

---

## [Phase 4] Real-World CVE Validation & Threat Intel — 2026-10-02 (Commit `0aa3e1e`)
- **Tavily CVE Validation:** Added strict target CVE relevance validator to `vulntrace/intel/tavily_client.py`.
- **Live End-to-End Verification:** Validated CVE-2020-14343 on real repositories (`flasgger`, `cookiecutter`, `repo_cloud_config`) with live evidence published.
- **Public GitHub Release:** Synchronized with public repository at `https://github.com/ROSHAN0230/vulntrace`.

---

## [Phases 1–3] Initial Architecture & Full-Stack Studio — 2026-10-01 to 2026-10-02
- **Core Engine:** Static AST call-graph analyzer (`vulntrace/analyzer/ast_engine.py`), OSV API client, and harness synthesizer.
- **AI Reasoning:** NVIDIA Nemotron 3 Ultra integration via Nebius Token Factory (`vulntrace/agent/nemotron_reasoner.py`).
- **Web UI & Server:** FastAPI streaming backend (`vulntrace/server.py`) and React 18 / Tailwind CSS dashboard (`ui/`).
