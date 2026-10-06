# VulnTrace Studio — Hackathon Development Changelog

All major project updates and milestones completed during the Nebius × NVIDIA Global AI Hackathon 2026.

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
- **Repository Hygiene:** Cleaned repository root to $\le 10$ items. Archived legacy Phase 1–4 reports, compliance audits, and screenshots into `docs/archive/`.
- **Agent Rules & Master Spec:** Adopted `VULNTRACE_STUDIO_SPEC.md` as the canonical master specification and recorded Section 8 rules into `AGENTS.md` and `.agents/rules/directive.md`.
- **Fixtures & Tests Refactoring:** Relocated loose `sample_repo` into `tests/fixtures/sample_repo` and verified all 108 tests pass.
- **Continuous Integration:** Created initial GitHub Actions CI workflow skeleton (`.github/workflows/ci.yml`).
- **Baseline Evidence:** Recorded full 108-test command output and multi-scenario benchmark in `docs/evidence/baseline_run.md`.
- **Clean Container Proof:** Executed full clone, editable installation (`pip install -e .`), and test suite in clean unprivileged container (`python:3.11-slim` via Podman in WSL2), verifying 86 passed, 15 skipped, 0 failed.
- **[VERIFY] Audit Matrix:** Completed comprehensive audit of all 9 specification items marked `[VERIFY]` in `docs/evidence/verify_audit.md`.
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
