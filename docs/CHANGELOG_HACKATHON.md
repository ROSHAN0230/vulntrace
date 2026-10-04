# VulnTrace Studio — Hackathon Development Changelog

All major project updates and milestones completed during the Nebius × NVIDIA Global AI Hackathon 2026.

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
