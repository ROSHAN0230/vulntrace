# VulnTrace Studio v0.1.0 — Initial Open-Source Release Notes

**Release Date:** November 18, 2026
**License:** Apache 2.0
**Repository:** `https://github.com/ROSHAN0230/vulntrace`

---

## 1. Overview & Architecture

VulnTrace Studio v0.1.0 is the first public open-source release of the autonomous vulnerability reproduction, proof synthesis, and verified patching agent.

Unlike manifest-only Software Composition Analysis (SCA) scanners that alert on version numbers in lockfiles regardless of reachability, VulnTrace establishes empirical proof through multi-file AST call-graph reachability, controlled container reproduction, surgical remediation, differential verification, and cryptographic evidence signing.

### Key Capabilities in v0.1.0
- **Local-First, API-Optional Execution:** The entire application—including reachability analysis, behavioral reproduction, AST deterministic patching, post-patch verification, and cryptographic evidence export—functions completely locally on the user's workstation with **zero paid API keys required**.
- **Optional Cloud AI & Threat Intel:** Supports optional enrichment via NVIDIA Nemotron 3 Ultra (via Nebius Token Factory) and Tavily Threat Intel. Both integrations require active credentials and **explicit per-run user opt-in**; they are strictly disabled by default.
- **Strict Tier 1 Rootless Container Isolation:** Mandatory sandbox execution for all non-curated / third-party code utilizing rootless Podman with kernel network denial (`--network none`), read-only root filesystems (`--read-only`), ephemeral 64MB tmpfs (`/tmp`), unprivileged user (`1000:1000`), dropped Linux capabilities (`--cap-drop ALL`), and cgroup resource limits.
- **Parent-Audited Verifier Oracles:** Post-patch trust is evaluated across an unforgeable parent boundary auditing physical filesystem sentinels and mandatory exit code 42, defeating adversarial attempts to bypass checks.
- **Cryptographic Evidence Signing:** Exports self-contained, Ed25519-signed evidence bundles verified both via CLI (`vulntrace verify-bundle`) and in-browser Web Crypto API.
- **Interactive Web Studio & Replay Stepper:** Full-featured React frontend with live SSE step streaming, visual reachability inspector, diff viewer, and an interactive 7-stage evidence replay stepper.

---

## 2. Platform & Compatibility Matrix

| Platform / Environment | Tier 0 (Curated Fixtures) | Tier 1 (Third-Party Code) | Support Status |
| :--- | :---: | :---: | :--- |
| **Ubuntu 24.04 LTS (x86_64)** | Supported | Supported | **Fully Validated & Supported** |
| **Windows 11 with WSL2 (Ubuntu 24.04)** | Supported | Supported | **Fully Validated & Supported** |
| **Native Windows 11 (without WSL2)** | Supported (Dev fixtures only) | Not Supported | Experimental / Curated fixtures only |
| **macOS (Darwin)** | Supported (Dev fixtures only) | Not Supported | Experimental / Curated fixtures only |
| **Linux ARM64** | Unverified | Unverified | Untested / Community experimental |

---

## 3. Supported Vulnerability Classes & Remediation Engines

| Vulnerability Class | Reachability Analysis | Behavioral Reproduction | Deterministic AST Remediation | LLM Contextual Remediation | Status |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **UNSAFE_DESERIALIZATION** (CWE-502) | Yes | Yes (Object instantiator canary) | Yes (`yaml.safe_load` / `AppSafeLoader`) | Supported (Nemotron 3 Ultra) | **Fully Supported** |
| **PATH_TRAVERSAL** (CWE-22) | Yes | Yes (Tar/zip escape probe) | Yes (PEP 706 `filter='data'`) | Supported (Nemotron 3 Ultra) | **Fully Supported** |
| **COMMAND_INJECTION** (CWE-78) | — | — | — | — | **Frozen** (Excluded to uphold non-destructive payload policy) |

---

## 4. Known Boundaries & Limitations

1. **Third-Party Container Execution:** Analyzing third-party or real-world repositories mandates rootless Podman with cgroups v2. Environments lacking container runtimes cannot safely execute non-curated code under VulnTrace's safety policy.
2. **Static AST Analysis Scope:** Reachability solvers analyze static Python call paths from declared entrypoints. Dynamic reflection, runtime monkeypatching, or dynamic plugin dispatch fall outside static solver boundaries.
3. **External Network Access for Dependencies:** When analyzing repositories with unprovisioned dependencies, the host environment builder requires outbound PyPI connectivity unless dependencies are pre-installed in the container base image.
4. **Command Injection Frozen:** Per specification cut-line decisions, command injection is excluded from active remediation to strictly enforce non-destructive, non-shell payload guidelines.
