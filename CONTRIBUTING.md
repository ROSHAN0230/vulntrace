# Contributing to VulnTrace Studio

Thank you for your interest in contributing to VulnTrace Studio! We welcome community contributions, bug fixes, documentation improvements, and verifier oracle expansions.

---

## 1. Guiding Principles & Technical Specification

All contributions must strictly adhere to the project's canonical technical specification and safety manifesto:
- **Canonical Specification:** [`docs/TECHNICAL_SPEC.md`](docs/TECHNICAL_SPEC.md) is the single source of truth.
- **Safety Policy:** [`docs/SAFETY.md`](docs/SAFETY.md) and [`SECURITY.md`](SECURITY.md) govern all sandbox boundaries and isolation rules.
- **Strict Anti-Gaming & Evaluation Integrity:** VulnTrace never reports ungrounded numbers or synthetic success percentages. Verifier oracles must catch adversarial attempts to bypass checks (see tests in `tests/verifier/`).
- **Strict Zero-Trust Policy:** Non-curated code must never run under Tier 0 host execution. Tier 1 rootless container isolation is mandatory for all non-curated repositories.
- **Behavioral Probes Only:** Never introduce payloads that spawn interactive shells, exfiltrate data, or execute destructive commands.

---

## 2. Development Setup

### System Prerequisites
- **Validated Operating Systems:**
  - Ubuntu 24.04 LTS
  - Windows 11 with WSL2 (Ubuntu 24.04)
- **Required Software:**
  - Python 3.11 or 3.12 (with `python3.12-venv`)
  - Node.js 18+ and `npm`
  - Git
  - Podman 4.9+ (required for Tier 1 container sandbox execution)

### Initializing the Workspace
```bash
# 1. Clone repository with submodules
git clone --recurse-submodules https://github.com/ROSHAN0230/vulntrace.git
cd vulntrace

# 2. Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install Python dependencies in editable mode
pip install -e ".[dev]"

# 4. Install frontend dependencies and build production UI
cd ui
npm install
npm run build
cd ..
```

---

## 3. Testing & Verification

Before submitting any code changes, ensure all quality gates and test suites pass cleanly.

### Running Test Suites
```bash
# A. Offline Unit & Verification Suite (Zero containers, Zero network)
pytest -v -m "not container and not live_network" tests/

# B. Local-First & API-Optional Test Suite
pytest -v tests/test_local_first_api_optional.py

# C. Tier 1 Container Isolation Suite (Requires Podman)
pytest -v -m "container" tests/

# D. Benchmark Verification Gate (Zero drift check)
python bench/run.py --ci

# E. Frontend Unit Tests
cd ui && npm test -- --run && cd ..
```

### Code Style & Formatting
We use **Ruff** for Python linting and code formatting:
```bash
# Check Python code style
.venv/bin/ruff check tests/ vulntrace/ bench/

# Check Git diff for whitespace or conflict markers
git diff --check
```

---

## 4. Pull Request Guidelines

1. **Focused Scopes:** Keep pull requests focused on a single logical change or bug fix.
2. **Deterministic Tests:** Add automated regression tests for every new feature or bug fix. Avoid flaky or timing-dependent tests.
3. **No Secret Leaks:** Never commit `.env` files, API keys, private tokens, or credentials.
4. **Preserve Specification Contracts:** Do not alter verdict strings (`Spec §3.2`), evidence schema field names (`Spec §4.11`), or API endpoints without explicit approval.
5. **Clean History:** Provide clear, descriptive commit messages outlining what was changed and why.
