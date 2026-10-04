# Nebius × NVIDIA Developer Feedback Notes

**Project:** VulnTrace Studio  
**Author:** Roshan (@ROSHAN0230)  
**Track:** Coding & Agentic Engineering (Devpost Hackathon 2026)  

This document logs real runtime experiences, telemetry notes, and engineering feedback regarding Nebius AI Cloud, Token Factory, NVIDIA Nemotron models, and Tavily integration throughout development.

---

## 1. Nebius Token Factory (NVIDIA Nemotron 3 Ultra)

### Observations:
- **API Compatibility:** The OpenAI-compatible endpoints (`https://api.tokenfactory.nebius.com/v1`) allow straightforward integration with standard client libraries (`httpx`, `openai-python`).
- **Contextual Reasoning Quality:** NVIDIA Nemotron 3 Ultra demonstrated superior structural comprehension of abstract syntax trees compared to standard general-purpose models. In custom YAML loader benchmarks (`AppSafeLoader` with custom constructor tags), Nemotron correctly identified that replacing `yaml.load(..., Loader=yaml.Loader)` with naive `yaml.safe_load()` would break application tag handling, and instead synthesized an AST-compliant `yaml.load(..., Loader=AppSafeLoader)`.
- **Reasoning Token Accounting:** Token Factory reports `reasoning_tokens` distinctly in the usage payload, allowing VulnTrace to accurately compute a multi-stage token ledger across triage, planning, and patch generation.

### Suggestions for Improvement:
- **Latency Consistency:** Prompt processing latency can exhibit variance during peak concurrency windows. Having dedicated provisioned throughput options for automated CI/agent loops would improve deterministic test SLAs.
- **Model Catalog Documentation:** Clearer, centralized documentation on context windows and token pricing for specific Nemotron model variants would simplify FinOps budgeting.

---

## 2. Cloud Sandboxes & Execution Isolation (ConTree / Token Factory Sandboxes)

### Observations:
- **Sandbox API Access:** When attempting to provision disposable cloud sandboxes via the ConTree/Nebius Sandbox API (`/sandboxes`), requests returned `HTTP 403 PERMISSION_DENIED` with standard hackathon developer tokens.
- **Engineering Response:** Rather than simulating or mocking cloud execution, VulnTrace implemented an explicit dual-tier substrate:
  1. **Tier 0:** Local subprocess with Win32 Job Objects kernel process-tree termination, sanitized environment variable purging, and profile redirection.
  2. **Tier 1:** Rootless OCI Podman container running with `--network none`, `--cap-drop ALL`, resource limits (512MB RAM, 1.0 CPU, 128 PIDs), and anti-spoofing sentinels.
- **Attestation & Policy:** The system reports `LOCAL_SUBPROCESS_FALLBACK` or `OCI_CONTAINER_ISOLATED` honestly in the signed evidence bundle, strictly preventing overclaiming.

### Suggestions for Improvement:
- **Sandbox Provisioning IAM Permissions:** Provide hackathon participants with pre-configured IAM roles or explicit sandbox quota documentation to enable Tier 2 cloud sandbox execution directly within the pipeline.

---

## 3. Tavily Security Threat Intelligence Search

### Observations:
- **Query Relevance:** Searching for CVEs and PoCs (`<CVE-ID> vulnerable function fix commit`) provides useful technical references. However, Tavily search responses occasionally contain references to adjacent CVEs with similar token numbers.
- **Engineering Solution:** In commit `0aa3e1e`, VulnTrace added a strict CVE relevance validator that checks titles, URLs, and snippet bodies for exact CVE ID matches before labeling them as valid CVE intelligence.
- **Degraded Mode Resilience:** If the Tavily API experiences network timeouts or invalid credentials, the pipeline gracefully marks `intel_status: degraded` without crashing the core verification loop.

---

## 4. Log of Runtime Metrics

| Date | Milestone | Component | Target | Latency | Tokens / Cost |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-10-02 | Phase 4 | Nemotron 3 Ultra | CVE-2020-14343 | 1,420 ms | 251 prompt / 139 completion |
| 2026-10-02 | Phase 4 | Tavily Intel | CVE-2020-14343 | 850 ms | 1 credit |
| 2026-10-03 | P0.6 | Podman OCI | Harness Execution | 3,120 ms | Local compute |
