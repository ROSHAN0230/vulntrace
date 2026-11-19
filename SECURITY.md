# Security Policy — VulnTrace Studio

VulnTrace executes autonomous vulnerability reproduction, proof synthesis, and patch verification against third-party and potentially untrusted target repositories. Because evaluating security vulnerabilities requires running exploit-reproducing harnesses and dependency build hooks, isolation and security controls are central to the application's architecture.

---

## 1. Reporting Security Vulnerabilities

We take the security of VulnTrace Studio and the safety of developer workstations seriously. If you discover a security vulnerability in VulnTrace Studio itself (such as a sandbox escape, privilege escalation, secret leak, or arbitrary code execution outside the intended isolation boundary), please report it responsibly.

### How to Report
- **Preferred Method:** Open a [GitHub Private Vulnerability Report](https://github.com/ROSHAN0230/vulntrace/security/advisories/new) on the repository.
- **Alternative:** Email the maintainer directly at `security@vulntrace.org` with details.
- **Please Include:**
  - A description of the issue and potential impact.
  - Detailed reproduction steps or a minimal proof-of-concept.
  - The execution tier and platform where the issue occurred (e.g., Tier 1 Podman on Ubuntu 24.04).

### Response SLA
- **Initial Acknowledgment:** Within 48 hours.
- **Triage & Assessment:** Within 5 business days.
- **Coordinated Disclosure:** We adhere to a 90-day responsible disclosure timeline or coordinate an earlier public fix release.

Please do **NOT** file public GitHub issues for unpatched security vulnerabilities.

---

## 2. Security Architecture & Threat Model

For the exhaustive specification of our safety model, see [`docs/SAFETY.md`](docs/SAFETY.md) and [`docs/TECHNICAL_SPEC.md`](docs/TECHNICAL_SPEC.md).

### Isolation Tiers
VulnTrace enforces a strictly tiered execution model:

| Tier | Substrate | Use Case | Network Boundary | Filesystem Boundary | Identity & Privileges |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Tier 0** | `LocalSubprocessBackend` | **Curated dev fixtures only.** Refuses non-curated / third-party code. | Proxy null-routing (`127.0.0.1:0`). | Disposable workspace. Ambient host user permissions. | Ambient host user, 512MB RAM cap. |
| **Tier 1** | `ContainerExecutionBackend` (Rootless Podman + crun OCI) | **Mandatory default for all real-world / non-curated code.** | **Kernel-enforced denial:** `--network none`. No network interfaces mapped except loopback. | **Read-only root:** `--read-only`. Ephemeral 64MB tmpfs at `/tmp`. Workspace mounted at `/workspace:rw`. | Non-root `1000:1000`, `--cap-drop ALL`, `no-new-privileges`, 512MB RAM, 1.0 CPU, 128 PIDs cap, wall-clock watchdog. |
| **Tier 2** | Remote Cloud MicroVM | Future extension. | Dedicated VPC with egress filtering. | Ephemeral disk destroyed on termination. | Ephemeral cloud worker. |

### Strict Zero-Trust Policy
- Non-curated or untrusted repositories must **never** execute under Tier 0.
- All real-world and third-party target repositories unconditionally mandate **Tier 1** rootless container isolation.
- No override flags (`--unsafe-local`, `unsafe_local=True`, or `VULNTRACE_UNSAFE_LOCAL=1`) authorize Tier 0 execution of non-curated repositories.

### Payload & Probe Policy
- Payloads synthesized by VulnTrace are **behavioral probes only**.
- Probes write a non-destructive timestamped sentinel file to disposable scratch space to verify vulnerability reproduction.
- Interactive shells, reverse connections, persistent filesystem modifications, and destructive commands are strictly prohibited by system policy.

---

## 3. Secret Isolation & Credential Hygiene

- **Local-First / API-Optional:** VulnTrace requires zero API credentials for core execution.
- **Purged Sandbox Environments:** When running sandboxed container processes, host environment variables—including any configured API keys (`NEBIUS_API_KEY`, `TAVILY_API_KEY`)—are stripped completely from child container environments.
- **Evidence Sanitization:** Serialized evidence bundles, diff outputs, and cryptographic signatures are audited to ensure credentials and host paths are never embedded or exported.

---

## 4. Known Platform & Sandbox Limitations

- **Validated Environments:** Tier 1 rootless container isolation is verified on **Ubuntu 24.04 LTS** and **Windows 11 with WSL2 (Ubuntu 24.04)** with Podman 4.9+ and crun with cgroups v2.
- **Host Dependencies:** Tier 1 isolation relies on the host kernel's user namespace and cgroups v2 implementation. Running in environments with disabled user namespaces or cgroups v1 will prevent Tier 1 container preflight from passing (failing closed).
- **Native Windows / macOS:** Native Windows (without WSL2) and macOS do not support rootless Linux OCI container primitives and are not supported for Tier 1 isolation.
- **Static Analysis Scope:** AST call-graph reachability analyzes direct static Python imports and call paths; dynamic runtime code evaluation (`eval`, dynamic `__import__`) lies outside static solver boundaries.
