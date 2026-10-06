# VulnTrace Studio — Safety Architecture & Isolation Boundaries

**Canonical Reference:** `VULNTRACE_STUDIO_SPEC.md` §4.6, §4.14, and Milestone M3 Acceptance Criteria.  
**Classification:** Public Security and Safety Policy.

---

## 1. Executive Summary & Safety Manifesto

VulnTrace executes autonomous vulnerability reproduction, proof synthesis, and patch verification against third-party and potentially untrusted repositories. Because evaluating security vulnerabilities requires running exploit-reproducing harnesses and dependency build hooks, **isolation is not an optional optimization—it is a critical security boundary.**

VulnTrace enforces three foundational safety principles:
1. **Never Mislead on Isolation:** Tier 0 (Local Subprocess) is explicitly classified as `DEGRADED_FALLBACK` for developer testing and curated fixtures. It is never advertised as an "isolated sandbox".
2. **Contain Real Code by Default:** Any real or non-curated repository input mandates Tier 1 (Rootless Container) isolation with kernel network denial, read-only root filesystems, unprivileged non-root execution, and strict cgroup caps.
3. **Zero Trust in Executing Payloads:** Child processes running under test are untrusted. Telemetry, exit codes, and physical file markers are audited independently across a parent-side trust boundary.

---

## 2. Isolation Tiers Overview

VulnTrace defines a strictly tiered execution model:

| Tier | Substrate / Mechanism | Intended Usage | Network Policy | Filesystem Policy | Identity & Limits |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Tier 0** | `LocalSubprocessBackend` (Host process + Win32 Job Object / POSIX process tree) | **Developer machines & curated fixtures only.** Refuses non-curated input unless explicitly overridden with `--unsafe-local`. | Cooperative environment proxy null-routing (`HTTP_PROXY=http://127.0.0.1:0`). Raw sockets bypass. | Disposable host workspace directory. Ambient filesystem readable under host DACLs. | Ambient host OS user; 512MB memory cap; sanitized environment variables. |
| **Tier 1** | `ContainerExecutionBackend` (Rootless Podman / crun OCI container in WSL2/Linux) | **Default execution tier for all real-world / non-curated repositories.** | **Kernel-enforced denial:** `--network none`. Network stack unmapped. | **Read-only root FS:** `--read-only`. Ephemeral tmpfs `/tmp` (64MB). Disposable workspace mounted at `/workspace:rw`. | **Unprivileged user:** `--user 1000:1000`. Capabilities dropped: `--cap-drop ALL`, `--security-opt no-new-privileges`. Limits: 512MB RAM, 1.0 CPU, 128 PIDs, wall-clock watchdog. |
| **Tier 2** | Remote Cloud Sandbox (Serverless ephemeral microVM / cloud worker) | Future extension (Spec §4.6 Tier 2). | Fully isolated VPC with egress filter. | Ephemeral disk volume destroyed on termination. | Dedicated ephemeral microVM. |

> **Benchmark Boundary Disclosure (Spec §4.6 / Decision D3 / Option B):**
> - **CASE-RW-01 (Flasgger):** Executed under **Tier 0** (`LOCAL_SUBPROCESS_FALLBACK`) with explicit `--unsafe-local` override specifically to validate host virtualenv creation and legacy Python 3.10 syntax support (**Milestone M2 Environment-Builder Compatibility Test**). It was **not** isolated under Tier 1.
> - **CASE-RW-04 (Cloud Config Service):** Executed end-to-end under **Tier 1** (`OCI_CONTAINER_ISOLATED`), demonstrating full rootless container isolation with kernel network denial, read-only rootfs, tmpfs scratch, and unprivileged user execution.
> - By default, all non-curated repositories refuse Tier 0 execution and mandate Tier 1 isolation.

---

## 3. Tier 1 Rootless Container Hardening Specifications

When Tier 1 is active, every execution (including harness reproduction, dependency builds, and pytest regressions) runs inside an isolated rootless container with the following enforced flags:

### 3.1 Kernel Network Denial (`--network none`)
- The container namespace is initialized with only a loopback interface (`lo`). No veth interfaces or network bridges are attached.
- Outbound socket calls (`connect()`, `getaddrinfo()`) fail immediately at the kernel level with `Network is unreachable` or `Name or service not known`.
- Prevents remote code execution callbacks, command-and-control beaconing, telemetry exfiltration, and SSRF attacks.

### 3.2 Read-Only Root Filesystem (`--read-only`)
- The container root filesystem (`/`) is mounted read-only.
- Write attempts to system binaries (`/bin`, `/usr`), configuration files (`/etc`), system libraries (`/lib`), or Python site-packages fail with `Read-only file system` (`[Errno 30]`).
- Prevents persistent backdooring, tampering with Python standard libraries, or system-level state corruption.

### 3.3 Ephemeral tmpfs Scratch (`--tmpfs /tmp:rw,nosuid,nodev,size=64m`)
- Temporary build files and caches are directed to an in-memory `tmpfs` mounted at `/tmp`.
- Mounted with `nosuid` and `nodev` mount options to prevent setuid exploitation or device node creation.
- Capped at 64MB; unmounted and destroyed automatically when the container terminates.
- Native build tools (`setup.py build`) are explicitly directed to `/tmp/build` to prevent host file permission collisions.

### 3.4 Unprivileged Non-Root Identity (`--user 1000:1000`)
- Containers execute strictly as non-root user `1000:1000`.
- Even if container breakout vulnerabilities were attempted, the process has no root privileges inside the container user namespace.

### 3.5 Complete Linux Capability Dropping
- Flags: `--cap-drop ALL --security-opt no-new-privileges`.
- Drops all kernel capabilities (including `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, etc.).
- Prohibits child processes from gaining elevated privileges via setuid binaries.

### 3.6 Resource & Process Explosion Limits (cgroups)
- `--memory 512m`: Containers consuming more than 512MB of RAM are terminated immediately by the cgroup OOM killer (exit code 137).
- `--cpus 1.0`: Prevents CPU starvation of the host machine by pinning execution to a maximum of 1.0 CPU quota.
- `--pids-limit 128`: Prevents fork bombs and process tree explosions. Process creation fails with `BlockingIOError: [Errno 11] Resource temporarily unavailable` once 128 PIDs are reached.

### 3.7 Wall-Clock Watchdog with Descendant Termination
- Podman native runtime watchdog is enforced via `--timeout <seconds>`.
- In addition, the parent process wraps container execution with a host timeout watchdog.
- If execution exceeds the wall-clock threshold, Podman crun terminates the container and all nested processes with exit code 255. A fallback `podman rm -f <container_name>` ensures no orphaned containers remain.

### 3.8 Strict Host Volume Isolation
- **No host filesystem mounts:** Only the disposable copy of the workspace is mounted (`-v <workspace>:/workspace:rw`).
- Host user home directories (`~/.ssh`, `~/.aws`, `~/.config`), system roots (`C:\`, `/`), and application directories are never mounted into the container.
- Host credentials (`NEBIUS_API_KEY`, `TAVILY_API_KEY`, etc.) are completely absent from the container environment.

---

## 4. Tier 0 Refusal & Degraded Fallback Policy

Tier 0 (`LocalSubprocessBackend`) executes harnesses directly on the host operating system. To protect developers and infrastructure:

1. **Refusal of Non-Curated Input:**
   - Tier 0 explicitly inspects repository paths.
   - Any repository that is not a known curated developer fixture (such as `tests/fixtures/sample_repo` or `tests/fixtures/deserialization/`) is **strictly refused** by default, raising `PermissionError`.
2. **Explicit User Override (`--unsafe-local`):**
   - Untrusted repository execution on Tier 0 requires an explicit developer opt-in (`unsafe_local=True` or `--unsafe-local`).
3. **Honest Labeling & Attestation:**
   - Tier 0 attestation explicitly brands runtime engines as `(DEGRADED_TIER_0)`.
   - Documentation and UI disclose: "Process executes under ambient host OS user identity without OS user separation. Network isolation is cooperative."
4. **Benchmark Testing Context (CASE-RW-01 vs CASE-RW-04):**
   - The `--unsafe-local` override is exercised in the real-world evaluation matrix exclusively for `CASE-RW-01` to test the host-based `EnvironmentBuilder` pipeline on legacy Python 3.10 runtimes.
   - Zero documentation or evaluation reports claim that `CASE-RW-01` was isolated in Tier 1.
   - `CASE-RW-04` serves as the official M3 Tier-1 Container Isolation benchmark under `OCI_CONTAINER_ISOLATED`.

---

## 5. Behavioral Probe Payload Policy

VulnTrace synthesizes reproduction harnesses to confirm whether an application is vulnerable to an alert. To guarantee safe verification:

1. **No Interactive Shells:** Probe payloads must never spawn `/bin/sh`, `/bin/bash`, `cmd.exe`, or `powershell.exe`.
2. **No Network Callbacks:** Payloads must never perform reverse shells, HTTP requests, DNS queries, or network beacons.
3. **No Credential Exfiltration:** Payloads must never read or transmit host environment variables, tokens, or configuration files.
4. **Target-Bound Benign Sentinels:** Payloads are restricted to:
   - Creating a timestamped sentinel file (e.g., `sentinel.txt`) strictly inside the target workspace directory via benign object instantiation (e.g., PyYAML `ObjectInstantiator`).
   - Verifying expected exception signatures (e.g., `ConstructorError`, `SafeLoader` block).
5. **Parent-Validated Proof:** The presence or absence of the physical sentinel file on disk is validated independently by the parent runner, not by trusting child stdout.

---

## 6. Threat Model

| Threat Scenario | Vector | VulnTrace Defense (Tier 1) | Defense Outcome |
| :--- | :--- | :--- | :--- |
| **Malicious Repository Setup Hook** | `setup.py` contains malicious network exfiltration or shell execution. | Provisioning runs inside container with `--network none`, `--read-only`, and `--cap-drop ALL`. | Network calls fail; system files unwritable; host unaffected. |
| **Outbound Data Exfiltration** | Exploit payload attempts to send host environment or code to external C2 server. | Container has `--network none` (no veth attached). | Kernel immediately returns `Network is unreachable`. |
| **Host Credential Theft** | Exploit payload attempts to read `~/.ssh/id_rsa` or host cloud tokens. | No host paths mounted; environment variables sanitized; container root is isolated OCI image. | Host files do not exist inside container mount namespace. |
| **Denial of Service (Fork Bomb)** | Malicious code spawns thousands of child processes to freeze host. | Container is bounded by `--pids-limit 128`. | Child process creation blocked by kernel cgroup. |
| **Denial of Service (Memory Hog)** | Exploit allocates gigabytes of RAM to exhaust host memory. | Container is bounded by `--memory 512m`. | cgroup OOM killer terminates container process tree. |
| **Runaway Process / Infinite Loop** | Exploit hangs indefinitely in a busy-wait loop. | Native crun `--timeout` and host watchdog timer kill process. | Terminated with timeout exit code (-9 / 255); workspace unlinked. |
| **Spoofed Verification (Fake GREEN)** | Compromised harness outputs forged telemetry claiming exploit was blocked. | Parent runner verifies physical disk absence of sentinel and mandates dedicated exit code 42. | Tampered stdout rejected; verdict marked `VERIFICATION_REJECTED`. |
| **Privilege Escalation** | Code attempts to gain root privileges via setuid binaries. | Flags `--user 1000:1000`, `--cap-drop ALL`, and `no-new-privileges`. | Privilege escalation blocked by Linux kernel. |
