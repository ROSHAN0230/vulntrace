# VulnTrace Studio — Held-Out Evaluation Dataset Specifications

## Overview and Segregation Guarantee

This document defines the verified held-out benchmark candidate specifications for VulnTrace Studio.

> [!IMPORTANT]
> **Segregation Guarantee:**
> All candidate cases documented herein are **strictly segregated** from development tuning, prompt engineering, and pipeline iteration. They are **not** cloned into the workspace, **not** executed during standard development or continuous integration, and are **strictly excluded** from development-set benchmark metrics and pass rates. They serve as an independent post-tuning generalizability validation suite.

---

## Authorized Sink Class Candidate Specifications

The current authorized sink classes under the M7 benchmark scope are:
1. **Unsafe Deserialization**
2. **Path Traversal**

*(Command Injection remains strictly frozen and out of scope).*

---

### Candidate HELD-01: aiohttp Path Traversal (CVE-2024-23334)

- **Repository:** `aio-libs/aiohttp` (`https://github.com/aio-libs/aiohttp`)
- **Primary Advisories:** [GHSA-5h86-8mv2-jq9f](https://github.com/advisories/GHSA-5h86-8mv2-jq9f) / [CVE-2024-23334](https://nvd.nist.gov/vuln/detail/CVE-2024-23334)
- **Sink Class:** Path Traversal
- **Vulnerable Revision (Parent Commit):** `33ccdfb0a12690af5bb49bda2319ec0907fa7827`
- **Fixed Revision (Patch Commit):** `1c335944d6a8b1298baf179b7c0b3069f10c514b` (PR #8079)
- **Vulnerable Configuration:**
  Static routes registered with `follow_symlinks=True` via `web.Application().router.add_static("/static", path, follow_symlinks=True)`.
- **Reproducible Oracle Specification:**
  Standard HTTP client libraries (such as `requests` or `urllib`) automatically normalize dot-segments (`/../`) in request URLs prior to socket transmission, which would mask the server vulnerability. Therefore, the reproduction harness requires an unnormalized **raw socket** HTTP transmission (using `asyncio.open_connection` or `socket.socket`) sending `GET /static/../private_file HTTP/1.1\r\nHost: localhost\r\n\r\n`.
  - **Vulnerable Parent State:** The server parses the raw path, follows symlinks past the designated static directory root, and responds with `HTTP/1.1 200 OK` exposing the contents of the target private file.
  - **Fixed Patch State:** The server validates boundary containment and responds with `HTTP/1.1 404 Not Found` or `403 Forbidden`.

---

### Candidate HELD-02: PyYAML Deserialization (CVE-2020-1747)

- **Repository:** `yaml/pyyaml` (`https://github.com/yaml/pyyaml`)
- **Primary Advisories:** [CVE-2020-1747](https://nvd.nist.gov/vuln/detail/CVE-2020-1747) / [PR #386](https://github.com/yaml/pyyaml/pull/386)
- **Sink Class:** Unsafe Deserialization
- **Vulnerable Revision (Parent Commit):** `2f463cf5b0e98a52bc20e348d1e69761bf263b86`
- **Fixed Revision (Patch Commit):** `6f675f711a807af61233355c6d127a3a2e412dbe` (PR #386)
- **Vulnerable Configuration:**
  `FullLoader` or `yaml.full_load` processing untrusted YAML payloads abusing `python/object/new` constructor with argument tuples that bypass initial class restrictions via `set_python_instance_state`.
- **Reproducible Oracle Specification:**
  The reproduction probe utilizes a bounded, benign canary payload utilizing `!!python/object/new:yaml.MappingNode` or similar constructor:
  `!!python/object/new:tuple [!!python/object/new:map [!!python/name:eval , ["__import__('pathlib').Path('canary.txt').touch()"]]]`
  *(or an equivalent bounded canary file creation probe executed within disposable Tier 1 sandbox space)*.
  - **Vulnerable Parent State:** `yaml.full_load()` executes the constructor, triggering method invocation and creating the canary file without constructor rejection.
  - **Fixed Patch State:** `yaml.constructor.ConstructorError` is raised immediately upon encountering unauthorized object/state constructors, and no canary is created.

---

### Candidate HELD-03: Tornado Path Traversal (CVE-2026-103263)

- **Repository:** `tornadoweb/tornado` (`https://github.com/tornadoweb/tornado`)
- **Primary Advisories:** [GHSA-c2m8-h5v5-343r](https://github.com/advisories/GHSA-c2m8-h5v5-343r) / [CVE-2026-103263](https://nvd.nist.gov/vuln/detail/CVE-2026-103263)
- **Sink Class:** Path Traversal
- **Vulnerable Revision (Parent Commit):** `03945136ea9746eccf61caf88edae39642e59c93`
- **Fixed Revision (Patch Commit):** `437ab5f76565403b3403438d2e555d11f8128d32` (Release 6.5.9)
- **Vulnerable Configuration:**
  `tornado.web.StaticFileHandler` serving a static root containing a symbolic link pointing to a file outside the root, in configurations where `allowed_symlink_directory` is not set or improperly checked.
- **Reproducible Oracle Specification:**
  A static directory contains a real **symlink** (`link_to_secret.txt -> /outside/secret_file.txt`).
  An HTTP GET request is made for `/static/link_to_secret.txt`.
  - **Vulnerable Parent State:** The handler traverses the symlink, resolves to the external target, and returns `HTTP/1.1 200 OK` with the secret contents.
  - **Fixed Patch State:** The handler validates the target against `allowed_symlink_directory` or rejects external symlink dereferencing, returning `HTTP/1.1 403 Forbidden`.
