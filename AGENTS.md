# VulnTrace Studio — Agent Rules & Canonical Blueprint Notice

> **MASTER SPECIFICATION NOTICE:**
> The file `%USERPROFILE%\Downloads\VULNTRACE_STUDIO_SPEC.md` is the **CANONICAL MASTER SPECIFICATION** for the entire VulnTrace Studio project.
> All architectural, product, security, verifier, sandbox, LLM, UI, and evidence decisions must remain strictly consistent with that specification.
> Work must be executed strictly one milestone at a time, following explicit user instruction and approval.

## Agent Rules (Spec Section 8)

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
