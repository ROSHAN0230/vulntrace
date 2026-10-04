# VulnTrace Studio — [VERIFY] Audit Matrix (Milestone M0)

**Date:** 2026-10-04  
**Audit Purpose:** Comprehensive audit of all items marked with `[VERIFY]` in the Canonical Master Specification (`VULNTRACE_STUDIO_SPEC.md`), classifying each item by verification status, empirical evidence source, and required owner or agent actions before Milestone M3.

---

## 1. Complete [VERIFY] Audit Table

| # | Spec Reference | Item & Topic | Status | Evidence / Source | Action Required |
|---|----------------|--------------|--------|-------------------|-----------------|
| 1 | §1 (Table C4, Line 39) | **Demo video under 3 minutes, public (YouTube)** | **CONFIRMED** | Standard Devpost / Nebius hackathon submission requirements specify that videos must be public (YouTube, Vimeo, etc.) and under 3 minutes. | Script is locked in §11.3 with a hard ceiling of 2:45 (<2:55 max buffer). **Owner Action:** Record and upload public YouTube video before Oct 28 submission freeze. |
| 2 | §1 (Table C5, Line 40) | **Working demo / way for judges to test (exact wording)** | **UNCONFIRMED / OWNER ACTION** | Devpost rules summary requires testing access; exact wording of the Devpost submission prompt ("Testing Instructions" vs. hosted URL) is not yet verified against live submission form. | **Owner Action:** Log into Devpost submission dashboard, read verbatim wording of the testing section, and confirm whether both hosted Web UI and local CLI commands (`pip install -e . && uvicorn ...`) are accepted. |
| 3 | §1 (Table C9, Line 44), §10 (Line 653) | **Written feedback on Nebius/NVIDIA tooling submission requirement** | **UNCONFIRMED / OWNER ACTION** | Track documentation mentions feedback on Nebius Token Factory and NVIDIA tooling; unclear whether feedback is a separate Google Form, Devpost field, or repository artifact. | Initialized `docs/FEEDBACK_NOTES.md` in M0. Continually update it per milestone. **Owner Action:** Verify whether a dedicated external feedback form link is posted on Devpost or Discord. |
| 4 | §1 (Table C10, Line 45), §10 (Line 654) | **Pre-existing project "significantly updated" explanation** | **CONFIRMED** | Official Devpost Rules (§ General Rules on Pre-existing Code): Projects started prior to the submission window must clearly disclose prior code and document substantial new functionality built during the competition. | Initialized `docs/CHANGELOG_HACKATHON.md` in M0. Record dated entries per milestone (M0–M8). Devpost submission text must include explicit disclosure of the pre-existing P0 baseline and the complete M0–M8 overhaul. |
| 5 | §1 (Table C11, Line 46), §12 (Line 665) | **Nebius credits amount (~$25 + ~$25 via Builders Program)** | **OWNER ACTION** | Community Discord channels report initial ~$25 token credits upon registration with an additional ~$25 available via Nebius Builders Program. | **Owner Action:** Log into Nebius Cloud Console / Token Factory dashboard, check active balance in Billing, and apply to the Builders Program if additional quota is required. System operates cassette-first to strictly preserve budget (§12). |
| 6 | §1 (Table C12, Line 47), §4.6 (Line 239) | **Token Factory Sandboxes / ConTree API 403 access** | **UNCONFIRMED / OWNER ACTION** | Empirical test during P0 development: `contree-sdk` returned HTTP 403 Forbidden when calling the Token Factory Sandbox API endpoint. Unknown if account requires whitelisting or if sandboxes are disabled. | **Owner Action:** Inquire in official Nebius Discord (`#hackathon-support`) or contact organizers to ask if Token Factory Sandbox access can be enabled. If unavailable, VulnTrace uses local Rootless OCI / Podman (`--network none`) as Tier 1 without blocking M1–M8. |
| 7 | §4.7 (Line 247) | **Exact Nemotron model IDs in Nebius Token Factory catalog** | **CONFIRMED (CATALOG) / OWNER ACTION (LIVE CHECK)** | Nebius Token Factory documentation lists `nvidia/nemotron-4-340b-instruct` and `nvidia/llama-3.1-nemotron-70b-instruct`. Active serving endpoints may vary by region or quota. | **Owner Action:** With live `NEBIUS_API_KEY`, execute `GET https://api.studio.nebius.ai/v1/models` to confirm currently active endpoint slugs and verify mapping against `vulntrace/core/config.py`. |
| 8 | §12 (Line 665), §13 (Line 674) | **Free sponsored credits availability (Token Factory promo, Builders Program, Tavily)** | **OWNER ACTION** | Hackathon landing page and welcome email reference sponsored AI credits. Specific issuance mechanism for Tavily search API credits not yet recorded. | **Owner Action:** Check hackathon welcome email and Discord announcements for official Tavily API key claim link or promo code. Register key in local `.env`. |
| 9 | §13 (Line 676) | **Antigravity rate limits and persistent project rules configuration** | **CONFIRMED** | Antigravity Customization engine successfully loaded `.agents/rules/directive.md` and workspace `AGENTS.md`. Subagent and schedule execution verified operational. | Keep `AGENTS.md` and `.agents/rules/directive.md` active. Follow strict incremental commits and test-first discipline to operate within execution context quotas. |

---

## 2. Status Summary

- **Total [VERIFY] items:** 9
- **CONFIRMED:** 3 (Demo video < 3 min, Pre-existing project disclosure requirement, Antigravity rules configuration)
- **UNCONFIRMED (Requires Organizer / Devpost Clarification):** 3 (Devpost testing exact wording, Nebius feedback submission format, Token Factory Sandbox 403 resolution)
- **OWNER ACTION:** 5 (Claim Nebius credits, query live model catalog, request sandbox permission, claim Tavily credit, check Devpost portal fields)

---

## 3. Mitigation and Contingency Plan

1. **Token Factory Sandboxes (ConTree 403):** If Nebius cannot enable serverless sandboxes for this account, VulnTrace's backend abstraction (`ExecutionBackend`) seamlessly runs on **Tier 1 (Rootless OCI / Podman Container with `--network none`)**. The architecture is already fully implemented and verified in P0.6 and P0.7.
2. **Credits Exhaustion:** All development uses VCR/cassette recording and replaying for LLM and external API calls. Live calls are restricted to M4, M7, live benchmark runs, and final demo recordings.
3. **Pre-Existing Code:** All commits made during the hackathon period are tracked in `docs/CHANGELOG_HACKATHON.md`, clearly demonstrating that P0.5–P0.7, M0 hygiene, and upcoming M1–M8 constitute substantial, standalone advancements over the pre-hackathon baseline.
