"""
VulnTrace Anti-Gaming Verifier Runner (Spec §4.4)

Coordinates multi-run deterministic verification:
1. RED reproduced 3/3 runs
2. Pre/Post SHA-256 integrity check (harness and test files outside patched tree)
3. Patch denylist enforcement (AST analysis)
4. GREEN verified 3/3 runs with expected block signature and positive controls
5. Anti-spoofing guard: bare exit 42 without structured proof is rejected
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple

from vulntrace.core.backend import ExecutionBackend
from vulntrace.sinks.base import ExpectedBlockSignature


@dataclass
class SingleRunResult:
    run_index: int
    exit_code: int
    stdout: str
    stderr: str
    sentinel_created: bool
    assertion_result: str
    exception_type: Optional[str]
    positive_control_passed: bool
    structured_evidence: Dict[str, Any]
    latency_ms: float
    is_valid_green: bool = False
    is_valid_red: bool = False


@dataclass
class AntiGamingAuditSummary:
    red_runs_passed: int
    red_runs_total: int
    red_consistent: bool
    green_runs_passed: int
    green_runs_total: int
    green_consistent: bool
    integrity_intact: bool
    integrity_violations: List[str] = field(default_factory=list)
    denylist_clean: bool = True
    denylist_violations: List[str] = field(default_factory=list)
    signature_matched: bool = False
    positive_control_verified: bool = False
    spoofing_prevented: bool = False
    final_verdict: str = "NON_GREEN"
    verdict_reason: str = ""


class AntiGamingVerifier:
    """
    Executes anti-gaming verification protocol across an isolated execution backend.
    """

    REPLICATION_COUNT = 3

    @classmethod
    async def verify_red_reproduction_3x(
        cls,
        backend: ExecutionBackend,
        workspace_id: str,
        harness_script_name: str,
        sentinel_filename: str,
        runs_count: int = REPLICATION_COUNT,
    ) -> Tuple[bool, List[SingleRunResult], str]:
        """
        Executes pre-patch harness `runs_count` times (default 3/3).
        Every run must exit 0, create sentinel, and report RED_PASSED.
        """
        results: List[SingleRunResult] = []

        for idx in range(1, runs_count + 1):
            cmd_res = await backend.execute_script(
                workspace_id=workspace_id,
                script_name=harness_script_name,
                sentinel_filename=sentinel_filename,
                timeout=10.0,
            )

            is_red = (
                cmd_res.exit_code == 0
                and cmd_res.sentinel_created is True
                and cmd_res.assertion_result == "RED_PASSED"
            )

            run_res = SingleRunResult(
                run_index=idx,
                exit_code=cmd_res.exit_code,
                stdout=cmd_res.stdout,
                stderr=cmd_res.stderr,
                sentinel_created=cmd_res.sentinel_created,
                assertion_result=cmd_res.assertion_result or "UNKNOWN",
                exception_type=cmd_res.exception_type,
                positive_control_passed=False,
                structured_evidence=cmd_res.structured_evidence or {},
                latency_ms=cmd_res.latency_ms,
                is_valid_red=is_red,
            )
            results.append(run_res)

            if not is_red:
                return (
                    False,
                    results,
                    f"RED flake/failure on run {idx}/{runs_count}: exit {cmd_res.exit_code}, sentinel={cmd_res.sentinel_created}, assertion={cmd_res.assertion_result}",
                )

        return True, results, f"Confirmed RED 3/3: All {runs_count} runs reproduced vulnerable behavior."

    @classmethod
    async def verify_green_remediation_3x(
        cls,
        backend: ExecutionBackend,
        workspace_id: str,
        harness_script_name: str,
        sentinel_filename: str,
        expected_signature: ExpectedBlockSignature,
        runs_count: int = REPLICATION_COUNT,
    ) -> Tuple[bool, List[SingleRunResult], str]:
        """
        Executes post-patch harness `runs_count` times (default 3/3).
        Every run must:
        - Exit with code 42
        - Sentinel absent on disk
        - Structured evidence present and asserts GREEN_SECURITY_BLOCK_VERIFIED
        - Positive control passes on benign inputs
        - Exception type matches expected block signature (bare crashes / exit 42 rejected)
        """
        results: List[SingleRunResult] = []

        for idx in range(1, runs_count + 1):
            cmd_res = await backend.execute_script(
                workspace_id=workspace_id,
                script_name=harness_script_name,
                sentinel_filename=sentinel_filename,
                timeout=10.0,
            )

            struct_ev = cmd_res.structured_evidence or {}
            exc_type = cmd_res.exception_type or struct_ev.get("exception_type")
            pos_ctrl = struct_ev.get("positive_control_passed", False)
            assertion = cmd_res.assertion_result or struct_ev.get("assertion")

            # Check expected block signature match
            sig_ok = expected_signature.matches(exc_type or "", struct_ev.get("detail", ""))

            # ANTI-SPOOFING CHECK:
            # If candidate code injected sys.exit(42), process exits 42 but structured evidence is missing or pos_ctrl is False!
            is_valid_green = (
                cmd_res.exit_code == 42
                and not cmd_res.sentinel_created
                and assertion == "GREEN_SECURITY_BLOCK_VERIFIED"
                and pos_ctrl is True
                and sig_ok
            )

            run_res = SingleRunResult(
                run_index=idx,
                exit_code=cmd_res.exit_code,
                stdout=cmd_res.stdout,
                stderr=cmd_res.stderr,
                sentinel_created=cmd_res.sentinel_created,
                assertion_result=assertion or "UNKNOWN",
                exception_type=exc_type,
                positive_control_passed=pos_ctrl,
                structured_evidence=struct_ev,
                latency_ms=cmd_res.latency_ms,
                is_valid_green=is_valid_green,
            )
            results.append(run_res)

            if not is_valid_green:
                fail_details = []
                if cmd_res.exit_code != 42:
                    fail_details.append(f"Exit code {cmd_res.exit_code} != 42")
                if cmd_res.sentinel_created:
                    fail_details.append("Sentinel marker was created")
                if not pos_ctrl:
                    fail_details.append("Positive control failed or missing")
                if not sig_ok:
                    fail_details.append(f"Exception '{exc_type}' does not match expected block signature {expected_signature.exception_class_names}")
                if assertion != "GREEN_SECURITY_BLOCK_VERIFIED":
                    fail_details.append(f"Assertion '{assertion}' != GREEN_SECURITY_BLOCK_VERIFIED")

                reason = f"GREEN verification failed on run {idx}/{runs_count}: {'; '.join(fail_details)}"
                return False, results, reason

        return True, results, f"Confirmed GREEN 3/3: All {runs_count} runs verified expected block signature and positive controls."
