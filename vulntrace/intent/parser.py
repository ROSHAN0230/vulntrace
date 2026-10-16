"""
VulnTrace Intent Parser & Requirements Classifier (M7 Phase 2 / Spec §4.4)
Parses repair intent and user requirements into a typed Spec with verifiable conditions,
scope constraints, explicit out-of-scope declarations, and defense against prompt injection.
"""

import re
from typing import Dict, Any, Optional, List, Tuple
from vulntrace.intent.spec import Spec, AcceptanceTestDefinition


class IntentParser:
    """
    Parses natural-language and structured repair requirements into canonical Spec models.
    Enforces Quality Gate 1 (rejection of vague/unverifiable requirements) and
    Quality Gate 5 (prompt injection defense).
    """

    VAGUE_INDICATORS = [
        "make it better",
        "make it secure",
        "fix bugs",
        "fix everything",
        "clean up",
        "improve code",
        "do something",
        "make better",
        "fix it",
        "make faster",
        "make secure",
    ]

    CONCRETE_TRIGGERS = [
        "cve-",
        "yaml",
        "json",
        "pickle",
        "sink",
        "preserve",
        "keep",
        "deserialization",
        "traversal",
        "tar",
        "zip",
        "extract",
        "load",
        "tags",
        "tag",
        "custom",
        "patch",
        "safe_load",
        "safeloader",
        "security",
        "vulnerability"
    ]

    HOSTILE_INJECTION_PATTERNS = [
        r"--unsafe-local",
        r"VULNTRACE_UNSAFE_LOCAL",
        r"rm\s+-rf",
        r"chmod\s+777",
        r"curl\s+",
        r"wget\s+",
        r"nc\s+-",
        r"bash\s+-i",
        r"sh\s+-i",
        r"ignore\s+(?:all\s+)?previous\s+instructions",
        r"bypass\s+isolation",
        r"execute\s+on\s+host\s+without\s+container",
        r"run\s+as\s+tier\s*0"
    ]

    @classmethod
    def sanitize_prompt(cls, text: str) -> Tuple[str, List[str]]:
        """Sanitizes text against prompt injection attempts aimed at breaking isolation."""
        sanitized = text
        detected_injections = []
        for pat in cls.HOSTILE_INJECTION_PATTERNS:
            if re.search(pat, sanitized, re.IGNORECASE):
                detected_injections.append(pat)
                sanitized = re.sub(pat, "[FILTERED_HOSTILE_INSTRUCTION]", sanitized, flags=re.IGNORECASE)
        return sanitized, detected_injections

    @classmethod
    def extract_out_of_scope(cls, text: str) -> List[str]:
        """Extracts explicit out-of-scope statements from requirements text."""
        out_of_scope = []
        patterns = [
            r"(?:out of scope|not in scope|ignore|non-goals?)\s*:\s*([^.\n]+)",
            r"(?:do not touch|leave untouched|do not modify)\s*:\s*([^.\n]+)"
        ]
        for pat in patterns:
            matches = re.finditer(pat, text, re.IGNORECASE)
            for m in matches:
                items = [item.strip() for item in m.group(1).split(",") if item.strip()]
                out_of_scope.extend(items)
        return out_of_scope

    @classmethod
    def parse(
        cls,
        requirement: str,
        target_file: Optional[str] = None,
        vulnerable_symbol: Optional[str] = None
    ) -> Spec:
        """Parses natural-language requirement into a typed Spec object."""
        raw_text = requirement.strip()
        sanitized_text, injections = cls.sanitize_prompt(raw_text)
        lowered = sanitized_text.lower()

        # Check for vague requirements lacking concrete conditions
        is_vague = any(ind in lowered for ind in cls.VAGUE_INDICATORS) or len(raw_text) < 15
        has_concrete = any(trig in lowered for trig in cls.CONCRETE_TRIGGERS)

        if is_vague and not has_concrete:
            unverifiable_msg = (
                "UNVERIFIABLE: Requirement lacks concrete verifiable conditions or measurable acceptance tests. "
                "Please specify exact sinks, diff budgets, or preservation constraints."
            )
            return Spec(
                must_fix="Unspecified target sink or CVE",
                must_preserve=[],
                constraints=["diff_budget <= 30 lines", "max_files <= 3"],
                out_of_scope=cls.extract_out_of_scope(raw_text),
                acceptance_tests=[],
                is_verifiable=False,
                warning=unverifiable_msg,
                unverifiable_reason=unverifiable_msg,
                target_file=target_file,
                vulnerable_symbol=vulnerable_symbol
            )

        # 1. Identify Target Defect / must_fix
        cve_match = re.search(r"CVE-\d{4}-\d+", sanitized_text, re.IGNORECASE)
        cve_id = cve_match.group(0).upper() if cve_match else None

        must_fix = cve_id or "Surgical sink vulnerability"
        is_deserialization = any(k in lowered for k in ["deserialization", "yaml", "pickle", "json", "load"])
        is_path_traversal = any(k in lowered for k in ["traversal", "tar", "zip", "extract", "archive", "directory escape"])

        if is_deserialization:
            if cve_id:
                must_fix += " (arbitrary YAML/object deserialization via unsafe loader)"
            else:
                must_fix = "Unsafe YAML/object deserialization via unsafe loader"
        elif is_path_traversal:
            if cve_id:
                must_fix += " (arbitrary file write via path traversal in archive extraction)"
            else:
                must_fix = "Arbitrary file write via path traversal in archive extraction"

        # 2. Identify Preserved Behaviors / must_preserve
        must_preserve = []
        has_custom_tags = any(k in lowered for k in ["custom tag", "custom tags", "custom_tag", "tag extension", "!env_var", "!custom"])
        has_custom_loader = any(k in lowered for k in ["custom loader", "loader extension", "custom class"])

        if has_custom_tags or (has_custom_loader and "tag" in lowered):
            must_preserve.append("Custom application tags and loader extensions (!custom_tag)")
        elif has_custom_loader:
            must_preserve.append("Custom loader/tag extensions")

        if "regression" in lowered or "test" in lowered or "suite" in lowered:
            must_preserve.append("Existing unit & regression test suite")

        if "api" in lowered or "signature" in lowered or "backward" in lowered:
            must_preserve.append("Backward-compatible public API signatures")

        if not must_preserve:
            must_preserve.append("Existing repository regression test suite")

        # 3. Identify Scope Constraints
        constraints = [
            "diff_budget <= 30 lines",
            "max_files <= 3 files",
            "forbid arbitrary object instantiation"
        ]

        # 4. Out of Scope
        out_of_scope = cls.extract_out_of_scope(raw_text)

        # 5. Synthesize Acceptance Test Definitions
        acceptance_tests: List[AcceptanceTestDefinition] = []

        if is_deserialization:
            acceptance_tests.append(
                AcceptanceTestDefinition(
                    name="test_cve_exploit_probe_blocked",
                    status="REQUIRED",
                    oracle="security_probe_rejection",
                    target_symbol=vulnerable_symbol or "parse_app_config",
                    description="Rejects arbitrary object instantiation (e.g. !!python/object/apply)"
                )
            )
            if has_custom_tags:
                acceptance_tests.append(
                    AcceptanceTestDefinition(
                        name="test_preserve_custom_tags",
                        status="REQUIRED",
                        oracle="custom_tag_preservation",
                        target_symbol=vulnerable_symbol or "parse_app_config",
                        description="Preserves custom tags (!custom_tag) and loads expected domain values"
                    )
                )
        elif is_path_traversal:
            acceptance_tests.append(
                AcceptanceTestDefinition(
                    name="test_path_traversal_archive_rejection",
                    status="REQUIRED",
                    oracle="security_probe_rejection",
                    target_symbol=vulnerable_symbol or "extract_archive",
                    description="Rejects archive members with directory traversal components"
                )
            )
            acceptance_tests.append(
                AcceptanceTestDefinition(
                    name="test_benign_archive_extraction_preserved",
                    status="REQUIRED",
                    oracle="benign_extraction_preservation",
                    target_symbol=vulnerable_symbol or "extract_archive",
                    description="Preserves clean extraction of benign archives within destination"
                )
            )
        else:
            acceptance_tests.append(
                AcceptanceTestDefinition(
                    name="test_cve_exploit_probe_blocked",
                    status="REQUIRED",
                    oracle="security_probe_rejection",
                    target_symbol=vulnerable_symbol,
                    description="Rejects adversarial exploit probe"
                )
            )

        # Baseline regression preservation is always required
        acceptance_tests.append(
            AcceptanceTestDefinition(
                name="test_existing_regressions_pass",
                status="REQUIRED",
                oracle="pytest_baseline_invariant",
                target_symbol=vulnerable_symbol,
                description="Existing repository regression tests pass"
            )
        )

        warning = None
        if injections:
            warning = f"Notice: Neutralized hostile prompt instructions targeting isolation: {', '.join(injections)}"

        return Spec(
            must_fix=must_fix,
            must_preserve=must_preserve,
            constraints=constraints,
            out_of_scope=out_of_scope,
            acceptance_tests=acceptance_tests,
            is_verifiable=True,
            warning=warning,
            unverifiable_reason=None,
            target_file=target_file,
            vulnerable_symbol=vulnerable_symbol
        )


def parse_intent(
    requirement: str,
    target_file: Optional[str] = None,
    vulnerable_symbol: Optional[str] = None
) -> Spec:
    """Convenience functional interface returning typed Spec."""
    return IntentParser.parse(requirement, target_file=target_file, vulnerable_symbol=vulnerable_symbol)


def parse_and_validate_intent(
    requirement: str,
    target_file: Optional[str] = None,
    vulnerable_symbol: Optional[str] = None
) -> Dict[str, Any]:
    """Legacy dictionary interface for REST API endpoints and database event records."""
    spec = parse_intent(requirement, target_file=target_file, vulnerable_symbol=vulnerable_symbol)
    return spec.to_api_dict()
