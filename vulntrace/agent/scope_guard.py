"""
VulnTrace Scope Guard & Plan Approval Engine (Spec §4.10)
Enforces:
1. Approved plan constraints (files to touch, strategy).
2. Out-of-plan file edit rejection (blocks modification of files outside approved plan).
3. Diff budget enforcement (default <= 30 changed lines, <= 3 files).
4. Structured gate ordering: syntax parse -> plan-scope -> AST denylist -> diff budget.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class RepairPlan(BaseModel):
    """User-approved repair plan specifying allowed scope and budget."""
    files_to_touch: List[str] = Field(default_factory=list)
    strategy: str = "surgical_sink_hardening"
    diff_budget_lines: int = 30
    max_files: int = 3
    user_approved: bool = True


class ScopeGateResult(BaseModel):
    """Outcome of evaluating a patch against scope and budget constraints."""
    passed: bool
    gate_name: str
    violations: List[str] = Field(default_factory=list)
    files_touched: List[str] = Field(default_factory=list)
    total_lines_changed: int = 0
    diff_budget_lines: int = 30
    max_files: int = 3


class ScopeViolationError(ValueError):
    """Raised when an edit attempt touches files outside the approved plan."""
    pass


class ScopeGuard:
    """Enforces plan-scope boundaries and line/file budgets on synthesized patches."""

    @classmethod
    def parse_diff_metrics(cls, diff_text: str) -> Dict[str, Any]:
        """
        Extracts touched file names and counts additions/deletions from unified diff.
        """
        files_touched: List[str] = []
        additions = 0
        deletions = 0

        for line in diff_text.splitlines():
            # Match --- a/path/to/file or +++ b/path/to/file
            if line.startswith("--- a/") or line.startswith("+++ b/"):
                file_path = line[6:].strip()
                if file_path and file_path != "/dev/null" and file_path not in files_touched:
                    files_touched.append(file_path)
            elif line.startswith("+") and not line.startswith("+++"):
                additions += 1
            elif line.startswith("-") and not line.startswith("---"):
                deletions += 1

        return {
            "files_touched": files_touched,
            "additions": additions,
            "deletions": deletions,
            "total_lines": additions + deletions
        }

    @classmethod
    def evaluate_scope(
        cls,
        diff_text: str,
        approved_plan: Optional[RepairPlan] = None
    ) -> ScopeGateResult:
        """
        Evaluates a diff against plan scope and budget.
        Rejects out-of-plan files and budget overflows.
        """
        metrics = cls.parse_diff_metrics(diff_text)
        files = metrics["files_touched"]
        total_lines = metrics["total_lines"]
        violations: List[str] = []

        budget_lines = approved_plan.diff_budget_lines if approved_plan else 30
        max_files = approved_plan.max_files if approved_plan else 3

        # 1. Check max files budget
        if len(files) > max_files:
            violations.append(
                f"Patch touched {len(files)} files, exceeding budget of {max_files} files: {files}"
            )

        # 2. Check total changed lines budget
        if total_lines > budget_lines:
            violations.append(
                f"Patch modified {total_lines} lines (+{metrics['additions']}/-{metrics['deletions']}), "
                f"exceeding diff budget of {budget_lines} lines."
            )

        # 3. Check plan-scope boundaries (if plan is approved)
        if approved_plan and approved_plan.files_to_touch:
            normalized_allowed = [f.replace("\\", "/").lstrip("./") for f in approved_plan.files_to_touch]
            for f in files:
                norm_f = f.replace("\\", "/").lstrip("./")
                if not any(norm_f == allowed or norm_f.endswith("/" + allowed) for allowed in normalized_allowed):
                    violations.append(
                        f"Out-of-plan file modification: '{f}' is not in approved plan files {approved_plan.files_to_touch}."
                    )

        passed = len(violations) == 0
        return ScopeGateResult(
            passed=passed,
            gate_name="PLAN_SCOPE_GUARD",
            violations=violations,
            files_touched=files,
            total_lines_changed=total_lines,
            diff_budget_lines=budget_lines,
            max_files=max_files
        )
