"""
Acceptance Tests for VulnTrace Scope Guard & Plan Approval (Spec §4.10, AC2).
Covers:
1. Within-plan surgical patch approval.
2. Out-of-plan file edit rejection (SCOPE_VIOLATION_BLOCKED).
3. Diff line budget overflow rejection (default <= 30 lines).
4. File count budget overflow rejection (default <= 3 files).
5. Unified diff metric parsing accuracy.
"""

from vulntrace.agent.scope_guard import ScopeGuard, RepairPlan


SAMPLE_SAFE_DIFF = """--- a/vulntrace/engine.py
+++ b/vulntrace/engine.py
@@ -10,3 +10,4 @@
 def handle_request(req):
+    # Sanitized input
+    req = sanitize(req)
     return process(req)
"""

SAMPLE_MULTI_FILE_DIFF = """--- a/src/core.py
+++ b/src/core.py
@@ -5,2 +5,3 @@
+x = 1
--- a/src/utils.py
+++ b/src/utils.py
@@ -1,2 +1,3 @@
+y = 2
--- a/src/config.py
+++ b/src/config.py
@@ -2,1 +2,2 @@
+z = 3
--- a/src/extra.py
+++ b/src/extra.py
@@ -1,1 +1,2 @@
+w = 4
"""


def test_diff_metrics_parsing():
    """Proves diff parser extracts accurate counts of files, additions, and deletions."""
    metrics = ScopeGuard.parse_diff_metrics(SAMPLE_SAFE_DIFF)
    assert metrics["files_touched"] == ["vulntrace/engine.py"]
    assert metrics["additions"] == 2
    assert metrics["deletions"] == 0
    assert metrics["total_lines"] == 2


def test_within_plan_patch_approved():
    """Proves patch modifying only approved files within line/file budget passes."""
    plan = RepairPlan(
        files_to_touch=["vulntrace/engine.py"],
        diff_budget_lines=30,
        max_files=3,
        user_approved=True
    )
    result = ScopeGuard.evaluate_scope(SAMPLE_SAFE_DIFF, plan)
    assert result.passed is True
    assert len(result.violations) == 0
    assert result.files_touched == ["vulntrace/engine.py"]
    assert result.total_lines_changed == 2


def test_out_of_plan_file_blocked():
    """Proves modifications targeting files not listed in approved plan are rejected."""
    plan = RepairPlan(
        files_to_touch=["vulntrace/unrelated.py"],
        diff_budget_lines=30,
        max_files=3,
        user_approved=True
    )
    result = ScopeGuard.evaluate_scope(SAMPLE_SAFE_DIFF, plan)
    assert result.passed is False
    assert any("Out-of-plan file modification" in v for v in result.violations)
    assert "vulntrace/engine.py" in result.violations[0]


def test_diff_line_budget_overflow_blocked():
    """Proves patches exceeding the approved diff line budget are rejected."""
    # Generate large diff with 40 additions
    large_diff_lines = [
        "--- a/vulntrace/engine.py",
        "+++ b/vulntrace/engine.py",
        "@@ -1,1 +1,41 @@",
    ] + [f"+    line_{i} = True" for i in range(40)]
    large_diff = "\n".join(large_diff_lines) + "\n"

    plan = RepairPlan(
        files_to_touch=["vulntrace/engine.py"],
        diff_budget_lines=30,
        max_files=3,
        user_approved=True
    )
    result = ScopeGuard.evaluate_scope(large_diff, plan)
    assert result.passed is False
    assert any("exceeding diff budget of 30 lines" in v for v in result.violations)
    assert result.total_lines_changed == 40


def test_max_files_budget_overflow_blocked():
    """Proves patches modifying more than max_files are rejected."""
    plan = RepairPlan(
        files_to_touch=["src/core.py", "src/utils.py", "src/config.py", "src/extra.py"],
        diff_budget_lines=100,
        max_files=2,  # Budget is 2, but diff touches 4
        user_approved=True
    )
    result = ScopeGuard.evaluate_scope(SAMPLE_MULTI_FILE_DIFF, plan)
    assert result.passed is False
    assert any("exceeding budget of 2 files" in v for v in result.violations)
    assert len(result.files_touched) == 4
