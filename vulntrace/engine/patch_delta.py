"""
Patch Delta Metadata Analyzer for VulnTrace
Extracts structured machine-readable metrics from unified diffs:
changed files, changed functions, changed lines, diff size, affected tests,
and minimality assessments.
"""

import re
from typing import Dict, Any, List
from vulntrace.models import PatchDeltaMetadata

class PatchDeltaAnalyzer:
    @classmethod
    def analyze_diff(cls, diff_text: str, target_function: str = "", tests_count: int = 0, reason: str = "") -> PatchDeltaMetadata:
        """Parses unified diff and produces structured PatchDeltaMetadata."""
        if not diff_text or not diff_text.strip():
            return PatchDeltaMetadata(
                changed_files=[],
                changed_functions=[],
                additions_count=0,
                deletions_count=0,
                total_lines_changed=0,
                diff_bytes=0,
                is_minimal=True,
                minimality_criterion="Empty diff",
                tests_affected_count=0,
                reason_for_change=reason or "No changes"
            )

        changed_files = set()
        changed_functions = set()
        additions = 0
        deletions = 0

        for line in diff_text.splitlines():
            if line.startswith("--- a/") or line.startswith("+++ b/"):
                fpath = line[6:].strip()
                if fpath:
                    changed_files.add(fpath)
            elif line.startswith("@@"):
                # e.g., @@ -13,8 +13,8 @@ def parse_cloud_descriptor(...)
                match = re.search(r"@@\s*(?:def\s+)?([a-zA-Z0-9_]+)", line)
                if match:
                    changed_functions.add(match.group(1))
                elif target_function:
                    changed_functions.add(target_function)
            elif line.startswith("+") and not line.startswith("+++"):
                additions += 1
            elif line.startswith("-") and not line.startswith("---"):
                deletions += 1

        if target_function and not changed_functions:
            changed_functions.add(target_function)

        total_lines = additions + deletions
        diff_bytes = len(diff_text.encode("utf-8"))
        
        # Minimality definition: <= 10 lines changed, exactly 1 file modified, scoped to target sink
        is_minimal = (len(changed_files) <= 1) and (total_lines <= 10)
        criterion = (
            f"Minimal: {total_lines} lines across {len(changed_files)} file(s) (threshold: <= 10 lines, 1 file)"
            if is_minimal
            else f"Broad patch: {total_lines} lines across {len(changed_files)} file(s)"
        )

        return PatchDeltaMetadata(
            changed_files=sorted(list(changed_files)),
            changed_functions=sorted(list(changed_functions)),
            additions_count=additions,
            deletions_count=deletions,
            total_lines_changed=total_lines,
            diff_bytes=diff_bytes,
            is_minimal=is_minimal,
            minimality_criterion=criterion,
            tests_affected_count=tests_count,
            reason_for_change=reason or "Surgical replacement of unsafe deserialization sink"
        )
