"""
VulnTrace Anti-Gaming Verification Engine (Spec §4.4)

Implements rigorous checks required before any GREEN_STATE_VERIFIED verdict:
1. Patch denylist enforcement (AST analysis for banned exits, broad excepts, deletions)
2. Workspace and test harness SHA-256 integrity auditing (anti-tampering)
3. Structured harness verification (reject bare exit 42 and forged signals)
4. Multi-run deterministic replication (3/3 RED, 3/3 GREEN)
"""

import ast
import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set


@dataclass
class PatchDenylistResult:
    allowed: bool
    violations: List[str] = field(default_factory=list)
    checked_rules: List[str] = field(default_factory=list)


class PatchDenylistValidator:
    """
    AST-level inspector enforcing patch hygiene and rejecting evasion attempts.
    Denylist rules:
    - No new sys.exit, os._exit, os.kill, exit(), quit()
    - No new broad except: pass or except Exception: pass
    - No deletion of the target function
    - No empty or whitespace-only diffs
    - No modifications to files outside the declared target file set
    """

    PROHIBITED_CALLS = {
        ("sys", "exit"),
        ("os", "_exit"),
        ("os", "kill"),
    }
    PROHIBITED_BUILTINS = {"exit", "quit"}

    @classmethod
    def validate_patch(
        cls,
        orig_code: str,
        patched_code: str,
        target_function_name: Optional[str] = None,
        touched_files: Optional[List[str]] = None,
        allowed_target_file: Optional[str] = None,
    ) -> PatchDenylistResult:
        violations: List[str] = []
        checked_rules: List[str] = []

        # Rule 1: Non-empty diff check
        checked_rules.append("non_empty_diff")
        if not patched_code or patched_code.strip() == orig_code.strip():
            violations.append("Denylist violation: Empty or whitespace-only patch diff.")
            return PatchDenylistResult(allowed=False, violations=violations, checked_rules=checked_rules)

        # Rule 2: Allowed file scope check
        checked_rules.append("file_scope_enforcement")
        if touched_files and allowed_target_file:
            for tf in touched_files:
                tf_norm = tf.replace("\\", "/").lstrip("/")
                allowed_norm = allowed_target_file.replace("\\", "/").lstrip("/")
                if tf_norm != allowed_norm:
                    # Check if touched file is a test or harness or config
                    if any(part in tf_norm for part in ["tests/", "test_", "harness", "_eval_", "pyproject", "setup.py", "requirements"]):
                        violations.append(f"Denylist violation: Patch modified restricted file '{tf}' outside target file.")
                    else:
                        violations.append(f"Denylist violation: Patch touched file '{tf}' outside allowed target '{allowed_target_file}'.")

        # Parse ASTs
        checked_rules.append("ast_syntax_validity")
        try:
            orig_tree = ast.parse(orig_code)
        except SyntaxError:
            orig_tree = None

        try:
            patched_tree = ast.parse(patched_code)
        except SyntaxError as e:
            violations.append(f"Denylist violation: Patched code has syntax errors: {e}")
            return PatchDenylistResult(allowed=False, violations=violations, checked_rules=checked_rules)

        # Rule 3: Target function preservation
        checked_rules.append("target_function_preservation")
        if target_function_name:
            orig_has_func = cls._has_function_or_method(orig_tree, target_function_name) if orig_tree else True
            patched_has_func = cls._has_function_or_method(patched_tree, target_function_name)
            if orig_has_func and not patched_has_func:
                violations.append(f"Denylist violation: Target function '{target_function_name}' was deleted.")

        # Rule 4: Prohibited exit calls (sys.exit, os._exit, os.kill, exit())
        checked_rules.append("no_prohibited_exit_calls")
        orig_calls = cls._find_prohibited_calls(orig_tree) if orig_tree else set()
        patched_calls = cls._find_prohibited_calls(patched_tree)
        new_calls = patched_calls - orig_calls
        for call_desc in new_calls:
            violations.append(f"Denylist violation: Injected prohibited exit call '{call_desc}'.")

        # Rule 5: Broad try/except pass suppression
        checked_rules.append("no_broad_except_pass")
        orig_broad = cls._count_broad_except_pass(orig_tree) if orig_tree else 0
        patched_broad = cls._count_broad_except_pass(patched_tree)
        if patched_broad > orig_broad:
            violations.append("Denylist violation: Injected broad try/except: pass error suppression.")

        allowed = len(violations) == 0
        return PatchDenylistResult(allowed=allowed, violations=violations, checked_rules=checked_rules)

    @classmethod
    def _has_function_or_method(cls, tree: ast.AST, name: str) -> bool:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == name:
                    return True
        return False

    @classmethod
    def _find_prohibited_calls(cls, tree: ast.AST) -> Set[str]:
        prohibited: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Attribute call e.g. sys.exit(42), os._exit(1)
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    pair = (node.func.value.id, node.func.attr)
                    if pair in cls.PROHIBITED_CALLS:
                        arg_str = ""
                        if node.args and isinstance(node.args[0], ast.Constant):
                            arg_str = str(node.args[0].value)
                        prohibited.add(f"{pair[0]}.{pair[1]}({arg_str})")
                # Bare name call e.g. exit(), quit()
                elif isinstance(node.func, ast.Name) and node.func.id in cls.PROHIBITED_BUILTINS:
                    prohibited.add(f"{node.func.id}()")
        return prohibited

    @classmethod
    def _count_broad_except_pass(cls, tree: ast.AST) -> int:
        count = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                for handler in node.handlers:
                    is_broad = False
                    if handler.type is None:
                        is_broad = True
                    elif isinstance(handler.type, ast.Name) and handler.type.id in ["Exception", "BaseException"]:
                        is_broad = True

                    if is_broad:
                        # Check if body is trivial pass / return None / return {}
                        if len(handler.body) == 1:
                            stmt = handler.body[0]
                            if isinstance(stmt, ast.Pass):
                                count += 1
                            elif isinstance(stmt, ast.Return):
                                if stmt.value is None or (isinstance(stmt.value, ast.Constant) and stmt.value.value is None):
                                    count += 1
                                elif isinstance(stmt.value, ast.Dict) and len(stmt.value.keys) == 0:
                                    count += 1
        return count


class IntegrityAuditor:
    """
    Computes and audits SHA-256 checksums across repository assets.
    Proves that harness files, test files, and out-of-scope files were not altered.
    """

    EXCLUDED_PATTERNS = {
        "__pycache__",
        ".pytest_cache",
        ".git",
        ".marker",
        ".pyc",
    }

    @classmethod
    def _is_excluded(cls, path: Path) -> bool:
        p_str = path.as_posix()
        return any(ex in p_str for ex in cls.EXCLUDED_PATTERNS)

    @classmethod
    def snapshot_hashes(cls, directory: Path, target_rel_file: Optional[str] = None) -> Dict[str, str]:
        """Snapshots SHA-256 hashes of all relevant files in directory except target_rel_file."""
        hashes: Dict[str, str] = {}
        target_norm = target_rel_file.replace("\\", "/").lstrip("/") if target_rel_file else None

        for item in directory.rglob("*"):
            if item.is_file() and not cls._is_excluded(item):
                rel_str = item.relative_to(directory).as_posix()
                if target_norm and rel_str == target_norm:
                    continue  # Target file is permitted to change
                try:
                    content = item.read_bytes()
                    hashes[rel_str] = hashlib.sha256(content).hexdigest()
                except (OSError, PermissionError):
                    pass
        return hashes

    @classmethod
    def verify_integrity(
        cls,
        pre_hashes: Dict[str, str],
        current_dir: Path,
        target_rel_file: Optional[str] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Compares pre-patch snapshot hashes with current directory state.
        Returns (True, []) if all protected files are intact, otherwise (False, [violations]).
        """
        violations: List[str] = []
        target_norm = target_rel_file.replace("\\", "/").lstrip("/") if target_rel_file else None

        for rel_path, expected_hash in pre_hashes.items():
            if target_norm and rel_path == target_norm:
                continue
            curr_file = current_dir / rel_path
            if not curr_file.exists():
                violations.append(f"Integrity violation: Protected file was deleted: '{rel_path}'")
                continue
            try:
                actual_hash = hashlib.sha256(curr_file.read_bytes()).hexdigest()
                if actual_hash != expected_hash:
                    violations.append(f"Integrity violation: Protected file was modified: '{rel_path}'")
            except Exception as e:
                violations.append(f"Integrity violation: Error reading '{rel_path}': {e}")

        return len(violations) == 0, violations
