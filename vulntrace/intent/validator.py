"""
VulnTrace Intent Quality Gates & Execution Boundary Validator (M7 Phase 2 / Spec §4.4)
Enforces strict quality gates on synthesized test suites:
- Gate 1: Requirement verifiability
- Gate 2: Non-trivial AST assertions (rejects assert True, assert 1 == 1, pass)
- Gate 3: Pre-execution syntax validation
- Gate 4: Target symbol verification
- Gate 5: Untrusted text & hostile injection defense
- Gate 6: Tier 1 container execution boundary enforcement
"""

import ast
from pathlib import Path
from typing import Tuple, List, Optional, Union

from vulntrace.intent.spec import Spec
from vulntrace.core.backend import ExecutionBackend, IsolationTier, is_curated_fixture
from vulntrace.core.factory import BackendFactory


class QualityGateFailure(Exception):
    """Raised when synthesized test code or repair specifications fail quality gates."""
    pass


class IntentQualityValidator:
    """
    Evaluates repair specifications and synthesized pytest test code against
    anti-gaming and isolation quality gates.
    """

    DANGEROUS_CALL_NAMES = {
        "system",
        "popen",
        "rmdir",
        "remove",
        "unlink",
        "eval",
        "exec"
    }

    @classmethod
    def validate_spec(cls, spec: Spec) -> Tuple[bool, List[str]]:
        """Quality Gate 1: Verifies that the spec is not marked UNVERIFIABLE."""
        errors = []
        if not spec.is_verifiable:
            reason = spec.unverifiable_reason or spec.warning or "UNVERIFIABLE: Requirement lacks concrete conditions."
            errors.append(reason)
            return False, errors
        return True, []

    @classmethod
    def _is_trivial_assert(cls, node: ast.Assert) -> Tuple[bool, Optional[str]]:
        """Detects whether an assert statement is trivial (assert True, assert 1 == 1, etc.)."""
        # assert True / assert False
        if isinstance(node.test, ast.Constant):
            if node.test.value is True:
                return True, "assert True"
            return True, f"constant assert {node.test.value}"

        # assert 1 == 1, assert "a" == "a"
        if isinstance(node.test, ast.Compare):
            if (
                isinstance(node.test.left, ast.Constant)
                and len(node.test.ops) == 1
                and isinstance(node.test.ops[0], ast.Eq)
                and len(node.test.comparators) == 1
                and isinstance(node.test.comparators[0], ast.Constant)
            ):
                if node.test.left.value == node.test.comparators[0].value:
                    return True, f"assert {node.test.left.value} == {node.test.comparators[0].value}"

        # assert not False
        if isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not):
            if isinstance(node.test.operand, ast.Constant) and node.test.operand.value is False:
                return True, "assert not False"

        return False, None

    @classmethod
    def validate_test_code(
        cls,
        code: str,
        target_symbol: Optional[str] = None
    ) -> Tuple[bool, List[str]]:
        """
        Validates synthesized test code against Quality Gates 2, 3, 4, and 5.
        """
        errors = []

        # Gate 3: Syntax Compilation
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return False, [f"Syntax error in synthesized test: {e}"]
        except Exception as e:
            return False, [f"Failed to parse test code AST: {e}"]

        # Gate 5: Dangerous Call & Shell Injection Defense
        for node in ast.walk(tree):
            # Check for shell=True in calls
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        errors.append("Forbidden dangerous operation: shell=True execution detected in test code.")
                # Check for os.system or direct system calls
                if isinstance(node.func, ast.Attribute) and node.func.attr in cls.DANGEROUS_CALL_NAMES:
                    if isinstance(node.func.value, ast.Name) and node.func.value.id in ("os", "subprocess"):
                        errors.append(f"Forbidden dangerous operation: {node.func.value.id}.{node.func.attr} detected.")
                elif isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                    errors.append(f"Forbidden dangerous operation: dynamic {node.func.id}() detected in test code.")

        # Gate 4: Target Symbol Verification
        if target_symbol:
            symbol_found = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id == target_symbol:
                    symbol_found = True
                    break
                if isinstance(node, ast.Attribute) and node.attr == target_symbol:
                    symbol_found = True
                    break
            if not symbol_found:
                errors.append(f"Missing target symbol: Synthesized test code does not exercise target symbol '{target_symbol}'.")

        # Gate 2: Trivial & Dummy Assertion Detection
        test_functions = [
            n for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")
        ]

        if not test_functions:
            errors.append("Test code contains no test functions starting with 'test_'.")

        for fn in test_functions:
            # Check for empty body / pass only
            body_statements = [
                stmt for stmt in fn.body
                if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str))
            ]

            if not body_statements or all(isinstance(stmt, ast.Pass) for stmt in body_statements):
                errors.append(f"Function '{fn.name}' has empty body or pass with no assertions.")
                continue

            # Check assertions and pytest.raises in function
            assert_nodes: List[ast.Assert] = []
            raises_nodes: List[ast.With] = []

            for n in ast.walk(fn):
                if isinstance(n, ast.Assert):
                    assert_nodes.append(n)
                elif isinstance(n, ast.With):
                    for item in n.items:
                        if isinstance(item.context_expr, ast.Call):
                            call = item.context_expr
                            if (
                                (isinstance(call.func, ast.Attribute) and call.func.attr == "raises") or
                                (isinstance(call.func, ast.Name) and call.func.id == "raises")
                            ):
                                raises_nodes.append(n)

            if not assert_nodes and not raises_nodes:
                errors.append(f"Function '{fn.name}' contains no assertions or exception checks.")
                continue

            # Inspect assert nodes for trivial statements
            trivial_count = 0
            for a_node in assert_nodes:
                is_trivial, trivial_expr = cls._is_trivial_assert(a_node)
                if is_trivial:
                    trivial_count += 1
                    errors.append(f"Function '{fn.name}' contains trivial assertion '{trivial_expr}'.")

            if trivial_count == len(assert_nodes) and not raises_nodes:
                errors.append(f"Function '{fn.name}' contains only trivial assertions.")

        is_valid = len(errors) == 0
        return is_valid, errors

    @classmethod
    def resolve_execution_backend(
        cls,
        target_repo: Union[str, Path]
    ) -> ExecutionBackend:
        """
        Quality Gate 6: Resolves the appropriate execution backend adhering to
        strict zero-trust isolation boundaries.
        """
        repo_path = Path(target_repo)
        return BackendFactory.resolve_best_available_backend(target_repo=repo_path)

    @classmethod
    def route_test_execution(
        cls,
        target_repo: Union[str, Path],
        backend: Optional[ExecutionBackend] = None
    ) -> ExecutionBackend:
        """
        Quality Gate 6: Enforces that non-curated / generated test execution
        strictly routes to Tier 1 and refuses Tier 0.
        """
        repo_path = Path(target_repo)
        is_curated = is_curated_fixture(repo_path)

        if backend is None:
            backend = cls.resolve_execution_backend(repo_path)

        if backend.capabilities.tier == IsolationTier.LOCAL_SUBPROCESS_FALLBACK and not is_curated:
            raise PermissionError(
                f"Tier 0 (LocalSubprocess) refused non-curated repository '{repo_path.name}'. "
                "Synthesized tests on non-curated workspaces require Isolation Tier 1 (OCI Container). "
                "Unsafe-local overrides are prohibited under strict zero-trust policy."
            )

        return backend
