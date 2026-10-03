"""
VulnTrace Behavioral Preservation Contract & Oracle (P0.5.4)
Replaces naive 'is not None' checks with a multi-input behavioral contract.

Validates that remediation patches preserve authentic application semantics:
1. Result type matching
2. Required structural invariants (nested keys, collections, types)
3. Non-empty data containers (rejects {}, "", [], None)
4. Domain-specific invariant verification across multiple distinct benign inputs
5. Prevention of dummy stubs or split-brain evasion
"""

import json
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field


@dataclass
class BenignInputContract:
    case_id: str
    description: str
    raw_input: str
    required_type_name: str
    required_keys: List[str] = field(default_factory=list)
    nested_invariants: Dict[str, Any] = field(default_factory=dict)
    custom_domain_tag: Optional[str] = None


class BehaviorOracle:
    """
    Generic Behavioral Preservation Oracle.
    Generates domain-appropriate multi-input contracts for verification harnesses
    and audits pre-patch vs post-patch behavioral fidelity.
    """

    @classmethod
    def get_yaml_contracts() -> List[BenignInputContract]:
        """Returns multi-input contracts for YAML deserialization services."""
        return [
            BenignInputContract(
                case_id="flat_service_mapping",
                description="Flat mapping with scalar string and integer configuration",
                raw_input="service: auth\nport: 9000",
                required_type_name="dict",
                required_keys=["service", "port"],
                nested_invariants={"service": "auth", "port": 9000}
            ),
            BenignInputContract(
                case_id="nested_hierarchy_mapping",
                description="Hierarchical mapping with nested dictionary, integer, and boolean",
                raw_input="service: core-api\nnested:\n  workers: 4\n  enabled: true",
                required_type_name="dict",
                required_keys=["service", "nested"],
                nested_invariants={"nested.workers": 4, "nested.enabled": True}
            ),
            BenignInputContract(
                case_id="collection_and_types_mapping",
                description="Complex mapping containing lists, ports, and multi-endpoint data",
                raw_input="database:\n  host: localhost\n  port: 5432\n  endpoints:\n    - primary\n    - replica",
                required_type_name="dict",
                required_keys=["database"],
                nested_invariants={"database.port": 5432, "database.endpoints": ["primary", "replica"]}
            )
        ]

    @classmethod
    def get_pickle_contracts() -> List[BenignInputContract]:
        """Returns multi-input contracts for pickle deserialization services."""
        return [
            BenignInputContract(
                case_id="pickle_flat_dict",
                description="Pickled basic configuration dictionary",
                raw_input='__import__("pickle").dumps({"service": "auth", "port": 9000})',
                required_type_name="dict",
                required_keys=["service", "port"]
            ),
            BenignInputContract(
                case_id="pickle_nested_structure",
                description="Pickled nested structure with collections",
                raw_input='__import__("pickle").dumps({"service": "core", "nested": {"workers": 4}})',
                required_type_name="dict",
                required_keys=["service", "nested"]
            )
        ]

    @classmethod
    def get_generic_contracts() -> List[BenignInputContract]:
        """Generic fallback contracts for scalar and command services."""
        return [
            BenignInputContract(
                case_id="scalar_input_alpha",
                description="Baseline benign scalar input",
                raw_input='"test_benign_input_alpha"',
                required_type_name="str"
            ),
            BenignInputContract(
                case_id="scalar_input_beta",
                description="Alternative benign scalar input",
                raw_input='"test_benign_input_beta"',
                required_type_name="str"
            )
        ]

    @classmethod
    def evaluate_output(
        cls,
        contract: BenignInputContract,
        output: Any
    ) -> Tuple[bool, str]:
        """
        Statically evaluates whether a function output satisfies a given contract.
        Adversarial evaluation checks:
        - Must not be None
        - Must match required type
        - Must not be empty container ({}, "", [])
        - Must contain all required keys
        - Must satisfy nested structural invariants
        """
        if output is None:
            return False, f"Contract '{contract.case_id}' failed: Output cannot be None"

        actual_type = type(output).__name__
        if actual_type != contract.required_type_name and contract.required_type_name not in [base.__name__ for base in type(output).__mro__]:
            return False, f"Contract '{contract.case_id}' failed: Type mismatch. Expected {contract.required_type_name}, got {actual_type}"

        # Reject empty dummy containers
        if isinstance(output, (dict, list, str, set)) and len(output) == 0:
            return False, f"Contract '{contract.case_id}' failed: Returned empty dummy container ({actual_type} of length 0)"

        # Check dictionary-specific invariants
        if isinstance(output, dict):
            for req_key in contract.required_keys:
                if req_key not in output:
                    return False, f"Contract '{contract.case_id}' failed: Missing required top-level key '{req_key}'"
                if output[req_key] is None:
                    return False, f"Contract '{contract.case_id}' failed: Key '{req_key}' has None value; expected non-null data"

            # Check nested dotted paths if specified
            for dotpath, expected_val in contract.nested_invariants.items():
                parts = dotpath.split(".")
                curr = output
                for p in parts:
                    if not isinstance(curr, dict) or p not in curr:
                        return False, f"Contract '{contract.case_id}' failed: Invariant path '{dotpath}' not found in output"
                    curr = curr[p]
                if curr != expected_val:
                    return False, f"Contract '{contract.case_id}' failed: Invariant '{dotpath}' value mismatch. Expected {expected_val!r}, got {curr!r}"

        return True, f"Contract '{contract.case_id}' verified successfully."
