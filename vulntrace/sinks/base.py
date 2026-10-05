"""
VulnTrace Sink-Class Oracle Library — Base Definitions (Spec §4.3)

Defines the contract for reviewed, domain-specific sink oracles.
The LLM never writes the oracle. Each oracle is deterministic and verified.

Safety Policy:
Behavioral probes only. No shells, no network callbacks, no destructive actions,
and no data exfiltration.
"""

from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple, Optional


class SinkClass(str, Enum):
    DESERIALIZATION = "deserialization"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    CODE_EVAL = "code_eval"
    GENERIC = "generic"


@dataclass(frozen=True)
class BenignProbe:
    """
    Controlled, non-destructive behavioral test probe.
    Creates a canary file inside the workspace upon execution to prove reachable execution.
    """
    payload_expr: str
    canary_filename: str
    description: str
    is_destructive: bool = False
    requires_network: bool = False
    requires_shell: bool = False


@dataclass(frozen=True)
class ExpectedBlockSignature:
    """
    Specific exception class and message family that signifies an authentic security block.
    A generic crash or arbitrary exception is never treated as a valid security block.
    """
    exception_class_names: Tuple[str, ...]
    exception_module_names: Tuple[str, ...] = ()
    message_keywords: Tuple[str, ...] = ()

    def matches(self, exception_type_name: str, exception_message: str = "") -> bool:
        """Evaluates whether an observed exception conforms to the expected block signature."""
        if not exception_type_name:
            return False
        # Match class name directly or as suffix
        name_matches = any(
            exception_type_name == expected or exception_type_name.endswith(f".{expected}")
            for expected in self.exception_class_names
        )
        if not name_matches:
            return False
        if self.message_keywords:
            msg_lower = (exception_message or "").lower()
            return any(k.lower() in msg_lower for k in self.message_keywords)
        return True


@dataclass(frozen=True)
class SafePattern:
    """Defines what an authentic, correct fix looks like for this sink class."""
    pattern_id: str
    description: str
    example_snippet: str
    ast_node_types: Tuple[str, ...] = ()


@dataclass
class BenignContract:
    """
    Multi-input positive control contract.
    Proves that legitimate application inputs continue to be parsed correctly.
    """
    case_id: str
    description: str
    raw_input: str
    required_type_name: str
    required_keys: List[str] = field(default_factory=list)
    nested_invariants: Dict[str, Any] = field(default_factory=dict)
    custom_domain_tag: Optional[str] = None


class BaseSinkOracle(ABC):
    """Abstract interface for reviewed sink-class oracles."""

    @property
    @abstractmethod
    def sink_class(self) -> SinkClass:
        """The category of vulnerability sink."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Descriptive name of this sink oracle."""
        pass

    @abstractmethod
    def matches(self, symbol_or_call: str) -> bool:
        """Returns True if this oracle handles the given AST symbol or call name."""
        pass

    @abstractmethod
    def get_probe(self, canary_filename: str) -> BenignProbe:
        """Generates a non-destructive behavioral probe creating canary_filename upon execution."""
        pass

    @abstractmethod
    def get_expected_block_signature(self) -> ExpectedBlockSignature:
        """Returns the specific exception classes and message family that signify 'blocked'."""
        pass

    @abstractmethod
    def get_safe_patterns(self) -> List[SafePattern]:
        """Returns documented safe remediation patterns for this sink class."""
        pass

    @abstractmethod
    def get_benign_contracts(self) -> List[BenignContract]:
        """Returns the suite of multi-input positive control contracts."""
        pass

    @abstractmethod
    def get_harness_import_block(self) -> str:
        """Returns safe Python import code for defensive exception handling in the verification harness."""
        pass

    def evaluate_benign_output(self, contract: BenignContract, output: Any) -> Tuple[bool, str]:
        """
        Evaluates whether an observed function output satisfies the benign input contract.
        Rejects None, empty containers, missing keys, and structural mismatches.
        """
        if output is None:
            return False, f"Contract '{contract.case_id}' failed: Output cannot be None"

        actual_type = type(output).__name__
        if actual_type != contract.required_type_name and contract.required_type_name not in [b.__name__ for b in type(output).__mro__]:
            return False, f"Contract '{contract.case_id}' failed: Type mismatch. Expected {contract.required_type_name}, got {actual_type}"

        # Reject empty dummy containers
        if isinstance(output, (dict, list, str, set)) and len(output) == 0:
            return False, f"Contract '{contract.case_id}' failed: Returned empty dummy container ({actual_type} of length 0)"

        if isinstance(output, dict):
            for req_key in contract.required_keys:
                if req_key not in output:
                    return False, f"Contract '{contract.case_id}' failed: Missing required top-level key '{req_key}'"
                if output[req_key] is None:
                    return False, f"Contract '{contract.case_id}' failed: Key '{req_key}' has None value; expected non-null data"

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
