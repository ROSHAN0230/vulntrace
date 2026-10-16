"""
VulnTrace Canonical Intent Specification & Models (M7 Phase 2 / Spec §4.4)
Defines the typed Pydantic representation for repair intent, scope constraints,
and acceptance test criteria.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AcceptanceTestDefinition(BaseModel):
    """Definition of an individual synthesized or required acceptance test."""
    name: str = Field(..., description="Canonical test function identifier")
    status: str = Field(default="REQUIRED", description="'REQUIRED', 'OPTIONAL', or 'MUTATION'")
    oracle: str = Field(..., description="Target oracle class or validation mechanism")
    code: Optional[str] = Field(default=None, description="Synthesized Python test code snippet")
    target_symbol: Optional[str] = Field(default=None, description="Target function or class symbol")
    description: Optional[str] = Field(default=None, description="Human-readable description of test intent")


class Spec(BaseModel):
    """
    Canonical Repair Specification schema.
    Must explicitly preserve:
    - must_fix: Concrete security defect or target sink
    - must_preserve: Preserved behaviors, custom loaders, and regression invariants
    - constraints: Diff budget, max files, and behavioral boundaries
    - out_of_scope: Explicit non-goals and untouched modules
    - acceptance_tests: Concrete verifiable tests
    - is_verifiable: Whether intent satisfies verifiable threshold
    - warning / unverifiable_reason: Explanatory diagnostic if unverifiable
    """
    must_fix: str = Field(..., description="Target vulnerability, CVE, or unsafe sink")
    must_preserve: List[str] = Field(default_factory=list, description="Preservation invariants and custom features")
    constraints: List[str] = Field(default_factory=list, description="Scope guard diff budgets and file limits")
    out_of_scope: List[str] = Field(default_factory=list, description="Explicit out of scope items")
    acceptance_tests: List[AcceptanceTestDefinition] = Field(
        default_factory=list,
        description="Synthesized acceptance test definitions"
    )
    is_verifiable: bool = Field(default=True, description="True if intent is concretely testable")
    warning: Optional[str] = Field(default=None, description="Warning message for user/UI")
    unverifiable_reason: Optional[str] = Field(default=None, description="Reason if flagged UNVERIFIABLE")
    target_file: Optional[str] = Field(default=None, description="Target source file being repaired")
    vulnerable_symbol: Optional[str] = Field(default=None, description="Target function or sink caller")

    def to_api_dict(self) -> Dict[str, Any]:
        """Formats the specification into the dictionary structure expected by REST endpoints and DB."""
        warning_msg = self.warning or self.unverifiable_reason
        return {
            "is_verifiable": self.is_verifiable,
            "warning": warning_msg,
            "unverifiable_reason": self.unverifiable_reason or self.warning,
            "parsed_spec": {
                "must_fix": self.must_fix,
                "must_preserve": self.must_preserve,
                "constraints": self.constraints,
                "out_of_scope": self.out_of_scope,
                "acceptance_tests": [t.model_dump() for t in self.acceptance_tests]
            }
        }
