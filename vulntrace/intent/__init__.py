"""
VulnTrace Intent Package (M7 Phase 2 / Spec §4.4)
Modular intent parser, canonical specification schemas, acceptance test synthesizer,
and strict anti-gaming quality gates.
"""

from vulntrace.intent.spec import Spec, AcceptanceTestDefinition
from vulntrace.intent.parser import IntentParser, parse_intent, parse_and_validate_intent
from vulntrace.intent.synthesizer import AcceptanceTestSynthesizer
from vulntrace.intent.validator import IntentQualityValidator, QualityGateFailure

__all__ = [
    "Spec",
    "AcceptanceTestDefinition",
    "IntentParser",
    "parse_intent",
    "parse_and_validate_intent",
    "AcceptanceTestSynthesizer",
    "IntentQualityValidator",
    "QualityGateFailure",
]
