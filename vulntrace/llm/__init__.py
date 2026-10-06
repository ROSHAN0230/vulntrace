"""
VulnTrace LLM Layer (Spec §4.7)
"""

from vulntrace.llm.tier import LLMModelTier, get_model_for_tier, DEFAULT_TIER_MODELS
from vulntrace.llm.ledger import TokenLedger
from vulntrace.llm.client import TokenFactoryClient
from vulntrace.llm.cassette import LLMCassetteManager

__all__ = [
    "LLMModelTier",
    "get_model_for_tier",
    "DEFAULT_TIER_MODELS",
    "TokenLedger",
    "TokenFactoryClient",
    "LLMCassetteManager",
]
