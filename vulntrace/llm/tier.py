"""
Nebius Token Factory Model Tiering Definitions (Spec §4.7 / D11)
Defines model tiers verified live against the Nebius Token Factory catalog:
- SMALL: nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B (Fast triage, classification, intel extraction)
- MID: nvidia/nemotron-3-super-120b-a12b (Planning, structured specification, test synthesis)
- ULTRA: nvidia/Nemotron-3-Ultra-550b-a55b (High-precision surgical patching and repair loops)
"""

import os
from enum import Enum
from typing import Dict


class LLMModelTier(str, Enum):
    SMALL = "SMALL"
    MID = "MID"
    ULTRA = "ULTRA"


# Live-verified Nebius Token Factory model IDs
DEFAULT_TIER_MODELS: Dict[LLMModelTier, str] = {
    LLMModelTier.SMALL: "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B",
    LLMModelTier.MID: "nvidia/nemotron-3-super-120b-a12b",
    LLMModelTier.ULTRA: "nvidia/Nemotron-3-Ultra-550b-a55b",
}


def get_model_for_tier(tier: LLMModelTier) -> str:
    """Resolves verified model ID for a given tier, respecting environment overrides."""
    env_key = f"NEBIUS_MODEL_{tier.value}"
    return os.environ.get(env_key, DEFAULT_TIER_MODELS[tier])
