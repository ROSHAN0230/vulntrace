"""
Nebius Token Factory Nemotron Client Adapter (Spec §4.7)
Performs model inference against NVIDIA Nemotron models hosted on Nebius Token Factory.
Delegates to the canonical TokenFactoryClient with cassette replay and token accounting.
"""

from typing import Dict, Any, Optional
from vulntrace.config import settings
from vulntrace.llm.tier import LLMModelTier
from vulntrace.llm.client import TokenFactoryClient
from vulntrace.llm.ledger import TokenLedger


class NemotronClient:
    ENDPOINT = "https://api.tokenfactory.nebius.com/v1/chat/completions"
    DEFAULT_MODEL = "nvidia/Nemotron-3-Ultra-550b-a55b"
    FALLBACK_MODEL = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 45.0,
        ledger: Optional[TokenLedger] = None
    ):
        self.api_key = api_key or settings.nebius_api_key
        self.timeout = timeout
        self.ledger = ledger or TokenLedger()
        self._client = TokenFactoryClient(
            api_key=self.api_key,
            timeout=self.timeout,
            ledger=self.ledger
        )

    async def generate_patch_suggestion(
        self,
        cve_id: str,
        vulnerable_code: str,
        advisory_summary: str,
        model_name: Optional[str] = None
    ) -> Dict[str, Any]:
        if not self.api_key and not self._client.api_key:
            return {
                "success": False,
                "error": "Nebius Token Factory API key not configured.",
                "status_code": 401,
                "latency_ms": 0.0
            }

        system_prompt = (
            "You are an expert security engineer and compiler engineer. "
            "Your task is to synthesize a surgical, minimal, non-breaking patch "
            "for a known vulnerability. Preserve all surrounding code. "
            "Do not introduce new dependencies."
        )

        untrusted_code_block = TokenFactoryClient.wrap_untrusted_content(
            vulnerable_code,
            label="VULNERABLE_SOURCE_CODE"
        )

        user_prompt = (
            f"Vulnerability ID: {cve_id}\n"
            f"Advisory: {advisory_summary}\n\n"
            f"Vulnerable Code:\n{untrusted_code_block}\n\n"
            "Return the complete updated Python file inside ```python ... ``` block without truncation. "
            "Preserve all surrounding helper classes, functions, custom constructors, and docstrings."
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        content, call_rec = await self._client.generate_chat(
            tier=LLMModelTier.ULTRA,
            messages=messages,
            stage="patch_synthesis",
            max_tokens=2048,
            temperature=0.2
        )

        if not call_rec.success:
            return {
                "success": False,
                "error": call_rec.error or "Unknown API error",
                "status_code": 500,
                "latency_ms": call_rec.latency_ms
            }

        return {
            "success": True,
            "model": call_rec.model,
            "content": content,
            "reasoning": "",
            "usage": {
                "prompt_tokens": call_rec.prompt_tokens,
                "completion_tokens": call_rec.completion_tokens,
                "reasoning_tokens": call_rec.reasoning_tokens,
                "total_tokens": call_rec.total_tokens
            },
            "latency_ms": call_rec.latency_ms,
            "status_code": 200
        }
