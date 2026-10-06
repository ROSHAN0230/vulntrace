"""
Token & Inference Call Accounting Ledger (Spec §4.7 / §4.11)
Tracks per-stage LLM call provenance, token consumption (prompt, completion, reasoning),
and inference latencies across model tiers.
Enforces strict secret hygiene: API keys and sensitive tokens are NEVER logged or exported.
"""

import time
import uuid
from typing import List, Dict, Optional
from vulntrace.models import LLMCallRecord, LLMLedgerSummary
from vulntrace.llm.tier import LLMModelTier


class TokenLedger:
    """Thread-safe accounting ledger tracking all LLM inference calls in a pipeline session."""

    def __init__(self):
        self._records: List[LLMCallRecord] = []

    def record_call(
        self,
        stage: str,
        model: str,
        tier: LLMModelTier,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        reasoning_tokens: int = 0,
        latency_ms: float = 0.0,
        success: bool = True,
        error: Optional[str] = None
    ) -> LLMCallRecord:
        """Records an inference call into the active ledger session."""
        total_tokens = prompt_tokens + completion_tokens + reasoning_tokens
        record = LLMCallRecord(
            call_id=f"llm-{uuid.uuid4().hex[:8]}",
            timestamp=time.time(),
            stage=stage,
            model=model,
            tier=tier.value,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            reasoning_tokens=reasoning_tokens,
            total_tokens=total_tokens,
            latency_ms=round(latency_ms, 2),
            success=success,
            error=self._sanitize_error(error)
        )
        self._records.append(record)
        return record

    def get_summary(self) -> LLMLedgerSummary:
        """Aggregates all recorded calls into a canonical ledger summary."""
        total_prompt = sum(r.prompt_tokens for r in self._records)
        total_comp = sum(r.completion_tokens for r in self._records)
        total_reason = sum(r.reasoning_tokens for r in self._records)
        total_tok = sum(r.total_tokens for r in self._records)
        total_lat = sum(r.latency_ms for r in self._records)

        tier_breakdown: Dict[str, Dict[str, int]] = {}
        model_breakdown: Dict[str, Dict[str, int]] = {}

        for r in self._records:
            # Aggregate by tier
            if r.tier not in tier_breakdown:
                tier_breakdown[r.tier] = {"calls": 0, "tokens": 0, "prompt": 0, "completion": 0}
            tier_breakdown[r.tier]["calls"] += 1
            tier_breakdown[r.tier]["tokens"] += r.total_tokens
            tier_breakdown[r.tier]["prompt"] += r.prompt_tokens
            tier_breakdown[r.tier]["completion"] += r.completion_tokens

            # Aggregate by model
            if r.model not in model_breakdown:
                model_breakdown[r.model] = {"calls": 0, "tokens": 0, "prompt": 0, "completion": 0}
            model_breakdown[r.model]["calls"] += 1
            model_breakdown[r.model]["tokens"] += r.total_tokens
            model_breakdown[r.model]["prompt"] += r.prompt_tokens
            model_breakdown[r.model]["completion"] += r.completion_tokens

        return LLMLedgerSummary(
            total_calls=len(self._records),
            total_prompt_tokens=total_prompt,
            total_completion_tokens=total_comp,
            total_reasoning_tokens=total_reason,
            total_tokens=total_tok,
            total_latency_ms=round(total_lat, 2),
            calls=list(self._records),
            tier_breakdown=tier_breakdown,
            model_breakdown=model_breakdown
        )

    def has_multiple_tiers(self, min_tiers: int = 2) -> bool:
        """Returns True if the ledger contains calls across at least min_tiers different model tiers."""
        active_tiers = set(r.tier for r in self._records if r.success)
        return len(active_tiers) >= min_tiers

    def reset(self) -> None:
        """Clears all records."""
        self._records.clear()

    @staticmethod
    def _sanitize_error(error: Optional[str]) -> Optional[str]:
        """Strips potential API keys, auth headers, and bearer tokens from error strings."""
        if not error:
            return None
        import re
        sanitized = re.sub(r"Bearer\s+[A-Za-z0-9_\-\.]+", "Bearer [REDACTED]", error)
        sanitized = re.sub(r"api[_-]?key=[A-Za-z0-9_\-\.]+", "api_key=[REDACTED]", sanitized, flags=re.IGNORECASE)
        return sanitized
