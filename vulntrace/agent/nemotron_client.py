"""
Nebius Token Factory Nemotron Client
Performs live model inference against NVIDIA Nemotron models hosted on Nebius Token Factory.
"""

from typing import Dict, Any, Optional
import time
import httpx
from vulntrace.config import settings

class NemotronClient:
    ENDPOINT = "https://api.tokenfactory.nebius.com/v1/chat/completions"
    DEFAULT_MODEL = "nvidia/Nemotron-3-Ultra-550b-a55b"
    FALLBACK_MODEL = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"

    def __init__(self, api_key: Optional[str] = None, timeout: float = 30.0):
        self.api_key = api_key or settings.nebius_api_key
        self.timeout = timeout

    async def generate_patch_suggestion(
        self,
        cve_id: str,
        vulnerable_code: str,
        advisory_summary: str,
        model_name: Optional[str] = None
    ) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "success": False,
                "error": "Nebius Token Factory API key not configured.",
                "status_code": 401,
                "latency_ms": 0.0
            }

        target_model = model_name or self.DEFAULT_MODEL
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        system_prompt = (
            "You are an expert security engineer and compiler engineer. "
            "Your task is to synthesize a surgical, minimal, non-breaking patch "
            "for a known vulnerability. Preserve all surrounding code. "
            "Do not introduce new dependencies."
        )

        user_prompt = (
            f"Vulnerability ID: {cve_id}\n"
            f"Advisory: {advisory_summary}\n\n"
            f"Vulnerable Code:\n```python\n{vulnerable_code}\n```\n\n"
            "Return the complete updated Python file inside ```python ... ``` block without truncation. "
            "Preserve all surrounding helper classes, functions, custom constructors, and docstrings."
        )

        payload = {
            "model": target_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "max_tokens": 2048,
            "temperature": 0.2
        }

        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.ENDPOINT, headers=headers, json=payload)
                dt = (time.perf_counter() - t0) * 1000.0

                if resp.status_code != 200:
                    return {
                        "success": False,
                        "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
                        "status_code": resp.status_code,
                        "latency_ms": round(dt, 2)
                    }

                data = resp.json()
                choice = data["choices"][0]
                msg = choice.get("message", {})
                content = msg.get("content") or ""
                reasoning = msg.get("reasoning_content") or msg.get("reasoning") or ""
                usage = data.get("usage", {})

                return {
                    "success": True,
                    "model": data.get("model", target_model),
                    "content": content,
                    "reasoning": reasoning,
                    "usage": usage,
                    "latency_ms": round(dt, 2),
                    "status_code": 200
                }
        except Exception as e:
            dt = (time.perf_counter() - t0) * 1000.0
            return {
                "success": False,
                "error": f"{type(e).__name__}: {str(e)}",
                "status_code": 500,
                "latency_ms": round(dt, 2)
            }
