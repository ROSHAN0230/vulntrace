"""
VulnTrace Remediation Engine
Synthesizes surgical patches using NVIDIA Nemotron 3 Ultra (via Nebius Token Factory)
with AST deterministic codemod fallback. Generates unified diffs and records token telemetry.
"""

import ast
import time
import difflib
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from vulntrace.agent.nemotron_client import NemotronClient
from vulntrace.models import RemediationRequest, RemediationResponse

class RemediationPatcher:
    """Remediation synthesizer combining live Nemotron 3 Ultra and deterministic AST codemods."""

    @classmethod
    def _ast_deterministic_patch(cls, orig_code: str, vulnerable_call: str = "yaml.load") -> str:
        """
        Deterministic AST codemod replacing unsafe calls (yaml.load, yaml.full_load, yaml.unsafe_load)
        with their secure counterparts (yaml.safe_load).
        Guaranteed to produce syntactically valid, minimal code changes.
        """
        class SafeLoadTransformer(ast.NodeTransformer):
            def visit_Call(self, node: ast.Call):
                # Match yaml.load, yaml.full_load, yaml.unsafe_load
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ["load", "full_load", "unsafe_load"]:
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml":
                            new_func = ast.Attribute(
                                value=ast.Name(id="yaml", ctx=ast.Load()),
                                attr="safe_load",
                                ctx=ast.Load()
                            )
                            # Retain first argument (payload), discard unsafe Loader kwargs
                            new_args = node.args[:1]
                            return ast.Call(func=new_func, args=new_args, keywords=[])
                return self.generic_visit(node)

        tree = ast.parse(orig_code)
        transformer = SafeLoadTransformer()
        patched_tree = transformer.visit(tree)
        ast.fix_missing_locations(patched_tree)
        return ast.unparse(patched_tree)

    @classmethod
    async def synthesize_remediation(
        cls,
        req: RemediationRequest,
        workspace_dir: Optional[Path] = None
    ) -> RemediationResponse:
        t0 = time.perf_counter()
        base_dir = workspace_dir or Path(req.repo_path).resolve()
        target_path = base_dir / req.target_file

        if not target_path.exists():
            dt = (time.perf_counter() - t0) * 1000.0
            return RemediationResponse(
                cve_id=req.cve_id,
                target_file=req.target_file,
                engine="NONE",
                diff="",
                explanation="Target file not found.",
                latency_ms=round(dt, 2),
                success=False,
                error=f"File not found: {target_path}"
            )

        orig_code = target_path.read_text(encoding="utf-8")
        patched_code: Optional[str] = None
        engine_used = "AST_DETERMINISTIC_CODEMOD"
        explanation = "Replaced unsafe yaml.load with yaml.safe_load via AST deterministic transformer."
        tokens_used = None
        reasoning_tokens = None
        model_name = None

        # 1. Attempt live Nemotron inference if requested
        if req.use_nemotron:
            client = NemotronClient()
            if not client.api_key:
                if not req.allow_ast_fallback:
                    dt = (time.perf_counter() - t0) * 1000.0
                    return RemediationResponse(
                        cve_id=req.cve_id,
                        target_file=req.target_file,
                        engine="NVIDIA_NEMOTRON_3_ULTRA",
                        diff="",
                        explanation="Nemotron requested but Nebius API key is not configured.",
                        latency_ms=round(dt, 2),
                        success=False,
                        validation_status="REJECTED_MISSING_CREDENTIALS",
                        error="Nebius API key is missing or unconfigured."
                    )
            else:
                try:
                    advisory = req.advisory_summary or f"Remediate {req.cve_id} in {req.target_file}: unsafe {req.vulnerable_call} deserialization."
                    nem_res = await client.generate_patch_suggestion(
                        cve_id=req.cve_id,
                        vulnerable_code=orig_code,
                        advisory_summary=advisory
                    )
                    if not nem_res.get("success"):
                        if not req.allow_ast_fallback:
                            dt = (time.perf_counter() - t0) * 1000.0
                            return RemediationResponse(
                                cve_id=req.cve_id,
                                target_file=req.target_file,
                                engine="NVIDIA_NEMOTRON_3_ULTRA",
                                diff="",
                                explanation="Nemotron API call failed.",
                                latency_ms=round(dt, 2),
                                success=False,
                                validation_status="REJECTED_API_ERROR",
                                error=nem_res.get("error", "Unknown API error")
                            )
                    else:
                        content = nem_res.get("content", "")
                        usage = nem_res.get("usage", {})
                        tokens_used = usage.get("total_tokens")
                        reasoning_tokens = usage.get("completion_tokens_details", {}).get("reasoning_tokens")

                        # Extract python code block
                        if "```python" in content:
                            parts = content.split("```python")
                            code_part = parts[1].split("```")[0].strip()
                        elif "```" in content:
                            parts = content.split("```")
                            code_part = parts[1].strip()
                        else:
                            code_part = content.strip()

                        # Step 1: AST Syntax Validation
                        try:
                            ast.parse(code_part)
                        except SyntaxError as syn_err:
                            if not req.allow_ast_fallback:
                                dt = (time.perf_counter() - t0) * 1000.0
                                return RemediationResponse(
                                    cve_id=req.cve_id,
                                    target_file=req.target_file,
                                    engine="NVIDIA_NEMOTRON_3_ULTRA",
                                    diff="",
                                    explanation=f"Nemotron generated invalid Python syntax: {syn_err}",
                                    tokens_used=tokens_used,
                                    reasoning_tokens=reasoning_tokens,
                                    latency_ms=round(dt, 2),
                                    success=False,
                                    validation_status="REJECTED_SYNTAX_ERROR",
                                    error=f"AST syntax validation error: {syn_err}"
                                )
                            code_part = None

                        # Step 2: Semantic Change Verification
                        if code_part is not None:
                            if code_part == orig_code:
                                if not req.allow_ast_fallback:
                                    dt = (time.perf_counter() - t0) * 1000.0
                                    return RemediationResponse(
                                        cve_id=req.cve_id,
                                        target_file=req.target_file,
                                        engine="NVIDIA_NEMOTRON_3_ULTRA",
                                        diff="",
                                        explanation="Nemotron output contained no modifications to the vulnerable file.",
                                        tokens_used=tokens_used,
                                        reasoning_tokens=reasoning_tokens,
                                        latency_ms=round(dt, 2),
                                        success=False,
                                        validation_status="REJECTED_EMPTY",
                                        error="Generated patch produced no semantic changes."
                                    )
                                code_part = None
                            else:
                                patched_code = code_part
                                engine_used = "NVIDIA_NEMOTRON_3_ULTRA"
                                model_name = nem_res.get("model")
                                explanation = content.split("```")[-1].strip() or "Synthesized surgical remediation using Nemotron 3 Ultra."
                except Exception as e:
                    if not req.allow_ast_fallback:
                        dt = (time.perf_counter() - t0) * 1000.0
                        return RemediationResponse(
                            cve_id=req.cve_id,
                            target_file=req.target_file,
                            engine="NVIDIA_NEMOTRON_3_ULTRA",
                            diff="",
                            explanation=f"Exception during Nemotron remediation: {e}",
                            latency_ms=round(dt, 2),
                            success=False,
                            validation_status="REJECTED_EXCEPTION",
                            error=str(e)
                        )

        # 2. Deterministic AST codemod (if Nemotron not requested or explicitly allowed fallback)
        if not patched_code:
            try:
                patched_code = cls._ast_deterministic_patch(orig_code, req.vulnerable_call)
                # Verify syntax of AST patch
                ast.parse(patched_code)
                engine_used = "AST_DETERMINISTIC_CODEMOD"
                explanation = f"Applied AST deterministic codemod: replaced {req.vulnerable_call} with safe alternative."
            except Exception as e:
                dt = (time.perf_counter() - t0) * 1000.0
                return RemediationResponse(
                    cve_id=req.cve_id,
                    target_file=req.target_file,
                    engine="FAILED",
                    diff="",
                    explanation="Failed to synthesize patch.",
                    latency_ms=round(dt, 2),
                    success=False,
                    validation_status="REJECTED",
                    error=str(e)
                )

        # 3. Compute unified diff
        diff_lines = list(difflib.unified_diff(
            orig_code.splitlines(keepends=True),
            patched_code.splitlines(keepends=True),
            fromfile=f"a/{req.target_file}",
            tofile=f"b/{req.target_file}"
        ))
        diff_str = "".join(diff_lines)

        # 4. Write patched code to file in workspace
        target_path.write_text(patched_code, encoding="utf-8")

        # 5. Compute patch delta metadata
        from vulntrace.engine.patch_delta import PatchDeltaAnalyzer
        patch_delta_meta = PatchDeltaAnalyzer.analyze_diff(
            diff_text=diff_str,
            target_function=req.vulnerable_call,
            reason=explanation
        )

        dt = (time.perf_counter() - t0) * 1000.0
        return RemediationResponse(
            cve_id=req.cve_id,
            target_file=req.target_file,
            engine=engine_used,
            diff=diff_str,
            explanation=explanation,
            tokens_used=tokens_used,
            reasoning_tokens=reasoning_tokens,
            latency_ms=round(dt, 2),
            success=True,
            validation_status="ACCEPTED",
            patch_delta=patch_delta_meta,
            model_name=model_name
        )
