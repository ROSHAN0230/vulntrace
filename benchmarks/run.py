"""
Test runner script executing all 4 VulnTrace benchmark scenarios
through the end-to-end controlled VerificationPipeline.
"""
import asyncio
import json
from pathlib import Path
from vulntrace.sandbox.pipeline import VerificationPipeline
from vulntrace.models import VerificationPipelineRequest
from vulntrace.server import BENCHMARK_SCENARIOS

async def main():
    print("=" * 70)
    print("VULNTRACE PHASE 3 BENCHMARK EVALUATION SUITE")
    print("=" * 70)
    
    summary = []
    
    for sc in BENCHMARK_SCENARIOS:
        print(f"\n--- Running Scenario: {sc.name} ({sc.id}) ---")
        print(f"Path: {sc.repo_path}")
        print(f"Target: {sc.target_file}:{sc.target_function}()")
        print(f"Expected Reachability: {sc.expected_reachability}")
        print(f"Expected Behavioral Verdict: {sc.expected_behavioral_verdict}")
        
        req = VerificationPipelineRequest(
            repo_path=sc.repo_path,
            cve_id=sc.cve_id,
            target_file=sc.target_file,
            target_function=sc.target_function,
            vulnerable_symbol="yaml.load",
            use_nemotron=True
        )
        
        events = []
        def log_event(evt):
            events.append(evt)
            if evt.event_type in ["STATE_TRANSITION", "STAGE_START", "STAGE_COMPLETE"]:
                print(f"  [{evt.stage}] {evt.message}")
        
        res = await VerificationPipeline.run_pipeline(req, on_event=log_event)
        
        entry = {
            "id": sc.id,
            "name": sc.name,
            "reachability_verdict": res.reachability_verdict,
            "expected_reachability": sc.expected_reachability,
            "reachability_match": res.reachability_verdict == sc.expected_reachability,
            "behavioral_verdict": res.final_behavioral_verdict,
            "expected_behavioral": sc.expected_behavioral_verdict,
            "behavioral_match": res.final_behavioral_verdict == sc.expected_behavioral_verdict,
            "pre_patch_state": res.pre_patch_result.reproduction_state,
            "remediation_engine": res.remediation.engine,
            "remediation_diff": res.remediation.diff,
            "post_patch_state": res.post_patch_result.reproduction_state,
            "regression_passed": res.regression_tests.get("passed", False),
            "regression_test_count": res.regression_tests.get("test_count", 0),
            "isolation_tier": res.isolation_tier,
            "sandbox_engine": res.sandbox_engine,
            "latency_ms": res.total_pipeline_ms
        }
        summary.append(entry)
        print(f"-> Result: Reachability={res.reachability_verdict} | Behavioral={res.final_behavioral_verdict} | Tier={res.isolation_tier} | Engine={res.remediation.engine} | Regressions={res.regression_tests.get('passed')} ({res.regression_tests.get('test_count')} tests) in {res.total_pipeline_ms}ms")
    
    print("\n" + "=" * 70)
    print("BENCHMARK SUITE EXECUTION SUMMARY")
    print("=" * 70)
    print(json.dumps(summary, indent=2))
    
    output_path = Path(__file__).resolve().parent.parent / "docs" / "evidence" / "benchmark_results.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

if __name__ == "__main__":
    asyncio.run(main())
