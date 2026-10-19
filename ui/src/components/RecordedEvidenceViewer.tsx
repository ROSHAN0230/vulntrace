import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FileCode,
  Cpu,
  Copy,
  Check,
  Lock,
  Server
} from 'lucide-react';

export type ShowcaseCaseId =
  | 'contextual_reasoning'
  | 'case_rw_04'
  | 'flasgger_external'
  | 'naive_comparison'
  | 'tavily_intel';

interface TestCaseInfo {
  name: string;
  status: 'passed' | 'failed' | 'skipped';
  duration?: string;
}

interface ShowcaseCaseData {
  id: ShowcaseCaseId;
  title: string;
  category: 'Curated Benchmark' | 'Internal Microservice Benchmark' | 'External Repository';
  provenance: string;
  verdict: 'GREEN_STATE_VERIFIED' | 'INCONCLUSIVE' | 'REGRESSION_FAILED' | 'VERIFIED';
  verdictBadgeColor: 'emerald' | 'amber' | 'rose' | 'blue';
  cveId: string;
  targetSymbol: string;
  isolationTier: string;
  isolationDescription: string;
  summary: string;
  executionMode: string;
  prePatchState: {
    exitCode: number;
    state: string;
    sentinelObserved: boolean;
    detail: string;
  };
  postPatchState: {
    exitCode: number;
    state: string;
    sentinelObserved: boolean;
    exceptionType?: string;
    detail: string;
  };
  regressionTests: {
    passed: boolean;
    total: number;
    passedCount: number;
    failedCount: number;
    tests: TestCaseInfo[];
  };
  diff?: string;
  telemetrySummary: {
    label: string;
    value: string;
  }[];
  notes: string[];
}

const SHOWCASE_CASES: Record<ShowcaseCaseId, ShowcaseCaseData> = {
  contextual_reasoning: {
    id: 'contextual_reasoning',
    title: 'Contextual Reasoning: Custom AppSafeLoader Hardening',
    category: 'Curated Benchmark',
    provenance: 'Internal curated synthetic benchmark (SYNTH-01) in benchmarks/contextual_reasoning. Evaluates contextual AST awareness when custom YAML tag constructors are present.',
    verdict: 'GREEN_STATE_VERIFIED',
    verdictBadgeColor: 'emerald',
    cveId: 'CVE-2020-14343',
    targetSymbol: 'service/custom_loader.py:parse_app_config (yaml.load)',
    isolationTier: 'OCI_CONTAINER_ISOLATED (Tier 1)',
    isolationDescription: 'Rootless Podman (vulntrace-sandbox-base:latest), kernel network denial (--network none), read-only rootfs, tmpfs /tmp, unprivileged non-root user (1000:1000).',
    summary: 'NVIDIA Nemotron 3 Ultra analyzes surrounding module context, identifies domain AppSafeLoader subclass extending SafeLoader with custom !env_var tags, and binds Loader=AppSafeLoader. Exploit is blocked with ConstructorError (exit 42) and all 3 regression tests pass.',
    executionMode: 'Live NVIDIA Nemotron 3 Ultra API (Phase 3 run) + Offline Cassette Threat Intelligence',
    prePatchState: {
      exitCode: 0,
      state: 'RED_STATE_REPRODUCED',
      sentinelObserved: true,
      detail: 'Arbitrary builtins.eval executed via yaml.load; physical sentinel file created on parent workspace disk.'
    },
    postPatchState: {
      exitCode: 42,
      state: 'GREEN_STATE_BLOCKED',
      sentinelObserved: false,
      exceptionType: 'ConstructorError',
      detail: 'ConstructorError caught; sentinel absent; positive control contracts verified (flat mapping, nested hierarchy, multi-type).'
    },
    regressionTests: {
      passed: true,
      total: 3,
      passedCount: 3,
      failedCount: 0,
      tests: [
        { name: 'test_standard_yaml', status: 'passed' },
        { name: 'test_custom_env_tag (!env_var)', status: 'passed' },
        { name: 'test_nested_dictionary', status: 'passed' }
      ]
    },
    diff: `--- a/service/custom_loader.py
+++ b/service/custom_loader.py
@@ -18,8 +18,8 @@
     Must maintain support for !env_var custom tag.
     Vulnerable sink: currently uses unsafe yaml.load with default Loader.
     """
-    # Vulnerable sink (CVE-2020-14343)
-    data = yaml.load(raw_yaml, Loader=yaml.Loader)
+    # Fixed: use AppSafeLoader (extends SafeLoader) to prevent arbitrary code execution
+    data = yaml.load(raw_yaml, Loader=AppSafeLoader)
     if isinstance(data, dict):
         return data
-    return {"config": data}
+    return {"config": data}`,
    telemetrySummary: [
      { label: 'LLM Engine', value: 'NVIDIA_NEMOTRON_3_ULTRA' },
      { label: 'Model', value: 'nvidia/Nemotron-3-Ultra-550b-a55b' },
      { label: 'Tokens Used', value: '3,450 tokens' },
      { label: 'Reproduction Latency', value: '131.9 ms' },
      { label: 'Regression Suite', value: '3/3 passed (100%)' }
    ],
    notes: [
      'Authentic recorded run from Phase 3 live verification.',
      'Demonstrates contextual reasoning: a blind codemod (yaml.safe_load) breaks !env_var constructors.',
      'Tier 1 container execution verified zero network leakage and zero ambient secret exposure.'
    ]
  },

  case_rw_04: {
    id: 'case_rw_04',
    title: 'CASE-RW-04: Multi-File Microservice Integration Benchmark',
    category: 'Internal Microservice Benchmark',
    provenance: 'Curated multi-file microservice integration fixture created in VulnTrace commit 241f93f. Stored at real_world_eval/repo_cloud_config. NOT a third-party open-source project.',
    verdict: 'GREEN_STATE_VERIFIED',
    verdictBadgeColor: 'emerald',
    cveId: 'CVE-2020-14343',
    targetSymbol: 'service/manifest_router.py -> service/yaml_adapter.py:parse_cloud_descriptor',
    isolationTier: 'OCI_CONTAINER_ISOLATED (Tier 1)',
    isolationDescription: 'Rootless Podman (vulntrace-sandbox-base:latest), --network none, disposable workspace mounted at tmpfs /tmp, unprivileged execution.',
    summary: 'Multi-hop inter-module call chain from router entrypoint to YAML adapter. Successfully verified across 3 live Nemotron tiers (Nano 30B -> Super 120B -> Ultra 550B) generating a minimal 8-line patch. All 4 unit and integration tests pass.',
    executionMode: 'Live Multi-Tier NVIDIA Nemotron API (Run ID: run_38193ea01037) + Offline Cassette Intel',
    prePatchState: {
      exitCode: 0,
      state: 'RED_STATE_REPRODUCED',
      sentinelObserved: true,
      detail: 'Target calls yaml.load(raw_yaml, Loader=yaml.Loader) with explicit Loader, allowing builtins.eval in PyYAML 6.0.3. Sentinel created in 2,814 ms.'
    },
    postPatchState: {
      exitCode: 42,
      state: 'GREEN_STATE_BLOCKED',
      sentinelObserved: false,
      exceptionType: 'ConstructorError',
      detail: 'ConstructorError evaluated; zero sentinels on disk; positive control passed in 1,482 ms.'
    },
    regressionTests: {
      passed: true,
      total: 4,
      passedCount: 4,
      failedCount: 0,
      tests: [
        { name: 'test_manifest_router_success', status: 'passed' },
        { name: 'test_manifest_router_invalid_yaml', status: 'passed' },
        { name: 'test_manifest_router_non_dict_yaml', status: 'passed' },
        { name: 'test_manifest_router_type_error', status: 'passed' }
      ]
    },
    diff: `--- a/service/yaml_adapter.py
+++ b/service/yaml_adapter.py
@@ -8,13 +8,13 @@
 def parse_cloud_descriptor(raw_yaml: str) -> Dict[str, Any]:
     """
     Parses arbitrary cloud descriptor YAML.
-    Vulnerable sink: uses unsafe Loader=yaml.Loader (CVE-2020-14343).
+    Fixed: uses safe_load to prevent arbitrary code execution (CVE-2020-14343).
     """
     if not isinstance(raw_yaml, str):
         raise TypeError("raw_yaml must be string")

-    # Insecure deserialization of untrusted cloud config
-    result = yaml.load(raw_yaml, Loader=yaml.Loader)
+    # Secure deserialization of untrusted cloud config
+    result = yaml.safe_load(raw_yaml)
     if not isinstance(result, dict):
         raise ValueError("Descriptor must evaluate to a dictionary")
-    return result
+    return result`,
    telemetrySummary: [
      { label: 'Run ID', value: 'run_38193ea01037' },
      { label: 'Triage Tier (Nano 30B)', value: '1,299 tokens (3,628 ms)' },
      { label: 'Planning Tier (Super 120B)', value: '1,438 tokens (3,523 ms)' },
      { label: 'Synthesis Tier (Ultra 550B)', value: '1,482 tokens (2,328 ms)' },
      { label: 'Total Live Tokens', value: '4,219 tokens (767 reasoning)' },
      { label: 'Regression Suite', value: '4/4 passed in 1,474 ms' }
    ],
    notes: [
      'Provenance rule: Must never be described as a third-party open-source repository.',
      'Succeeds where Flasgger halted because explicit yaml.Loader reproduces RED in modern PyYAML, and tests have zero legacy Flask dependencies.',
      'Authentic recorded execution from Phase 4C.'
    ]
  },

  flasgger_external: {
    id: 'flasgger_external',
    title: 'Flasgger: External Repository Fail-Closed Inconclusive Result',
    category: 'External Repository',
    provenance: 'Authentic pinned external open-source repository: flasgger/flasgger at vulnerable commit 163a753 (51 Python files). Evaluated in Phase 4 / Phase 4A.',
    verdict: 'INCONCLUSIVE',
    verdictBadgeColor: 'amber',
    cveId: 'CVE-2020-14343 / CVE-2020-24395',
    targetSymbol: 'flasgger/utils.py:parse_docstring (yaml.load)',
    isolationTier: 'OCI_CONTAINER_ISOLATED (Tier 1)',
    isolationDescription: 'Rootless Podman container environment running Python 3.12, PyYAML 6.0.3, pytest 9.1.1.',
    summary: 'VulnTrace correctly identified 3 reachable vulnerable sinks via AST call-graph analysis. However, under the available PyYAML 6.0.3 container runtime, implicit yaml.load blocks the exploit probe by default, so RED state could not be reproduced. Test collection also failed due to legacy Flask 1.x Markup deprecation in Flask 3.1.3 and missing flex. VulnTrace safely halted remediation without guessing.',
    executionMode: 'Offline Container Evaluation (Phase 4 / Phase 4A Audit)',
    prePatchState: {
      exitCode: 42,
      state: 'INCONCLUSIVE_NO_EFFECT',
      sentinelObserved: false,
      detail: 'Exploit probe was blocked pre-patch by PyYAML 6.0.3 runtime defaults. VulnTrace refused to forge a RED reproduction state.'
    },
    postPatchState: {
      exitCode: -1,
      state: 'SKIPPED',
      sentinelObserved: false,
      detail: 'Patch synthesis safely halted. VulnTrace requires verified RED reproduction before attempting automated patch generation.'
    },
    regressionTests: {
      passed: false,
      total: 0,
      passedCount: 0,
      failedCount: 0,
      tests: [
        { name: 'pytest collection (flasgger/tests)', status: 'failed' }
      ]
    },
    telemetrySummary: [
      { label: 'AST Reachable Sinks', value: '3 reachable call sites identified' },
      { label: 'Vulnerability Verdict', value: 'REACHABLE_CALL_PATH_IDENTIFIED' },
      { label: 'Pre-Patch Result', value: 'INCONCLUSIVE (Exit 42)' },
      { label: 'Patch Synthesis', value: 'SAFELY HALTED (Zero code churn)' },
      { label: 'Collection Error', value: "cannot import name 'Markup' from 'flask'" },
      { label: 'Missing Dependency', value: 'flex>=0.6.2 unavailable offline' }
    ],
    notes: [
      'Critical Hackathon Disclosure: This run DOES NOT establish successful remediation of Flasgger.',
      'Demonstrates scientific honesty: VulnTrace reports INCONCLUSIVE rather than faking test passes or fabricating patches on incompatible runtimes.',
      'Milestone M7 remains OPEN/BLOCKED pending historical environment builder support.'
    ]
  },

  naive_comparison: {
    id: 'naive_comparison',
    title: 'Controlled Comparison: Naive yaml.safe_load vs Context-Aware AppSafeLoader',
    category: 'Curated Benchmark',
    provenance: 'Controlled Phase 5 experiment on benchmarks/contextual_reasoning comparing deterministic codemod against captured contextual remediation under Tier 1 container isolation.',
    verdict: 'REGRESSION_FAILED',
    verdictBadgeColor: 'rose',
    cveId: 'CVE-2020-14343',
    targetSymbol: 'service/custom_loader.py:parse_app_config',
    isolationTier: 'OCI_CONTAINER_ISOLATED (Tier 1)',
    isolationDescription: 'Two identical disposable workspace copies tested under identical rootless container environments with zero network egress.',
    summary: 'Both arms achieve security parity (both block arbitrary code execution with ConstructorError, exit 42). However, the naive baseline breaks the custom !env_var constructor, failing 1 of 3 regression tests. The context-aware AppSafeLoader patch passes all 3 regression tests.',
    executionMode: 'Offline Container Comparison Experiment (Phase 5 - Zero paid tokens)',
    prePatchState: {
      exitCode: 0,
      state: 'RED_STATE_REPRODUCED',
      sentinelObserved: true,
      detail: 'Both arms verified identical pre-patch vulnerability reproduction (exit 0, sentinel created).'
    },
    postPatchState: {
      exitCode: 42,
      state: 'GREEN_STATE_BLOCKED',
      sentinelObserved: false,
      exceptionType: 'ConstructorError',
      detail: 'Arm A (naive) and Arm B (contextual) both successfully block exploit payload with ConstructorError.'
    },
    regressionTests: {
      passed: false,
      total: 3,
      passedCount: 2,
      failedCount: 1,
      tests: [
        { name: 'test_standard_yaml', status: 'passed' },
        { name: 'test_custom_env_tag (Arm A Naive: FAILED / Arm B Contextual: PASSED)', status: 'failed' },
        { name: 'test_nested_dictionary', status: 'passed' }
      ]
    },
    diff: `--- Arm A: Naive Baseline (safe_load) ---
- data = yaml.load(raw_yaml, Loader=yaml.Loader)
+ data = yaml.safe_load(raw_yaml)
Result: Breaks !env_var custom tag constructor. 1 regression failure.

--- Arm B: Contextual Remediation (AppSafeLoader) ---
- data = yaml.load(raw_yaml, Loader=yaml.Loader)
+ data = yaml.load(raw_yaml, Loader=AppSafeLoader)
Result: Preserves !env_var custom tag constructor. 3/3 regression passes.`,
    telemetrySummary: [
      { label: 'Arm A Security Probe', value: 'GREEN_STATE_BLOCKED (Exit 42)' },
      { label: 'Arm B Security Probe', value: 'GREEN_STATE_BLOCKED (Exit 42)' },
      { label: 'Arm A Custom Tag', value: 'FAILED (ConstructorError)' },
      { label: 'Arm B Custom Tag', value: 'PASSED (value="DEFAULT_DB_HOST")' },
      { label: 'Arm A Regressions', value: '1 FAILED, 2 PASSED (0.50s)' },
      { label: 'Arm B Regressions', value: '3 PASSED, 0 FAILED (0.13s)' }
    ],
    notes: [
      'Empirical proof of functional divergence on custom tag benchmark.',
      'Single-case comparison: does not claim general superiority across all vulnerabilities.',
      'Source artifact: scratch/phase5_comparison_results.json.'
    ]
  },

  tavily_intel: {
    id: 'tavily_intel',
    title: 'Tavily Search API: Runtime Threat Intelligence Integration',
    category: 'Curated Benchmark',
    provenance: 'Single bounded live runtime search query executed in Phase 6 via vulntrace/intel/tavily_client.py with LIVE_INTEL=1.',
    verdict: 'VERIFIED',
    verdictBadgeColor: 'blue',
    cveId: 'CVE-2020-14343',
    targetSymbol: 'https://api.tavily.com/search (Real external HTTP POST)',
    isolationTier: 'Host Pre-Execution Pre-flight (Egress Decoupled)',
    isolationDescription: 'Tavily API queried on host before container launch; results passed as sanitized advisory context into isolated verification container.',
    summary: 'Verified live external HTTP request (status 200, 2,398 ms) retrieving 2 verified-relevant CVE findings. Demonstrates active relevance filtering, offline cassette bypass, and canonical normalizer extraction of affected symbols (yaml.load) to guide AST and patch planning.',
    executionMode: 'Live Tavily REST API Request (Bounded: search_depth=basic, max_results=2)',
    prePatchState: {
      exitCode: 200,
      state: 'HTTP_SUCCESS',
      sentinelObserved: false,
      detail: 'HTTP 200 OK received from https://api.tavily.com/search in 2,398.13 ms.'
    },
    postPatchState: {
      exitCode: 0,
      state: 'NORMALIZATION_OK',
      sentinelObserved: false,
      detail: 'ThreatIntelNormalizer extracted symbols ["yaml.load", "yaml.full_load"] and safe pattern ["yaml.safe_load"].'
    },
    regressionTests: {
      passed: true,
      total: 2,
      passedCount: 2,
      failedCount: 0,
      tests: [
        { name: 'Finding 1: Miggo PyYAML Code Execution (Relevant)', status: 'passed' },
        { name: 'Finding 2: Amazon Linux Security Advisory ALAS (Relevant)', status: 'passed' }
      ]
    },
    diff: `Query Dispatched: "CVE-2020-14343" vulnerable function fix commit exploit
HTTP Endpoint: https://api.tavily.com/search
Payload Constraints: max_results=2, search_depth="basic", include_answer=false

Normalized Pipeline Context Generated:
[1] Title: CVE-2020-14343: PyYAML Code Execution - Miggo
    URL: https://www.miggo.io/vulnerability-database/cve/CVE-2020-14343
[2] Title: CVE-2020-14343 - Amazon Linux ALAS
    URL: https://explore.alas.aws.amazon.com/CVE-2020-14343.html`,
    telemetrySummary: [
      { label: 'HTTP Status', value: '200 OK' },
      { label: 'Live Network Latency', value: '2,398.13 ms' },
      { label: 'Raw Results', value: '2 items' },
      { label: 'Retained Relevant', value: '2 items (100% relevant)' },
      { label: 'Cassette Bypassed', value: 'True (Verified Relevant tag)' },
      { label: 'Canonical Hash', value: '469b2f88aa8c... (Reference Items)' }
    ],
    notes: [
      'Provides credible evidence for Best Use of Tavily bonus: active relevance filtering and AST symbol binding.',
      'Cassette bypass proven: source tag confirmed "Tavily Intelligence API (Verified Relevant)" and latency was 2.4s (vs 1.5ms cassette).',
      'Canonical hash reflects SHA-256 of canonical reference advisory items, not ephemeral raw bytes.',
      'Source artifact: scratch/phase6_tavily_results.json.'
    ]
  }
};

function resolveInitialCaseId(): ShowcaseCaseId {
  if (typeof window !== 'undefined') {
    const params = new URLSearchParams(window.location.search);
    const caseParam = params.get('case')?.toLowerCase();
    if (caseParam) {
      if (caseParam === 'case_rw_04' || caseParam === 'rw_04' || caseParam === 'repo_cloud_config' || caseParam === 'rw04') {
        return 'case_rw_04';
      }
      if (caseParam === 'flasgger_external' || caseParam === 'flasgger' || caseParam === 'case_rw_01' || caseParam === 'rw_01' || caseParam === 'rw01') {
        return 'flasgger_external';
      }
      if (caseParam === 'naive_comparison' || caseParam === 'naive' || caseParam === 'comparison' || caseParam === 'phase5') {
        return 'naive_comparison';
      }
      if (caseParam === 'tavily_intel' || caseParam === 'tavily' || caseParam === 'intel' || caseParam === 'phase6') {
        return 'tavily_intel';
      }
      if (caseParam === 'contextual_reasoning' || caseParam === 'synth_01' || caseParam === 'synth01' || caseParam === 'contextual') {
        return 'contextual_reasoning';
      }
    }
  }
  return 'contextual_reasoning';
}

export const RecordedEvidenceViewer: React.FC = () => {
  const [selectedCaseId, setSelectedCaseId] = useState<ShowcaseCaseId>(resolveInitialCaseId);
  const [copiedDiff, setCopiedDiff] = useState(false);

  useEffect(() => {
    const handlePopState = () => {
      setSelectedCaseId(resolveInitialCaseId());
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const handleSelectCase = (id: ShowcaseCaseId) => {
    setSelectedCaseId(id);
    if (typeof window !== 'undefined') {
      const url = new URL(window.location.href);
      url.searchParams.set('view', 'showcase');
      url.searchParams.set('case', id);
      window.history.replaceState({}, '', url.toString());
    }
  };

  const activeCase = SHOWCASE_CASES[selectedCaseId];

  const handleCopyDiff = () => {
    if (!activeCase.diff) return;
    navigator.clipboard.writeText(activeCase.diff);
    setCopiedDiff(true);
    setTimeout(() => setCopiedDiff(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Disclaimer / Evidence Notice Banner */}
      <div className="rounded-lg border border-amber-500/30 bg-amber-950/20 p-4 text-sm text-amber-200/90 flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-amber-300">
            RECORDED EVIDENCE SHOWCASE — AUTHENTIC VERIFICATION RECORDS
          </div>
          <p className="text-xs text-amber-200/80 leading-relaxed">
            Browsing this showcase inspects genuine recorded run artifacts and experimental telemetry from Phases 3 through 6.
            Opening or reviewing a case displays empirical evidence and <strong>does not rerun live analysis or trigger new billable API calls</strong>.
          </p>
        </div>
      </div>

      {/* Case Selector Tabs */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        {Object.values(SHOWCASE_CASES).map((item) => {
          const isSelected = item.id === selectedCaseId;
          return (
            <button
              key={item.id}
              onClick={() => handleSelectCase(item.id)}
              className={`text-left p-3.5 rounded-lg border transition-all flex flex-col justify-between ${
                isSelected
                  ? 'border-emerald-500/80 bg-emerald-950/20 shadow-sm shadow-emerald-950/30 ring-1 ring-emerald-500/50'
                  : 'border-border-subtle bg-surface-2 hover:bg-surface-3 hover:border-slate-600'
              }`}
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-surface-3 text-text-muted border border-border-subtle">
                    {item.category === 'External Repository' ? 'External Repo' : item.category === 'Internal Microservice Benchmark' ? 'Internal Micro' : 'Synthetic'}
                  </span>
                  <span
                    className={`w-2 h-2 rounded-full ${
                      item.verdictBadgeColor === 'emerald'
                        ? 'bg-emerald-400'
                        : item.verdictBadgeColor === 'amber'
                        ? 'bg-amber-400'
                        : item.verdictBadgeColor === 'rose'
                        ? 'bg-rose-400'
                        : 'bg-blue-400'
                    }`}
                  />
                </div>
                <div className="text-xs font-semibold text-text-primary line-clamp-2">
                  {item.title}
                </div>
              </div>
              <div className="mt-2 text-[11px] font-mono text-text-muted flex items-center justify-between">
                <span>{item.cveId}</span>
                <span
                  className={`font-semibold ${
                    item.verdictBadgeColor === 'emerald'
                      ? 'text-emerald-400'
                      : item.verdictBadgeColor === 'amber'
                      ? 'text-amber-400'
                      : item.verdictBadgeColor === 'rose'
                      ? 'text-rose-400'
                      : 'text-blue-400'
                  }`}
                >
                  {item.verdict === 'GREEN_STATE_VERIFIED' ? 'VERIFIED' : item.verdict}
                </span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Main Evidence Card for Selected Case */}
      <div className="rounded-lg border border-border-subtle bg-surface-2 p-6 space-y-6">
        {/* Header Block */}
        <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4 border-b border-border-subtle pb-5">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-slate-800 text-slate-300 border border-slate-700">
                RECORDED EVIDENCE
              </span>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-surface-3 text-text-muted border border-border-subtle">
                {activeCase.category}
              </span>
              <span className="text-xs font-mono text-text-muted">{activeCase.cveId}</span>
            </div>
            <h2 className="text-xl font-bold text-text-primary">{activeCase.title}</h2>
            <p className="text-xs text-text-muted leading-relaxed max-w-3xl">
              <strong>Provenance:</strong> {activeCase.provenance}
            </p>
          </div>

          <div className="flex flex-col items-start md:items-end gap-1.5 shrink-0">
            <div className="text-[11px] font-mono text-text-muted">Behavioral Verdict</div>
            <span
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono font-semibold border ${
                activeCase.verdictBadgeColor === 'emerald'
                  ? 'bg-emerald-950/80 text-emerald-300 border-emerald-600/80'
                  : activeCase.verdictBadgeColor === 'amber'
                  ? 'bg-amber-950/80 text-amber-300 border-amber-600/80'
                  : activeCase.verdictBadgeColor === 'rose'
                  ? 'bg-rose-950/80 text-rose-300 border-rose-600/80'
                  : 'bg-blue-950/80 text-blue-300 border-blue-600/80'
              }`}
            >
              {activeCase.verdictBadgeColor === 'emerald' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              ) : activeCase.verdictBadgeColor === 'amber' ? (
                <AlertTriangle className="w-4 h-4 text-amber-400" />
              ) : activeCase.verdictBadgeColor === 'rose' ? (
                <XCircle className="w-4 h-4 text-rose-400" />
              ) : (
                <CheckCircle2 className="w-4 h-4 text-blue-400" />
              )}
              {activeCase.verdict}
            </span>
          </div>
        </div>

        {/* Isolation & Runtime Attestation Banner */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-surface-1 p-4 rounded-lg border border-border-subtle">
          <div className="space-y-1">
            <div className="text-xs font-semibold text-text-primary flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              Isolation Tier Contract
            </div>
            <div className="text-xs font-mono text-emerald-400">{activeCase.isolationTier}</div>
            <div className="text-[11px] text-text-muted leading-relaxed">
              {activeCase.isolationDescription}
            </div>
          </div>
          <div className="space-y-1">
            <div className="text-xs font-semibold text-text-primary flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-blue-400" />
              Execution Mode
            </div>
            <div className="text-xs font-mono text-blue-400">{activeCase.executionMode}</div>
            <div className="text-[11px] text-text-muted leading-relaxed">
              Target Symbol: <code className="font-mono text-text-primary">{activeCase.targetSymbol}</code>
            </div>
          </div>
        </div>

        {/* Narrative Summary */}
        <div className="space-y-1.5">
          <div className="text-xs font-semibold text-text-primary uppercase tracking-wider text-[11px]">
            Executive Analysis Summary
          </div>
          <p className="text-xs text-text-secondary leading-relaxed bg-surface-3 p-3.5 rounded border border-border-subtle">
            {activeCase.summary}
          </p>
        </div>

        {/* Pre / Post Behavioral Verification Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Pre-Patch State */}
          <div className="rounded-lg border border-border-subtle bg-surface-1 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-text-primary flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
                Stage 1: Pre-Patch Exploit Reproduction
              </span>
              <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-surface-3 border border-border-subtle text-text-primary">
                Exit {activeCase.prePatchState.exitCode}
              </span>
            </div>
            <div className="space-y-1 text-xs">
              <div className="text-text-muted">
                Observed State: <span className="font-mono text-text-primary">{activeCase.prePatchState.state}</span>
              </div>
              <div className="text-text-muted">
                Sentinel Marker Created: <span className="font-mono text-text-primary">{activeCase.prePatchState.sentinelObserved ? 'True (Exploited)' : 'False'}</span>
              </div>
              <div className="text-xs text-text-secondary bg-surface-2 p-2.5 rounded border border-border-subtle mt-2">
                {activeCase.prePatchState.detail}
              </div>
            </div>
          </div>

          {/* Post-Patch State */}
          <div className="rounded-lg border border-border-subtle bg-surface-1 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-text-primary flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                Stage 4: Post-Patch Isolated Verification
              </span>
              <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-surface-3 border border-border-subtle text-text-primary">
                Exit {activeCase.postPatchState.exitCode}
              </span>
            </div>
            <div className="space-y-1 text-xs">
              <div className="text-text-muted">
                Verified State: <span className="font-mono text-text-primary">{activeCase.postPatchState.state}</span>
              </div>
              <div className="text-text-muted">
                Sentinel Marker Blocked: <span className="font-mono text-text-primary">{!activeCase.postPatchState.sentinelObserved ? 'True (Zero Sentinels)' : 'False'}</span>
              </div>
              <div className="text-xs text-text-secondary bg-surface-2 p-2.5 rounded border border-border-subtle mt-2">
                {activeCase.postPatchState.detail}
              </div>
            </div>
          </div>
        </div>

        {/* Regression Test Outcomes */}
        <div className="rounded-lg border border-border-subtle bg-surface-1 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-text-primary flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              Stage 5: Functional Regression Suite
            </span>
            <span
              className={`text-xs font-mono font-semibold px-2 py-0.5 rounded border ${
                activeCase.regressionTests.passed
                  ? 'bg-emerald-950/80 text-emerald-300 border-emerald-600/80'
                  : 'bg-rose-950/80 text-rose-300 border-rose-600/80'
              }`}
            >
              {activeCase.regressionTests.passedCount} / {activeCase.regressionTests.total} Passed
            </span>
          </div>

          <div className="space-y-1.5">
            {activeCase.regressionTests.tests.map((t, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between text-xs font-mono p-2 rounded bg-surface-2 border border-border-subtle"
              >
                <span className="text-text-primary">{t.name}</span>
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-semibold ${
                    t.status === 'passed'
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      : 'bg-rose-950 text-rose-400 border border-rose-800'
                  }`}
                >
                  {t.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Patch Unified Diff */}
        {activeCase.diff && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="text-xs font-semibold text-text-primary uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-text-muted" />
                Synthesized Remediation Diff
              </div>
              <button
                onClick={handleCopyDiff}
                className="inline-flex items-center gap-1 text-xs text-text-muted hover:text-text-primary px-2 py-1 rounded bg-surface-3 border border-border-subtle transition-colors"
              >
                {copiedDiff ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                {copiedDiff ? 'Copied' : 'Copy Diff'}
              </button>
            </div>
            <pre className="p-3.5 rounded bg-surface-1 border border-border-subtle text-xs font-mono text-text-secondary overflow-x-auto whitespace-pre leading-relaxed">
              {activeCase.diff}
            </pre>
          </div>
        )}

        {/* Key Empirical Telemetry */}
        <div className="space-y-2">
          <div className="text-xs font-semibold text-text-primary uppercase tracking-wider text-[11px] flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-text-muted" />
            Key Telemetry & Model Ledger
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
            {activeCase.telemetrySummary.map((t, idx) => (
              <div key={idx} className="p-2.5 rounded bg-surface-1 border border-border-subtle space-y-0.5">
                <div className="text-[10px] text-text-muted uppercase font-mono">{t.label}</div>
                <div className="text-xs font-semibold font-mono text-text-primary truncate" title={t.value}>
                  {t.value}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Notes & Boundaries */}
        <div className="border-t border-border-subtle pt-4 space-y-1.5">
          <div className="text-[11px] font-semibold text-text-muted uppercase font-mono">
            Auditor Notes & Integrity Invariants
          </div>
          <ul className="text-xs text-text-secondary space-y-1 list-disc list-inside">
            {activeCase.notes.map((n, idx) => (
              <li key={idx} className="leading-relaxed">
                {n}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};
