import React from 'react';
import {
  LineChart,
  ShieldAlert,
  GitFork,
  ExternalLink,
  EyeOff,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  RefreshCw
} from 'lucide-react';
import { StudioAnalysis } from '../types';

interface StepAnalysisProps {
  analysis: StudioAnalysis | null;
  loading: boolean;
  error?: string;
  onRunAnalysis: () => void;
  onProceedToRequirements: () => void;
}

export const StepAnalysis: React.FC<StepAnalysisProps> = ({
  analysis,
  loading,
  error,
  onRunAnalysis,
  onProceedToRequirements
}) => {
  return (
    <section aria-labelledby="step-analysis-title" className="space-y-6">
      {/* Title & Navigation Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 id="step-analysis-title" className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <LineChart className="w-5 h-5 text-emerald-400" aria-hidden="true" />
            Step 2: Static Analysis, Reachability & Threat Intelligence
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            AST call-graph traversal, baseline test evaluation, and live Tavily threat intelligence (Spec §4.2, §4.3).
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onRunAnalysis}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-2 rounded bg-surface-3 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs font-mono border border-border-interactive transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
            <span>Re-run Analysis</span>
          </button>

          {analysis && (
            <button
              type="button"
              onClick={onProceedToRequirements}
              className="flex items-center gap-2 px-4 py-2 rounded bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-mono transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
            >
              <span>Proceed to Step 3: Requirements</span>
              <ArrowRight className="w-4 h-4" aria-hidden="true" />
            </button>
          )}
        </div>
      </div>

      {/* Loading State */}
      {loading && (
        <div
          role="status"
          aria-live="polite"
          className="rounded-lg border border-border-subtle bg-surface-2 p-12 flex flex-col items-center justify-center text-center space-y-3 min-h-[260px]"
        >
          <RefreshCw className="w-8 h-8 text-emerald-400 animate-spin" aria-hidden="true" />
          <span className="text-sm font-semibold text-slate-200">Executing Multi-File AST Traversal...</span>
          <span className="text-xs font-mono text-slate-400">
            Parsing function callers, tracing sinks to entrypoints, and querying OSV + Tavily intelligence.
          </span>
        </div>
      )}

      {/* Error State */}
      {error && !loading && (
        <div
          role="alert"
          aria-live="assertive"
          className="rounded-lg border border-rose-800/60 bg-rose-950/30 p-4 text-xs font-mono text-rose-200 space-y-2"
        >
          <div className="flex items-center gap-2 font-semibold text-rose-400">
            <AlertTriangle className="w-4 h-4 text-rose-500 shrink-0" aria-hidden="true" />
            <span>ANALYSIS ENGINE ERROR</span>
          </div>
          <p className="text-rose-300 font-sans">{error}</p>
          <button
            type="button"
            onClick={onRunAnalysis}
            className="px-3 py-1.5 rounded bg-rose-900/60 hover:bg-rose-900 text-rose-100 text-xs font-mono font-semibold border border-rose-700/60"
          >
            Retry Analysis
          </button>
        </div>
      )}

      {/* Empty State */}
      {!analysis && !loading && !error && (
        <div className="rounded-lg border border-dashed border-border-interactive bg-surface-2/40 p-12 flex flex-col items-center justify-center text-center space-y-3">
          <LineChart className="w-10 h-10 text-slate-500" aria-hidden="true" />
          <span className="text-sm font-semibold text-slate-300">No static analysis generated yet.</span>
          <p className="text-xs text-slate-400 max-w-md font-sans">
            Initiate the static analysis traversal to inspect function call graphs, establish baseline test stability,
            and correlate live threat intelligence advisories.
          </p>
          <button
            type="button"
            onClick={onRunAnalysis}
            className="px-4 py-2 rounded bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-mono transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            Run Static Analysis
          </button>
        </div>
      )}

      {/* Analysis Content View */}
      {analysis && !loading && (
        <div className="space-y-6">
          {/* Top Metric Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="rounded-lg border border-border-subtle bg-surface-2 p-3 space-y-1">
              <span className="text-[11px] font-mono text-slate-400 uppercase">REACHABILITY VERDICT</span>
              <div className="text-sm font-bold font-mono text-emerald-400 truncate">
                {analysis.reachability.verdict}
              </div>
            </div>

            <div className="rounded-lg border border-border-subtle bg-surface-2 p-3 space-y-1">
              <span className="text-[11px] font-mono text-slate-400 uppercase">ACTIVE VULNERABLE PATHS</span>
              <div className="text-sm font-bold font-mono text-rose-400">
                {analysis.reachability.reachable_paths_count} Call Site(s)
              </div>
            </div>

            <div className="rounded-lg border border-border-subtle bg-surface-2 p-3 space-y-1">
              <span className="text-[11px] font-mono text-slate-400 uppercase">BASELINE TEST SUITE</span>
              <div className="text-sm font-bold font-mono text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" aria-hidden="true" />
                <span>{analysis.baseline_tests.test_count} Passed</span>
                <span className="text-slate-500 text-xs">({analysis.baseline_tests.duration_ms.toFixed(0)}ms)</span>
              </div>
            </div>

            <div className="rounded-lg border border-border-subtle bg-surface-2 p-3 space-y-1">
              <span className="text-[11px] font-mono text-slate-400 uppercase">DEAD CODE / FALSE POSITIVES</span>
              <div className="text-sm font-bold font-mono text-slate-300">
                {analysis.reachability.unreachable_dead_code_count} Suppressed
              </div>
            </div>
          </div>

          {/* Section: Discovered Vulnerability Findings Table */}
          <div className="rounded-lg border border-border-subtle bg-surface-2 overflow-hidden space-y-0">
            <div className="px-4 py-3 border-b border-border-subtle bg-surface-1 flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-slate-200 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" aria-hidden="true" />
                DISCOVERED VULNERABLE SINK CALL SITES ({analysis.findings.length})
              </span>
              <span className="text-[11px] font-mono text-slate-400">Spec §4.2 AST Analysis</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-surface-inset text-slate-400 border-b border-border-subtle text-[11px]">
                  <tr>
                    <th scope="col" className="px-4 py-2">CVE</th>
                    <th scope="col" className="px-4 py-2">LOCATION</th>
                    <th scope="col" className="px-4 py-2">CALLER FUNCTION</th>
                    <th scope="col" className="px-4 py-2">DANGEROUS SINK</th>
                    <th scope="col" className="px-4 py-2">STATUS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle text-slate-300">
                  {analysis.findings.map((f, i) => (
                    <tr key={i} className="hover:bg-surface-3/40 transition-colors">
                      <td className="px-4 py-2.5 font-bold text-sky-400">{f.cve_id}</td>
                      <td className="px-4 py-2.5 text-slate-300">{f.file}:{f.line}</td>
                      <td className="px-4 py-2.5 text-amber-300">{f.caller}</td>
                      <td className="px-4 py-2.5 text-rose-300 font-semibold">{f.sink}</td>
                      <td className="px-4 py-2.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                          f.reachable
                            ? 'bg-rose-950/60 text-rose-300 border-rose-700/60'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}>
                          {f.reachable ? 'REACHABLE' : 'UNREACHABLE'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Section: Reachability Call Path Hierarchy (Cut-line Tree/List) */}
          <div className="rounded-lg border border-border-subtle bg-surface-2 p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-border-subtle pb-2">
              <span className="text-xs font-mono font-bold text-slate-200 flex items-center gap-2">
                <GitFork className="w-4 h-4 text-emerald-400" aria-hidden="true" />
                CALL-GRAPH REACHABILITY PATH HIERARCHY
              </span>
              <span className="text-[11px] font-mono text-slate-400">Spec §4.2 Trace</span>
            </div>

            <div className="space-y-2">
              {analysis.findings.map((f, idx) => (
                <div key={idx} className="rounded border border-border-interactive bg-surface-inset p-3 font-mono text-xs space-y-1.5">
                  <div className="flex items-center gap-2 text-slate-300 font-semibold">
                    <span className="w-2 h-2 rounded-full bg-rose-400" aria-hidden="true" />
                    <span>Path #{idx + 1}: Entrypoint &rarr; Vulnerable Sink Execution Chain</span>
                  </div>
                  <div className="pl-4 border-l-2 border-emerald-500/40 text-slate-300 space-y-1">
                    <div>1. Entrypoint: <span className="text-sky-300">{f.caller || 'main'}</span></div>
                    <div>2. Invocation: <span className="text-slate-200">{f.file}:{f.line}</span></div>
                    <div>3. Dangerous Sink: <span className="text-rose-400 font-bold">{f.sink}</span> (Target of surgical defense)</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Section: Tavily Threat Intelligence Sources & Blind Spots */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Tavily Threat Intel Sources */}
            <div className="rounded-lg border border-border-subtle bg-surface-2 p-4 space-y-3 flex flex-col justify-between">
              <div className="space-y-2">
                <div className="flex items-center justify-between border-b border-border-subtle pb-2">
                  <span className="text-xs font-mono font-bold text-slate-200 flex items-center gap-2">
                    <ExternalLink className="w-4 h-4 text-indigo-400" aria-hidden="true" />
                    TAVILY THREAT INTEL SOURCES ({analysis.intel.sources.length})
                  </span>
                  <span className="text-[11px] font-mono text-indigo-300">Live API</span>
                </div>
                <p className="text-xs text-slate-400 font-sans">{analysis.intel.summary}</p>
                <ul className="space-y-1.5 pt-1">
                  {analysis.intel.sources.map((src, i) => (
                    <li key={i} className="text-xs font-mono flex items-center justify-between gap-2 p-1.5 rounded bg-surface-inset border border-border-subtle">
                      <span className="text-slate-300 truncate">{src.title}</span>
                      <a
                        href={src.url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="text-sky-400 hover:text-sky-300 flex items-center gap-1 text-[11px] shrink-0 font-semibold"
                      >
                        <span>View</span>
                        <ExternalLink className="w-3 h-3" aria-hidden="true" />
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Blind Spots & Static Analysis Boundaries */}
            <div className="rounded-lg border border-border-subtle bg-surface-2 p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-border-subtle pb-2">
                <span className="text-xs font-mono font-bold text-slate-200 flex items-center gap-2">
                  <EyeOff className="w-4 h-4 text-amber-400" aria-hidden="true" />
                  STATIC ANALYSIS BLIND SPOTS & BOUNDARIES
                </span>
                <span className="text-[11px] font-mono text-amber-400">Spec §4.2 Limitations</span>
              </div>
              <p className="text-xs text-slate-400 font-sans">
                Static AST analysis cannot resolve non-deterministic or reflective dispatch patterns:
              </p>
              <ul className="space-y-1.5 text-xs font-mono text-slate-300">
                {analysis.reachability.blind_spots.map((spot, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-amber-400 font-bold">•</span>
                    <span>{spot}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};
