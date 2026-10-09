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
    <section aria-labelledby="step-analysis-title" className="space-y-5">
      {/* Title & Navigation Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 id="step-analysis-title" className="text-base font-bold text-slate-100 flex items-center gap-2 font-sans">
            <LineChart className="w-5 h-5 text-emerald-400" aria-hidden="true" />
            Step 2: Static Analysis, Reachability &amp; Threat Intelligence
          </h2>
          <p className="text-xs text-slate-400 font-sans mt-0.5">
            AST call-graph traversal, baseline test evaluation, and live Tavily threat intelligence (Spec §4.2, §4.3).
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onRunAnalysis}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-surface-3 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs font-sans font-medium border border-border-interactive transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
            <span>Re-run Analysis</span>
          </button>

          {analysis && (
            <button
              type="button"
              onClick={onProceedToRequirements}
              className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-sans transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
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
          className="rounded-lg border border-border-subtle bg-surface-2 p-10 flex flex-col items-center justify-center text-center space-y-3 min-h-[240px]"
        >
          <RefreshCw className="w-8 h-8 text-emerald-400 animate-spin" aria-hidden="true" />
          <span className="text-sm font-semibold text-slate-200 font-sans">Executing Multi-File AST Traversal...</span>
          <span className="text-xs font-sans text-slate-400 max-w-md">
            Parsing function callers, tracing sinks to entrypoints, and querying OSV + Tavily intelligence.
          </span>
        </div>
      )}

      {/* Error State */}
      {error && !loading && (
        <div
          role="alert"
          aria-live="assertive"
          className="rounded-lg border border-rose-800/60 bg-rose-950/30 p-4 text-xs text-rose-200 space-y-2"
        >
          <div className="flex items-center gap-2 font-semibold text-rose-400 font-sans">
            <AlertTriangle className="w-4 h-4 text-rose-500 shrink-0" aria-hidden="true" />
            <span>Analysis Engine Error</span>
          </div>
          <p className="text-rose-300 font-sans">{error}</p>
          <button
            type="button"
            onClick={onRunAnalysis}
            className="px-3 py-1.5 rounded-md bg-rose-900/60 hover:bg-rose-900 text-rose-100 text-xs font-sans font-semibold border border-rose-700/60 transition-colors"
          >
            Retry Analysis
          </button>
        </div>
      )}

      {/* Empty State */}
      {!analysis && !loading && !error && (
        <div className="rounded-lg border border-dashed border-border-interactive bg-surface-2/40 p-10 flex flex-col items-center justify-center text-center space-y-3">
          <LineChart className="w-10 h-10 text-slate-500" aria-hidden="true" />
          <span className="text-sm font-semibold text-slate-300 font-sans">No static analysis generated yet.</span>
          <p className="text-xs text-slate-400 max-w-md font-sans">
            Initiate the static analysis traversal to inspect function call graphs, establish baseline test stability,
            and correlate live threat intelligence advisories.
          </p>
          <button
            type="button"
            onClick={onRunAnalysis}
            className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-sans transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            Run Static Analysis
          </button>
        </div>
      )}

      {/* Analysis Content View */}
      {analysis && !loading && (
        <div className="space-y-5">
          {/* Top Metric Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="rounded-lg border border-border-subtle bg-surface-2 p-3 space-y-1">
              <span className="text-[11px] font-sans font-medium text-slate-400 uppercase tracking-wide">
                Reachability Verdict
              </span>
              <div className="text-sm font-bold font-mono text-emerald-400 truncate" title={analysis.reachability.verdict}>
                {analysis.reachability.verdict}
              </div>
            </div>

            <div className="rounded-lg border border-border-subtle bg-surface-2 p-3 space-y-1">
              <span className="text-[11px] font-sans font-medium text-slate-400 uppercase tracking-wide">
                Active Vulnerable Paths
              </span>
              <div className="text-sm font-bold font-mono text-rose-400">
                {analysis.reachability.reachable_paths_count} Call Site(s)
              </div>
            </div>

            <div className="rounded-lg border border-border-subtle bg-surface-2 p-3 space-y-1">
              <span className="text-[11px] font-sans font-medium text-slate-400 uppercase tracking-wide">
                Baseline Test Suite
              </span>
              <div className="text-sm font-bold font-mono text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" aria-hidden="true" />
                <span>{analysis.baseline_tests.test_count} Passed</span>
                <span className="text-slate-500 text-xs font-normal font-sans">({analysis.baseline_tests.duration_ms.toFixed(0)}ms)</span>
              </div>
            </div>

            <div className="rounded-lg border border-border-subtle bg-surface-2 p-3 space-y-1">
              <span className="text-[11px] font-sans font-medium text-slate-400 uppercase tracking-wide">
                Dead Code / False Positives
              </span>
              <div className="text-sm font-bold font-mono text-slate-300">
                {analysis.reachability.unreachable_dead_code_count} Suppressed
              </div>
            </div>
          </div>

          {/* Section: Discovered Vulnerability Findings Table */}
          <div className="rounded-lg border border-border-subtle bg-surface-2 overflow-hidden">
            <div className="px-4 py-2.5 border-b border-border-subtle bg-surface-1 flex items-center justify-between">
              <span className="text-xs font-sans font-bold text-slate-200 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" aria-hidden="true" />
                Discovered Vulnerable Sink Call Sites ({analysis.findings.length})
              </span>
              <span className="text-[11px] font-mono text-slate-400">Spec §4.2 AST Analysis</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-surface-inset text-slate-400 border-b border-border-subtle text-[11px] font-sans">
                  <tr>
                    <th scope="col" className="px-4 py-2 font-semibold">CVE</th>
                    <th scope="col" className="px-4 py-2 font-semibold">Location</th>
                    <th scope="col" className="px-4 py-2 font-semibold">Caller Function</th>
                    <th scope="col" className="px-4 py-2 font-semibold">Dangerous Sink</th>
                    <th scope="col" className="px-4 py-2 font-semibold">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle text-slate-300">
                  {analysis.findings.map((f, i) => (
                    <tr key={i} className="hover:bg-surface-3/30 transition-colors">
                      <td className="px-4 py-2.5 font-bold text-sky-400 whitespace-nowrap">{f.cve_id}</td>
                      <td className="px-4 py-2.5 text-slate-300 whitespace-nowrap">
                        <span className="break-all" title={`${f.file}:${f.line}`}>{f.file}:{f.line}</span>
                      </td>
                      <td className="px-4 py-2.5 text-amber-300">
                        <span className="break-all font-mono" title={f.caller}>{f.caller}</span>
                      </td>
                      <td className="px-4 py-2.5 text-rose-300 font-semibold">
                        <span className="break-all font-mono" title={f.sink}>{f.sink}</span>
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${
                            f.reachable
                              ? 'bg-rose-950/70 text-rose-300 border-rose-700/70'
                              : 'bg-slate-800 text-slate-300 border-slate-700'
                          }`}
                        >
                          <span className={`w-1.5 h-1.5 rounded-full ${f.reachable ? 'bg-rose-400' : 'bg-slate-400'}`} aria-hidden="true" />
                          {f.reachable ? 'REACHABLE' : 'UNREACHABLE'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Section: Reachability Call Path Hierarchy (AST Call Tree) */}
          <div className="rounded-lg border border-border-subtle bg-surface-2 p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-border-subtle pb-2">
              <span className="text-xs font-sans font-bold text-slate-200 flex items-center gap-2">
                <GitFork className="w-4 h-4 text-emerald-400" aria-hidden="true" />
                Call-Graph Reachability Path Hierarchy
              </span>
              <span className="text-[11px] font-mono text-slate-400">Spec §4.2 Trace</span>
            </div>

            <div className="space-y-2.5">
              {analysis.findings.map((f, idx) => (
                <div key={idx} className="rounded-lg border border-border-interactive bg-surface-inset p-3.5 font-mono text-xs space-y-2">
                  <div className="flex items-center justify-between text-slate-300 font-sans">
                    <span className="font-semibold text-xs flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-rose-400" aria-hidden="true" />
                      Execution Chain #{idx + 1}: Public Entrypoint &rarr; Vulnerable Sink
                    </span>
                    <span className="text-[11px] font-mono text-slate-400">
                      {f.reachable ? 'Reachable from Entrypoint' : 'Dead Code / Guarded'}
                    </span>
                  </div>

                  <div className="pl-4 border-l-2 border-emerald-500/50 space-y-1.5 text-xs">
                    <div className="flex items-baseline gap-2">
                      <span className="text-[10px] font-sans font-semibold text-sky-400 bg-sky-950/60 px-1.5 py-0.5 rounded border border-sky-800/60 shrink-0">
                        ENTRYPOINT
                      </span>
                      <span className="text-sky-300 font-mono break-all" title={f.caller || 'main'}>
                        {f.caller || 'main'}
                      </span>
                    </div>

                    <div className="flex items-baseline gap-2">
                      <span className="text-[10px] font-sans font-semibold text-slate-300 bg-slate-800 px-1.5 py-0.5 rounded border border-slate-700 shrink-0">
                        CALL SITE
                      </span>
                      <span className="text-slate-300 font-mono break-all" title={`${f.file}:${f.line}`}>
                        {f.file}:{f.line}
                      </span>
                    </div>

                    <div className="flex items-baseline gap-2">
                      <span className="text-[10px] font-sans font-semibold text-rose-300 bg-rose-950/70 px-1.5 py-0.5 rounded border border-rose-800/70 shrink-0">
                        SINK (TARGET)
                      </span>
                      <span className="text-rose-400 font-bold font-mono break-all" title={f.sink}>
                        {f.sink}
                      </span>
                      <span className="text-[11px] font-sans text-slate-400">(Subject to surgical patch)</span>
                    </div>
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
                  <span className="text-xs font-sans font-bold text-slate-200 flex items-center gap-2">
                    <ExternalLink className="w-4 h-4 text-indigo-400" aria-hidden="true" />
                    Tavily Threat Intel Sources ({analysis.intel.sources.length})
                  </span>
                  <span className="text-[11px] font-mono text-indigo-300">Live API</span>
                </div>
                <p className="text-xs text-slate-400 font-sans leading-relaxed">{analysis.intel.summary}</p>
                <ul className="space-y-1.5 pt-1">
                  {analysis.intel.sources.map((src, i) => (
                    <li key={i} className="text-xs font-sans flex items-center justify-between gap-2 p-2 rounded-md bg-surface-inset border border-border-subtle">
                      <span className="text-slate-300 truncate font-medium" title={src.title}>{src.title}</span>
                      <a
                        href={src.url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="text-sky-400 hover:text-sky-300 flex items-center gap-1 text-[11px] shrink-0 font-medium transition-colors"
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
                <span className="text-xs font-sans font-bold text-slate-200 flex items-center gap-2">
                  <EyeOff className="w-4 h-4 text-amber-400" aria-hidden="true" />
                  Static Analysis Blind Spots &amp; Boundaries
                </span>
                <span className="text-[11px] font-mono text-amber-400">Spec §4.2 Limitations</span>
              </div>
              <p className="text-xs text-slate-400 font-sans leading-relaxed">
                Static AST analysis cannot resolve non-deterministic or reflective dispatch patterns:
              </p>
              <ul className="space-y-1.5 text-xs text-slate-300 font-sans">
                {analysis.reachability.blind_spots.map((spot, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-amber-400 font-bold shrink-0">•</span>
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
