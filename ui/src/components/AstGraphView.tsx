import React from 'react';
import { GitGraph, AlertTriangle, CheckCircle2, FileCode, ArrowRight, ShieldAlert, RefreshCw } from 'lucide-react';
import { AstAnalyzeResponse } from '../types';

interface AstGraphViewProps {
  onAnalyze: () => Promise<void>;
  data: AstAnalyzeResponse | null;
  loading: boolean;
  error?: string;
}

export const AstGraphView: React.FC<AstGraphViewProps> = ({ onAnalyze, data, loading, error }) => {
  return (
    <div className="bg-surface-2 border border-border-subtle rounded-md p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <GitGraph className="w-4 h-4 text-violet-400" />
          <h2 className="text-sm font-semibold text-slate-200">AST Static Reachability Engine</h2>
        </div>
        <button
          onClick={onAnalyze}
          disabled={loading}
          className="bg-violet-600 hover:bg-violet-500 disabled:opacity-50 text-white font-medium px-3 py-1 rounded text-xs flex items-center gap-1.5 transition-colors font-sans shadow-sm"
        >
          {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <GitGraph className="w-3.5 h-3.5" />}
          Run Call-Graph Solver
        </button>
      </div>

      {error && (
        <div className="mb-3 px-3 py-2 rounded bg-rose-950/40 border border-rose-900/60 text-rose-300 text-xs flex items-center gap-2 font-mono">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {data && (
        <div className="space-y-4">
          {/* Verdict Banner */}
          <div className={`p-3 rounded border flex items-center justify-between font-mono text-xs ${
            (data.verdict === 'REACHABLE_CALL_PATH_IDENTIFIED' || data.verdict === 'REACHABLE_CONFIRMED')
              ? 'bg-amber-950/40 border-amber-700/60 text-amber-300'
              : data.verdict === 'UNREACHABLE_FALSE_POSITIVE'
              ? 'bg-emerald-950/40 border-emerald-600/60 text-emerald-300'
              : 'bg-surface-1 border-border-subtle text-slate-300'
          }`}>
            <div className="flex items-center gap-2.5">
              {(data.verdict === 'REACHABLE_CALL_PATH_IDENTIFIED' || data.verdict === 'REACHABLE_CONFIRMED') ? (
                <ShieldAlert className="w-5 h-5 text-amber-400" />
              ) : data.verdict === 'UNREACHABLE_FALSE_POSITIVE' ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              ) : (
                <FileCode className="w-5 h-5 text-slate-400" />
              )}
              <div>
                <div className="font-bold tracking-wider text-sm">
                  {(data.verdict === 'REACHABLE_CALL_PATH_IDENTIFIED' || data.verdict === 'REACHABLE_CONFIRMED') && 'REACHABLE VULNERABLE CALL PATH IDENTIFIED'}
                  {data.verdict === 'UNREACHABLE_FALSE_POSITIVE' && 'FALSE POSITIVE: VULNERABILITY UNREACHABLE'}
                  {data.verdict === 'NO_VULNERABILITIES_FOUND' && 'NO TARGET VULNERABLE SYMBOLS DISCOVERED'}
                </div>
                <div className="text-[11px] opacity-80">
                  {data.reachable_vulnerabilities_count} reachable call path(s) • {data.unreachable_dead_code_count} dead code isolation(s) • Static AST analysis ({data.latency_ms}ms)
                </div>
              </div>
            </div>
            <div className="text-right">
              <span className="text-[10px] uppercase tracking-widest px-2 py-0.5 rounded bg-surface-inset border border-border-subtle">
                {data.analyzed_files.length} MODULES ANALYZED
              </span>
            </div>
          </div>

          {/* Discovered Vulnerable Call Sites */}
          {data.discovered_calls.length > 0 && (
            <div className="border border-border-subtle rounded overflow-hidden">
              <div className="bg-surface-1 px-3 py-1.5 border-b border-border-subtle text-[11px] font-mono text-slate-400 flex items-center justify-between">
                <span>VULNERABLE CALL-SITE TRACES</span>
                <span>ENTRYPOINT → CALL PATH</span>
              </div>
              <div className="divide-y divide-border-subtle text-xs font-mono">
                {data.discovered_calls.map((call, idx) => (
                  <div key={idx} className="p-3 bg-surface-2/60 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          call.reachable
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                            : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        }`}>
                          {call.reachable ? 'REACHABLE (HIGH RISK)' : 'DEAD CODE (ZERO RISK)'}
                        </span>
                        <span className="text-slate-200 font-semibold">{call.function_name}()</span>
                        <span className="text-slate-500 text-[11px]">→ {call.call_name}</span>
                      </div>
                      <span className="text-[10px] text-slate-400">{call.file}:{call.line_number}</span>
                    </div>

                    {/* Execution Call Path */}
                    {call.call_path_from_entrypoint.length > 0 && (
                      <div className="bg-surface-inset p-2 rounded border border-border-subtle flex items-center gap-1.5 text-[11px] overflow-x-auto text-slate-300">
                        <span className="text-slate-500 text-[10px] uppercase shrink-0">Path:</span>
                        {call.call_path_from_entrypoint.map((step, sIdx) => (
                          <React.Fragment key={sIdx}>
                            <span className={`px-1 rounded ${sIdx === call.call_path_from_entrypoint.length - 1 ? 'text-rose-400 font-bold' : 'text-slate-300'}`}>
                              {step}
                            </span>
                            {sIdx < call.call_path_from_entrypoint.length - 1 && (
                              <ArrowRight className="w-3 h-3 text-slate-600 shrink-0" />
                            )}
                          </React.Fragment>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Visual Call-Graph Topology Matrix */}
          {data.nodes.length > 0 && (
            <div className="border border-border-subtle rounded overflow-hidden">
              <div className="bg-surface-1 px-3 py-1.5 border-b border-border-subtle text-[11px] font-mono text-slate-400 flex items-center justify-between">
                <span>CALL-GRAPH TOPOLOGY NODES ({data.nodes.length})</span>
                <span>DIRECTED EDGES: {data.edges.length}</span>
              </div>
              <div className="p-3 bg-surface-inset max-h-52 overflow-y-auto font-mono text-xs">
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {data.nodes.map((node) => {
                    let borderClass = 'border-border-subtle bg-surface-1 text-slate-300';
                    let tagClass = 'bg-surface-2 text-slate-400';

                    if (node.node_type === 'VULNERABLE_CALL') {
                      borderClass = 'border-rose-500/60 bg-rose-950/20 text-rose-200';
                      tagClass = 'bg-rose-900/60 text-rose-300';
                    } else if (node.node_type === 'DEAD_CODE') {
                      borderClass = 'border-amber-600/40 bg-amber-950/20 text-amber-200';
                      tagClass = 'bg-amber-900/60 text-amber-300';
                    } else if (node.node_type === 'ENTRYPOINT') {
                      borderClass = 'border-sky-500/60 bg-sky-950/20 text-sky-200';
                      tagClass = 'bg-sky-900/60 text-sky-300';
                    }

                    return (
                      <div key={node.id} className={`p-2 rounded border ${borderClass} flex flex-col justify-between gap-1`}>
                        <div className="flex items-center justify-between">
                          <span className="font-semibold truncate">{node.label}</span>
                          <span className={`text-[9px] px-1 py-0.5 rounded font-bold uppercase ${tagClass}`}>
                            {node.node_type}
                          </span>
                        </div>
                        <div className="text-[10px] text-slate-500 truncate">
                          {node.file}:{node.line_number}
                        </div>
                        {node.vulnerability_details && (
                          <div className="text-[10px] text-rose-400 truncate mt-0.5">
                            Target: {node.vulnerability_details}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
