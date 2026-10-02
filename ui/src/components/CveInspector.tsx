import React, { useState } from 'react';
import { ShieldAlert, ExternalLink, Search, RefreshCw, AlertCircle, Link2, GitFork } from 'lucide-react';
import { CveQueryResponse } from '../types';

interface CveInspectorProps {
  onQuery: (cveId: string) => Promise<void>;
  data: CveQueryResponse | null;
  loading: boolean;
  error?: string;
}

export const CveInspector: React.FC<CveInspectorProps> = ({ onQuery, data, loading, error }) => {
  const [cveId, setCveId] = useState<string>('CVE-2020-14343');

  return (
    <div className="bg-surface-2 border border-border-subtle rounded-md p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-rose-400" />
          <h2 className="text-sm font-semibold text-slate-200">Vulnerability Threat Intelligence</h2>
        </div>
        <div className="text-[11px] font-mono text-slate-400">
          OSV.dev REST + Tavily PoC Discovery
        </div>
      </div>

      <div className="flex gap-2 mb-4">
        <input
          type="text"
          value={cveId}
          onChange={(e) => setCveId(e.target.value)}
          placeholder="Enter CVE ID e.g. CVE-2020-14343"
          className="flex-1 bg-surface-inset border border-border-interactive rounded px-3 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-rose-500 transition-colors uppercase"
        />
        <button
          type="button"
          onClick={() => cveId.trim() && onQuery(cveId.trim())}
          disabled={loading}
          className="bg-rose-500 hover:bg-rose-400 disabled:opacity-50 text-white font-medium px-3.5 py-1.5 rounded text-xs flex items-center gap-1.5 transition-colors font-sans shadow-sm"
        >
          {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
          Query Intelligence
        </button>
      </div>

      {error && (
        <div className="mb-3 px-3 py-2 rounded bg-rose-950/40 border border-rose-900/60 text-rose-300 text-xs flex items-center gap-2 font-mono">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {data && data.found && (
        <div className="space-y-3">
          {/* Header Card */}
          <div className="bg-surface-1 border border-border-subtle p-3 rounded space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold font-mono text-rose-400">{data.cve_id}</span>
                {data.aliases.map((al, idx) => (
                  <span key={idx} className="text-[10px] font-mono bg-surface-3 px-1.5 py-0.5 rounded text-slate-300 border border-border-subtle">
                    {al}
                  </span>
                ))}
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono text-slate-400">{data.latency_ms}ms</span>
                <a
                  href={data.source_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1"
                >
                  OSV Record <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed font-sans">{data.summary}</p>
          </div>

          {/* Affected Package Ranges */}
          {data.affected_packages.length > 0 && (
            <div className="border border-border-subtle rounded overflow-hidden">
              <div className="bg-surface-1 px-3 py-1.5 border-b border-border-subtle text-[11px] font-mono text-slate-400 flex items-center justify-between">
                <span>AFFECTED REPOSITORIES & COMMIT RANGES</span>
                <span>GIT COMMITS</span>
              </div>
              <div className="divide-y divide-border-subtle text-xs font-mono">
                {data.affected_packages.map((pkg, idx) => (
                  <div key={idx} className="p-2.5 bg-surface-2/60">
                    <div className="font-semibold text-slate-200 mb-1 flex items-center justify-between">
                      <span className="text-sky-300">{pkg.package_name}</span>
                      <span className="text-[10px] text-slate-500">{pkg.ecosystem}</span>
                    </div>
                    {pkg.ranges.map((rng, rIdx) => (
                      <div key={rIdx} className="text-[11px] text-slate-400 pl-2 border-l border-border-interactive space-y-0.5">
                        {rng.repo && (
                          <div className="flex items-center gap-1 truncate text-slate-300">
                            <GitFork className="w-3 h-3 text-slate-500" />
                            {rng.repo}
                          </div>
                        )}
                        <div className="flex gap-4 text-[10px]">
                          {rng.introduced && <span>Introduced: <span className="text-amber-400">{rng.introduced.slice(0, 10)}</span></span>}
                          {rng.fixed && <span>Fixed: <span className="text-emerald-400">{rng.fixed.slice(0, 10)}</span></span>}
                        </div>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tavily PoC Findings */}
          {data.pocs.length > 0 && (
            <div className="border border-border-subtle rounded overflow-hidden">
              <div className="bg-surface-1 px-3 py-1.5 border-b border-border-subtle text-[11px] font-mono text-indigo-400 flex items-center justify-between">
                <span>TAVILY LIVE EXPLOIT POC & ADVISORY FINDINGS ({data.pocs.length})</span>
                <span>REAL-TIME RETRIEVAL</span>
              </div>
              <div className="divide-y divide-border-subtle text-xs">
                {data.pocs.map((poc, idx) => (
                  <div key={idx} className="p-2.5 hover:bg-surface-3/30 transition-colors">
                    <a
                      href={poc.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-medium text-sky-400 hover:underline flex items-center gap-1.5 truncate mb-1"
                    >
                      <Link2 className="w-3.5 h-3.5 shrink-0 text-slate-500" />
                      {poc.title}
                    </a>
                    <p className="text-[11px] text-slate-400 leading-snug line-clamp-2">{poc.snippet}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
