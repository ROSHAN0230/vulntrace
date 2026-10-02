import React, { useState, useEffect } from 'react';
import { FolderGit2, GitBranch, GitCommit, FileCode, AlertCircle, RefreshCw, Layers, CheckCircle2 } from 'lucide-react';
import { RepoInspectResponse, BenchmarkScenarioInfo } from '../types';

interface RepoSelectorProps {
  onInspect: (path: string) => Promise<void>;
  data: RepoInspectResponse | null;
  loading: boolean;
  error?: string;
  benchmarks?: BenchmarkScenarioInfo[];
  activeScenario?: BenchmarkScenarioInfo | null;
  onSelectScenario?: (sc: BenchmarkScenarioInfo) => void;
}

export const RepoSelector: React.FC<RepoSelectorProps> = ({
  onInspect,
  data,
  loading,
  error,
  benchmarks = [],
  activeScenario = null,
  onSelectScenario
}) => {
  const [repoPath, setRepoPath] = useState<string>(
    activeScenario?.repo_path || 'benchmarks/deep_callchain'
  );

  useEffect(() => {
    if (activeScenario) {
      setRepoPath(activeScenario.repo_path);
    }
  }, [activeScenario]);

  const handleScenarioClick = (sc: BenchmarkScenarioInfo) => {
    setRepoPath(sc.repo_path);
    if (onSelectScenario) {
      onSelectScenario(sc);
    }
    onInspect(sc.repo_path);
  };

  return (
    <div className="bg-surface-2 border border-border-subtle rounded-md p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <FolderGit2 className="w-4 h-4 text-sky-400" />
          <h2 className="text-sm font-semibold text-slate-200">Target Repository Inspection</h2>
        </div>
        <div className="text-[11px] font-mono text-slate-400">
          Source Manifests & Multi-File Benchmarks
        </div>
      </div>

      {/* Phase 3 Benchmark Scenario Quick Switcher */}
      {benchmarks.length > 0 && (
        <div className="mb-3.5 bg-surface-1/70 border border-border-subtle rounded p-2.5">
          <div className="text-[10px] font-mono uppercase text-slate-400 mb-1.5 flex items-center justify-between">
            <span className="flex items-center gap-1 font-semibold text-sky-400">
              <Layers className="w-3 h-3" /> Phase 3 Multi-Scenario Evaluation Benchmarks
            </span>
            <span className="text-slate-500">4 Real Isolated Codebases</span>
          </div>
          <div className="grid grid-cols-2 gap-1.5">
            {benchmarks.map((sc) => {
              const isActive = activeScenario?.id === sc.id || repoPath === sc.repo_path;
              return (
                <button
                  key={sc.id}
                  type="button"
                  onClick={() => handleScenarioClick(sc)}
                  className={`text-left p-1.5 rounded text-xs font-mono transition-all border ${
                    isActive
                      ? 'bg-sky-950/50 border-sky-500 text-sky-200 shadow-sm'
                      : 'bg-surface-inset border-border-subtle hover:border-slate-600 text-slate-300'
                  }`}
                >
                  <div className="font-semibold truncate flex items-center justify-between">
                    <span>{sc.name.split('(')[0].trim()}</span>
                    {isActive && <CheckCircle2 className="w-3 h-3 text-sky-400 shrink-0" />}
                  </div>
                  <div className="text-[10px] text-slate-400 truncate mt-0.5">
                    {sc.target_file}
                  </div>
                </button>
              );
            })}
          </div>
          {activeScenario && (
            <div className="mt-2 text-[11px] text-slate-400 font-mono bg-surface-inset/80 p-2 rounded border border-border-subtle">
              <span className="text-sky-300 font-semibold">{activeScenario.highlight}</span>
              <div className="mt-1 flex items-center gap-3 text-[10px] text-slate-400">
                <span>Target: <code className="text-amber-300">{activeScenario.target_file}:{activeScenario.target_function}()</code></span>
                <span>Expected: <span className="text-emerald-400 font-semibold">{activeScenario.expected_behavioral_verdict}</span></span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Path Input & Inspect Button */}
      <div className="flex gap-2 mb-4">
        <input
          type="text"
          value={repoPath}
          onChange={(e) => setRepoPath(e.target.value)}
          placeholder="Enter absolute directory path e.g. C:\AI-Tools\vulntrace\benchmarks\deep_callchain"
          className="flex-1 bg-surface-inset border border-border-interactive rounded px-3 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 transition-colors"
        />
        <button
          type="button"
          onClick={() => repoPath.trim() && onInspect(repoPath.trim())}
          disabled={loading}
          className="bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-slate-950 font-medium px-3.5 py-1.5 rounded text-xs flex items-center gap-1.5 transition-colors font-sans shadow-sm"
        >
          {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <FolderGit2 className="w-3.5 h-3.5" />}
          Inspect Codebase
        </button>
      </div>

      {error && (
        <div className="mb-3 px-3 py-2 rounded bg-rose-950/40 border border-rose-900/60 text-rose-300 text-xs flex items-center gap-2 font-mono">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {data && data.exists && (
        <div className="space-y-3">
          {/* Metadata Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
            <div className="bg-surface-1 border border-border-subtle p-2 rounded">
              <div className="text-slate-500 text-[10px] uppercase">Git Branch</div>
              <div className="flex items-center gap-1 text-slate-200 font-medium truncate">
                <GitBranch className="w-3 h-3 text-sky-400" />
                {data.git_branch || 'main (clean)'}
              </div>
            </div>
            <div className="bg-surface-1 border border-border-subtle p-2 rounded">
              <div className="text-slate-500 text-[10px] uppercase">Commit SHA</div>
              <div className="flex items-center gap-1 text-slate-200 font-medium truncate">
                <GitCommit className="w-3 h-3 text-indigo-400" />
                {data.git_commit || 'local-clean'}
              </div>
            </div>
            <div className="bg-surface-1 border border-border-subtle p-2 rounded">
              <div className="text-slate-500 text-[10px] uppercase">Python Files</div>
              <div className="flex items-center gap-1 text-slate-200 font-medium">
                <FileCode className="w-3 h-3 text-emerald-400" />
                {data.python_files_count} modules
              </div>
            </div>
            <div className="bg-surface-1 border border-border-subtle p-2 rounded">
              <div className="text-slate-500 text-[10px] uppercase">Manifests</div>
              <div className="text-slate-200 font-medium truncate">
                {data.manifest_files.join(', ') || 'requirements.txt'}
              </div>
            </div>
          </div>

          {/* Dependencies Table */}
          {data.dependencies.length > 0 && (
            <div className="border border-border-subtle rounded overflow-hidden">
              <div className="bg-surface-1 px-3 py-1.5 border-b border-border-subtle flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>DETECTED PACKAGES ({data.dependencies.length})</span>
                <span>ECOSYSTEM: PyPI / pip</span>
              </div>
              <div className="max-h-36 overflow-y-auto divide-y divide-border-subtle">
                {data.dependencies.map((dep, idx) => (
                  <div key={idx} className="px-3 py-1 text-xs font-mono flex items-center justify-between hover:bg-surface-3/40 transition-colors">
                    <span className="font-semibold text-slate-200">{dep.name}</span>
                    <div className="flex items-center gap-3">
                      <span className="text-sky-400">{dep.version_spec}</span>
                      <span className="text-[10px] text-slate-500 bg-surface-inset px-1.5 py-0.5 rounded border border-border-subtle">
                        {dep.manifest_source}
                      </span>
                    </div>
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
