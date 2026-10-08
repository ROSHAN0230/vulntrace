import React, { useState } from 'react';
import {
  FolderGit2,
  Github,
  Upload,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  FileArchive,
  RefreshCw
} from 'lucide-react';
import { BenchmarkScenarioInfo, StudioRun } from '../types';

interface StepSourceProps {
  benchmarks: BenchmarkScenarioInfo[];
  currentRun: StudioRun | null;
  loading: boolean;
  error?: string;
  onSelectBenchmark: (scenario: BenchmarkScenarioInfo) => void;
  onSubmitGithubUrl: (url: string, cveId: string) => void;
  onSubmitZipUpload: (file: File, cveId: string) => void;
  onProceedToAnalysis: () => void;
}

export const StepSource: React.FC<StepSourceProps> = ({
  benchmarks,
  currentRun,
  loading,
  error,
  onSelectBenchmark,
  onSubmitGithubUrl,
  onSubmitZipUpload,
  onProceedToAnalysis
}) => {
  const [tab, setTab] = useState<'curated' | 'github' | 'upload'>('curated');
  const [githubUrl, setGithubUrl] = useState('');
  const [cveId, setCveId] = useState('CVE-2020-14343');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const handleGithubSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!githubUrl.trim()) return;
    onSubmitGithubUrl(githubUrl.trim(), cveId.trim());
  };

  const handleZipSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) return;
    onSubmitZipUpload(selectedFile, cveId.trim());
  };

  return (
    <section aria-labelledby="step-source-title" className="space-y-6">
      {/* Title & Safety Notice */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 id="step-source-title" className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <FolderGit2 className="w-5 h-5 text-emerald-400" aria-hidden="true" />
            Step 1: Target Repository Intake & Disposable Workspace
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Provision an isolated workspace bounded by Ingest Security Guards (Spec §4.1, §4.14).
          </p>
        </div>

        {currentRun && (
          <button
            type="button"
            onClick={onProceedToAnalysis}
            className="flex items-center gap-2 px-4 py-2 rounded bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-mono transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            <span>Proceed to Step 2: Analysis</span>
            <ArrowRight className="w-4 h-4" aria-hidden="true" />
          </button>
        )}
      </div>

      {/* Safety Notice Banner */}
      <div className="rounded-lg border border-sky-800/40 bg-sky-950/20 p-4 text-xs font-mono text-sky-200/90 space-y-2">
        <div className="flex items-center gap-2 font-semibold text-sky-300">
          <ShieldCheck className="w-4 h-4 text-sky-400 shrink-0" aria-hidden="true" />
          <span>PLATFORM ISOLATION & INGEST SECURITY BOUNDARY</span>
        </div>
        <p className="text-slate-300 leading-relaxed font-sans text-xs">
          Target repository code executes exclusively within an ephemeral, disposable sandbox workspace.
          Ingest guards scrub ambient credentials, enforce max upload size (50MB) and file count (10,000),
          block Zip-Slip directory traversals, disable Git hooks and submodules, and deny host filesystem tampering.
        </p>
        <div className="flex flex-wrap gap-4 text-[11px] text-sky-400/80 pt-1">
          <span>• Network Policy: NONE during verification</span>
          <span>• Root Filesystem: READ-ONLY</span>
          <span>• Scratch: Disposable tmpfs</span>
        </div>
      </div>

      {/* Intake Method Tabs */}
      <div className="flex items-center gap-2 border-b border-border-subtle pb-2">
        <button
          type="button"
          onClick={() => setTab('curated')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono transition-all ${
            tab === 'curated'
              ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldCheck className="w-4 h-4" aria-hidden="true" />
          <span>Curated Benchmarks (1-Click)</span>
        </button>

        <button
          type="button"
          onClick={() => setTab('github')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono transition-all ${
            tab === 'github'
              ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Github className="w-4 h-4" aria-hidden="true" />
          <span>Public GitHub HTTPS Repo</span>
        </button>

        <button
          type="button"
          onClick={() => setTab('upload')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono transition-all ${
            tab === 'upload'
              ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Upload className="w-4 h-4" aria-hidden="true" />
          <span>Safe ZIP Archive Upload</span>
        </button>
      </div>

      {/* Loading State */}
      {loading && (
        <div
          role="status"
          aria-live="polite"
          className="rounded-lg border border-border-subtle bg-surface-2 p-8 flex flex-col items-center justify-center text-center space-y-3 min-h-[220px]"
        >
          <RefreshCw className="w-8 h-8 text-emerald-400 animate-spin" aria-hidden="true" />
          <span className="text-sm font-semibold text-slate-200">Provisioning Disposable Workspace...</span>
          <span className="text-xs font-mono text-slate-400">
            Running Ingest Guards, scrubbing ambient credentials, and locking filesystem bounds.
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
            <span>INGEST SECURITY GUARD VIOLATION / PROVISIONING ERROR</span>
          </div>
          <p className="text-rose-300 font-sans">{error}</p>
          <p className="text-[11px] text-slate-400">
            Check repository URL permissions, scheme (HTTPS only), or archive safety constraints.
          </p>
        </div>
      )}

      {/* Tab 1: Curated Benchmark Scenarios */}
      {tab === 'curated' && !loading && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase">
              SELECT FROM {benchmarks.length} REAL MULTI-FILE VULNERABILITY BENCHMARKS:
            </span>
            <span className="text-[11px] font-mono text-emerald-400">
              Deterministic cassettes & verified oracles
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {benchmarks.map((b) => {
              const isSelected = currentRun?.cve_id === b.cve_id;
              return (
                <div
                  key={b.id}
                  className={`rounded-lg border p-4 transition-all flex flex-col justify-between gap-3 text-left ${
                    isSelected
                      ? 'border-emerald-500/80 bg-emerald-950/20 shadow-sm'
                      : 'border-border-subtle bg-surface-2 hover:border-slate-600'
                  }`}
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-slate-800 text-sky-300 border border-slate-700">
                        {b.cve_id}
                      </span>
                      {isSelected && (
                        <span className="flex items-center gap-1 text-[11px] font-mono font-semibold text-emerald-400">
                          <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
                          ACTIVE
                        </span>
                      )}
                    </div>
                    <h3 className="text-sm font-bold text-slate-100">{b.name}</h3>
                    <p className="text-xs text-slate-400 line-clamp-2">{b.description}</p>
                  </div>

                  <div className="space-y-2 pt-2 border-t border-border-subtle/60 text-[11px] font-mono text-slate-400">
                    <div>Target: <span className="text-slate-300">{b.target_file}::{b.target_function}</span></div>
                    <div>Oracle: <span className="text-amber-300">{b.highlight}</span></div>

                    <button
                      type="button"
                      onClick={() => onSelectBenchmark(b)}
                      className={`w-full py-1.5 px-3 rounded text-xs font-mono font-semibold transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 ${
                        isSelected
                          ? 'bg-emerald-500 text-slate-950 hover:bg-emerald-400'
                          : 'bg-surface-3 text-slate-200 hover:bg-surface-3/80 border border-border-subtle'
                      }`}
                    >
                      {isSelected ? 'Provisioned & Ready' : 'Load Benchmark Scenario'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Tab 2: Public GitHub HTTPS URL */}
      {tab === 'github' && !loading && (
        <form onSubmit={handleGithubSubmit} className="rounded-lg border border-border-subtle bg-surface-2 p-6 space-y-4 max-w-2xl">
          <div className="space-y-1">
            <label htmlFor="github-url-input" className="block text-xs font-mono font-semibold text-slate-200">
              PUBLIC GITHUB REPOSITORY HTTPS URL:
            </label>
            <input
              id="github-url-input"
              type="url"
              required
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
              placeholder="https://github.com/owner/repository.git"
              className="w-full px-3 py-2 rounded bg-surface-inset border border-border-interactive text-slate-100 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
            />
            <span className="text-[11px] text-slate-400 font-mono">
              Cloned with `--depth 1`, `core.hooksPath=NUL`, and zero ambient credentials.
            </span>
          </div>

          <div className="space-y-1">
            <label htmlFor="github-cve-input" className="block text-xs font-mono font-semibold text-slate-200">
              TARGET CVE ADVISORY IDENTIFIER:
            </label>
            <input
              id="github-cve-input"
              type="text"
              required
              value={cveId}
              onChange={(e) => setCveId(e.target.value)}
              placeholder="CVE-2020-14343"
              className="w-full px-3 py-2 rounded bg-surface-inset border border-border-interactive text-slate-100 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
            />
          </div>

          <button
            type="submit"
            disabled={!githubUrl.trim()}
            className="px-4 py-2 rounded bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-bold text-xs font-mono transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            Clone Repository & Initialize Run
          </button>
        </form>
      )}

      {/* Tab 3: Safe ZIP Upload */}
      {tab === 'upload' && !loading && (
        <form onSubmit={handleZipSubmit} className="rounded-lg border border-border-subtle bg-surface-2 p-6 space-y-4 max-w-2xl">
          <div className="space-y-1">
            <label htmlFor="zip-file-input" className="block text-xs font-mono font-semibold text-slate-200">
              UPLOAD TARGET SOURCE REPOSITORY ZIP ARCHIVE:
            </label>
            <div className="flex items-center gap-3">
              <input
                id="zip-file-input"
                type="file"
                accept=".zip"
                required
                onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                className="text-xs text-slate-300 font-mono file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-xs file:font-mono file:bg-surface-3 file:text-slate-200 hover:file:bg-surface-3/80 cursor-pointer"
              />
              {selectedFile && (
                <span className="text-xs font-mono text-emerald-400 flex items-center gap-1">
                  <FileArchive className="w-4 h-4" aria-hidden="true" />
                  {(selectedFile.size / 1024 / 1024).toFixed(2)} MB
                </span>
              )}
            </div>
            <span className="text-[11px] text-slate-400 font-mono block">
              Checked for Zip-Slip traversal, symlink escapes, and decompression-bomb ratios (&le;100:1).
            </span>
          </div>

          <div className="space-y-1">
            <label htmlFor="upload-cve-input" className="block text-xs font-mono font-semibold text-slate-200">
              TARGET CVE ADVISORY IDENTIFIER:
            </label>
            <input
              id="upload-cve-input"
              type="text"
              required
              value={cveId}
              onChange={(e) => setCveId(e.target.value)}
              placeholder="CVE-2020-14343"
              className="w-full px-3 py-2 rounded bg-surface-inset border border-border-interactive text-slate-100 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
            />
          </div>

          <button
            type="submit"
            disabled={!selectedFile}
            className="px-4 py-2 rounded bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-bold text-xs font-mono transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            Extract & Initialize Disposable Workspace
          </button>
        </form>
      )}

      {/* Active Run Confirmation Card */}
      {currentRun && (
        <div className="rounded-lg border border-emerald-500/40 bg-emerald-950/20 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" aria-hidden="true" />
            <div>
              <span className="text-emerald-300 font-bold">WORKSPACE INITIALIZED: {currentRun.id}</span>
              <p className="text-slate-400 text-[11px]">
                Target: {currentRun.cve_id} | Ref: {currentRun.source_ref}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onProceedToAnalysis}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 self-start sm:self-auto"
          >
            <span>Run Analysis</span>
            <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
          </button>
        </div>
      )}
    </section>
  );
};
