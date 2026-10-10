import React, { useState } from 'react';
import {
  Download,
  FileCode,
  FileArchive,
  FileCheck2,
  Copy,
  Check,
  ShieldCheck,
  KeyRound,
  Terminal,
  RefreshCw,
  AlertTriangle,
  CheckCircle2
} from 'lucide-react';
import { EvidenceBundle } from '../types';

interface StepExportProps {
  runId: string;
  bundle: EvidenceBundle | null;
  loading: boolean;
}

export const StepExport: React.FC<StepExportProps> = ({
  runId,
  bundle,
  loading
}) => {
  const [copiedGitApply, setCopiedGitApply] = useState(false);
  const [copiedVerify, setCopiedVerify] = useState(false);
  const [copiedFp, setCopiedFp] = useState(false);
  const [downloadingFormat, setDownloadingFormat] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);

  const gitApplySnippet = `git apply ${runId}_patch.diff`;
  const verifyCommandSnippet = `vulntrace verify-bundle ${runId}_bundle.json`;
  const signerFp = bundle?.signature?.public_key_fingerprint || '';

  const handleCopy = (text: string, setter: (val: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setter(true);
    setTimeout(() => setter(false), 2000);
  };

  const handleDownload = async (format: 'diff' | 'zip' | 'bundle') => {
    setDownloadingFormat(format);
    setDownloadError(null);
    setDownloadSuccess(null);
    try {
      const url = format === 'bundle'
        ? `/runs/${runId}/bundle`
        : `/runs/${runId}/export?format=${format}`;
      const res = await fetch(url);
      if (!res.ok) {
        let errMsg = `HTTP ${res.status}: ${res.statusText}`;
        try {
          const errData = await res.json();
          if (errData.detail) errMsg = errData.detail;
        } catch {
          // fallback
        }
        throw new Error(`Export download failed (${errMsg})`);
      }
      const blob = await res.blob();
      const blobUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      const ext = format === 'diff' ? 'diff' : format === 'zip' ? 'zip' : 'json';
      a.download = `${runId}_${format}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(blobUrl);
      setDownloadSuccess(`Successfully downloaded .${ext} artifact`);
      setTimeout(() => setDownloadSuccess(null), 4000);
    } catch (err: any) {
      setDownloadError(err.message || 'Download failed due to network or server error');
    } finally {
      setDownloadingFormat(null);
    }
  };

  if (loading) {
    return (
      <div
        role="status"
        aria-live="polite"
        className="rounded-lg border border-border-subtle bg-surface-2 p-12 flex flex-col items-center justify-center text-center space-y-3 min-h-[300px]"
      >
        <span className="w-8 h-8 rounded-full border-2 border-emerald-400 border-t-transparent animate-spin" aria-hidden="true" />
        <span className="text-sm font-semibold text-slate-200 font-sans">Assembling and Signing Export Artifacts...</span>
        <span className="text-xs text-slate-400 max-w-md font-sans">
          Generating unified diff, compressing sanitized workspace archive, and packaging RFC 8032 sealed bundle (Spec §4.11, §4.13).
        </span>
      </div>
    );
  }

  if (!bundle && !loading) {
    return (
      <div
        role="alert"
        aria-live="assertive"
        className="rounded-lg border border-dashed border-border-interactive bg-surface-2/40 p-12 flex flex-col items-center justify-center text-center space-y-3"
      >
        <Download className="w-10 h-10 text-slate-500" aria-hidden="true" />
        <span className="text-sm font-semibold text-slate-300 font-sans">No export artifacts ready yet.</span>
        <p className="text-xs text-slate-400 max-w-md font-sans">
          Complete the live verification run in Step 5 and audit evidence in Step 6 to enable distribution downloads.
        </p>
      </div>
    );
  }

  return (
    <section aria-labelledby="step-export-title" className="space-y-6">
      {/* Title */}
      <div>
        <h2 id="step-export-title" className="text-base font-bold text-slate-100 flex items-center gap-2 font-sans">
          <Download className="w-5 h-5 text-emerald-400" aria-hidden="true" />
          Step 7: Engineering Handoff &amp; Cryptographic Distribution
        </h2>
        <p className="text-xs text-slate-400 font-sans mt-0.5">
          Download verifiable patch distribution packages and execute independent CLI verification (Spec §4.11, §4.13).
        </p>
      </div>

      {/* Download Feedback Alerts */}
      {downloadError && (
        <div
          role="alert"
          aria-live="assertive"
          className="rounded-lg border border-rose-800/60 bg-rose-950/30 p-4 text-xs text-rose-200 space-y-1"
        >
          <div className="flex items-center gap-2 font-semibold text-rose-400 font-sans">
            <AlertTriangle className="w-4 h-4 text-rose-500 shrink-0" aria-hidden="true" />
            <span>Artifact Download Error</span>
          </div>
          <p className="text-rose-300 font-sans">{downloadError}</p>
        </div>
      )}

      {downloadSuccess && (
        <div
          role="status"
          aria-live="polite"
          className="rounded-lg border border-emerald-700/60 bg-emerald-950/30 p-3 text-xs text-emerald-200 flex items-center gap-2 font-sans"
        >
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" aria-hidden="true" />
          <span>{downloadSuccess}</span>
        </div>
      )}

      {/* Engineering Handoff Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Card 1: Normalized Unified Diff */}
        <div className="rounded-lg border border-border-subtle bg-surface-2 p-5 flex flex-col justify-between space-y-4 hover:border-slate-700 transition-colors">
          <div className="space-y-2.5">
            <div className="w-9 h-9 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
              <FileCode className="w-5 h-5" aria-hidden="true" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 font-sans">Unified Diff Patch (.diff)</h3>
              <span className="text-[11px] font-mono text-sky-400 block pt-0.5">Surgical Git Diff Format</span>
            </div>
            <p className="text-xs text-slate-400 font-sans leading-relaxed">
              Clean, minimal diff suitable for direct application via <code className="text-slate-300 font-mono">git apply</code> or automated CI pull request merges.
            </p>
          </div>
          <button
            type="button"
            disabled={downloadingFormat !== null}
            onClick={() => handleDownload('diff')}
            className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-md bg-surface-3 hover:bg-slate-700 disabled:opacity-60 text-slate-100 text-xs font-sans font-semibold border border-border-interactive transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
          >
            {downloadingFormat === 'diff' ? (
              <RefreshCw className="w-4 h-4 animate-spin text-sky-400" aria-hidden="true" />
            ) : (
              <Download className="w-4 h-4" aria-hidden="true" />
            )}
            <span>{downloadingFormat === 'diff' ? 'Downloading...' : 'Download .diff'}</span>
          </button>
        </div>

        {/* Card 2: Patched Workspace Archive */}
        <div className="rounded-lg border border-border-subtle bg-surface-2 p-5 flex flex-col justify-between space-y-4 hover:border-slate-700 transition-colors">
          <div className="space-y-2.5">
            <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <FileArchive className="w-5 h-5" aria-hidden="true" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 font-sans">Patched Workspace (.zip)</h3>
              <span className="text-[11px] font-mono text-emerald-400 block pt-0.5">Full Clean Repository</span>
            </div>
            <p className="text-xs text-slate-400 font-sans leading-relaxed">
              Complete target repository workspace checked out with the verified patch applied and git hooks securely stripped.
            </p>
          </div>
          <button
            type="button"
            disabled={downloadingFormat !== null}
            onClick={() => handleDownload('zip')}
            className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-md bg-surface-3 hover:bg-slate-700 disabled:opacity-60 text-slate-100 text-xs font-sans font-semibold border border-border-interactive transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
          >
            {downloadingFormat === 'zip' ? (
              <RefreshCw className="w-4 h-4 animate-spin text-emerald-400" aria-hidden="true" />
            ) : (
              <Download className="w-4 h-4" aria-hidden="true" />
            )}
            <span>{downloadingFormat === 'zip' ? 'Downloading...' : 'Download .zip'}</span>
          </button>
        </div>

        {/* Card 3: Schema v1 Signed Bundle */}
        <div className="rounded-lg border border-emerald-500/50 bg-emerald-950/20 p-5 flex flex-col justify-between space-y-4 shadow-sm hover:border-emerald-500 transition-colors">
          <div className="space-y-2.5">
            <div className="w-9 h-9 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <FileCheck2 className="w-5 h-5" aria-hidden="true" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100 font-sans">Schema v1 Signed Bundle (.json)</h3>
              <span className="text-[11px] font-mono text-emerald-400 block pt-0.5">RFC 8032 / RFC 8785 Sealed</span>
            </div>
            <p className="text-xs text-slate-300 font-sans leading-relaxed">
              Complete machine-verifiable audit trail embedding canonical JSON hashes and an Ed25519 digital signature seal.
            </p>
          </div>
          <button
            type="button"
            disabled={downloadingFormat !== null}
            onClick={() => handleDownload('bundle')}
            className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-md bg-emerald-500 hover:bg-emerald-400 disabled:opacity-60 text-slate-950 text-xs font-sans font-bold shadow-md transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            {downloadingFormat === 'bundle' ? (
              <RefreshCw className="w-4 h-4 animate-spin text-slate-950" aria-hidden="true" />
            ) : (
              <Download className="w-4 h-4" aria-hidden="true" />
            )}
            <span>{downloadingFormat === 'bundle' ? 'Downloading...' : 'Download bundle.json'}</span>
          </button>
        </div>
      </div>

      {/* Prominent 1-Click Copy CLI Blocks */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* CLI Block 1: Git Apply */}
        <div className="rounded-lg border border-border-subtle bg-surface-2 p-4 space-y-2.5 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-border-subtle pb-2">
            <span className="font-bold text-slate-200 flex items-center gap-2 font-sans">
              <Terminal className="w-4 h-4 text-sky-400" aria-hidden="true" />
              1. Apply Patch to Local Repository
            </span>
            <button
              type="button"
              onClick={() => handleCopy(gitApplySnippet, setCopiedGitApply)}
              className="flex items-center gap-1 text-[11px] font-sans font-medium text-slate-400 hover:text-emerald-400 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500 rounded px-1.5 py-0.5 bg-surface-3"
              aria-label="Copy git apply command"
            >
              {copiedGitApply ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedGitApply ? 'Copied!' : 'Copy Snippet'}</span>
            </button>
          </div>
          <div className="p-3 rounded-md bg-[#020617] border border-border-interactive text-slate-200 select-all overflow-x-auto">
            <code>{gitApplySnippet}</code>
          </div>
          <span className="text-[11px] font-sans text-slate-400 block">
            Executes clean whitespace-safe git patch application against the target repository head.
          </span>
        </div>

        {/* CLI Block 2: Independent Bundle Verification */}
        <div className="rounded-lg border border-border-subtle bg-surface-2 p-4 space-y-2.5 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-border-subtle pb-2">
            <span className="font-bold text-slate-200 flex items-center gap-2 font-sans">
              <ShieldCheck className="w-4 h-4 text-emerald-400" aria-hidden="true" />
              2. Independent Offline Bundle Verification
            </span>
            <button
              type="button"
              onClick={() => handleCopy(verifyCommandSnippet, setCopiedVerify)}
              className="flex items-center gap-1 text-[11px] font-sans font-medium text-slate-400 hover:text-emerald-400 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500 rounded px-1.5 py-0.5 bg-surface-3"
              aria-label="Copy verify-bundle command"
            >
              {copiedVerify ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedVerify ? 'Copied!' : 'Copy Snippet'}</span>
            </button>
          </div>
          <div className="p-3 rounded-md bg-[#020617] border border-border-interactive text-slate-200 select-all overflow-x-auto">
            <code>{verifyCommandSnippet}</code>
          </div>
          <span className="text-[11px] font-sans text-slate-400 block">
            Verifies Ed25519 signature and RFC 8785 canonical hashes independently of the studio server.
          </span>
        </div>
      </div>

      {/* Ed25519 Public Key Fingerprint Trust Seal Card */}
      {signerFp && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/15 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-3">
            <KeyRound className="w-5 h-5 text-emerald-400 shrink-0" aria-hidden="true" />
            <div>
              <span className="text-emerald-300 font-bold font-sans">
                Ed25519 Public Key SHA-256 Fingerprint:
              </span>
              <p className="text-slate-300 select-all break-all text-[11px] font-mono pt-0.5">{signerFp}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => handleCopy(signerFp, setCopiedFp)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-surface-3 hover:bg-slate-700 text-slate-200 text-xs font-sans font-medium border border-border-subtle transition-colors shrink-0 self-start sm:self-auto focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
          >
            {copiedFp ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedFp ? 'Copied!' : 'Copy Fingerprint'}</span>
          </button>
        </div>
      )}
    </section>
  );
};
