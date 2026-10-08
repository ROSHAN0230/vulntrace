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
  Terminal
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

  const gitApplySnippet = `git apply ${runId}_patch.diff`;
  const verifyCommandSnippet = `vulntrace verify-bundle ${runId}_bundle.json`;
  const signerFp = bundle?.signature?.public_key_fingerprint || '';

  const handleCopy = (text: string, setter: (val: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setter(true);
    setTimeout(() => setter(false), 2000);
  };

  const handleDownload = (format: 'diff' | 'zip' | 'bundle') => {
    if (format === 'bundle') {
      window.open(`/runs/${runId}/bundle`, '_blank');
    } else {
      window.open(`/runs/${runId}/export?format=${format}`, '_blank');
    }
  };

  if (!bundle && !loading) {
    return (
      <div
        role="alert"
        aria-live="assertive"
        className="rounded-lg border border-dashed border-border-interactive bg-surface-2/40 p-12 flex flex-col items-center justify-center text-center space-y-3"
      >
        <Download className="w-10 h-10 text-slate-500" aria-hidden="true" />
        <span className="text-sm font-semibold text-slate-300">No export artifacts ready yet.</span>
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
        <h2 id="step-export-title" className="text-lg font-bold text-slate-100 flex items-center gap-2">
          <Download className="w-5 h-5 text-emerald-400" aria-hidden="true" />
          Step 7: Artifact Export & Independent Cryptographic Verification
        </h2>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Download verifiable patch distribution packages and execute independent CLI verification (Spec §4.11, §4.13).
        </p>
      </div>

      {/* Artifact Download Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Unified Diff Download */}
        <div className="rounded-lg border border-border-subtle bg-surface-2 p-5 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-9 h-9 rounded bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
              <FileCode className="w-5 h-5" aria-hidden="true" />
            </div>
            <h3 className="text-sm font-bold text-slate-100 font-mono">Normalized Unified Diff (.diff)</h3>
            <p className="text-xs text-slate-400 font-sans">
              Clean, surgical patch format suitable for direct application via <code className="text-slate-300">git apply</code> or CI/CD pipelines.
            </p>
          </div>
          <button
            type="button"
            onClick={() => handleDownload('diff')}
            className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded bg-surface-3 hover:bg-slate-700 text-slate-100 text-xs font-mono font-semibold border border-border-interactive transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
          >
            <Download className="w-4 h-4" aria-hidden="true" />
            <span>Download .diff</span>
          </button>
        </div>

        {/* Patched Workspace ZIP */}
        <div className="rounded-lg border border-border-subtle bg-surface-2 p-5 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-9 h-9 rounded bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <FileArchive className="w-5 h-5" aria-hidden="true" />
            </div>
            <h3 className="text-sm font-bold text-slate-100 font-mono">Patched Workspace (.zip)</h3>
            <p className="text-xs text-slate-400 font-sans">
              Full disposable target repository workspace checked out with the verified patch applied and git hooks disabled.
            </p>
          </div>
          <button
            type="button"
            onClick={() => handleDownload('zip')}
            className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded bg-surface-3 hover:bg-slate-700 text-slate-100 text-xs font-mono font-semibold border border-border-interactive transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
          >
            <Download className="w-4 h-4" aria-hidden="true" />
            <span>Download .zip</span>
          </button>
        </div>

        {/* Schema v1 Signed Bundle */}
        <div className="rounded-lg border border-border-subtle bg-surface-2 p-5 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-9 h-9 rounded bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <FileCheck2 className="w-5 h-5" aria-hidden="true" />
            </div>
            <h3 className="text-sm font-bold text-slate-100 font-mono">Schema v1 Signed Bundle (JSON)</h3>
            <p className="text-xs text-slate-400 font-sans">
              Complete machine-readable audit trail embedding canonical RFC 8785 hashes and an RFC 8032 Ed25519 digital signature.
            </p>
          </div>
          <button
            type="button"
            onClick={() => handleDownload('bundle')}
            className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-xs font-mono font-bold shadow-md transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            <Download className="w-4 h-4" aria-hidden="true" />
            <span>Download bundle.json</span>
          </button>
        </div>
      </div>

      {/* Copyable CLI Snippets */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Git Apply Snippet */}
        <div className="rounded-lg border border-border-subtle bg-surface-2 p-4 space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-border-subtle pb-2">
            <span className="font-bold text-slate-200 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-sky-400" aria-hidden="true" />
              1. APPLY PATCH TO REPOSITORY
            </span>
            <button
              type="button"
              onClick={() => handleCopy(gitApplySnippet, setCopiedGitApply)}
              className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-emerald-400 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500 rounded px-1"
              aria-label="Copy git apply command"
            >
              {copiedGitApply ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedGitApply ? 'Copied!' : 'Copy'}</span>
            </button>
          </div>
          <div className="p-3 rounded bg-surface-inset border border-border-interactive text-slate-200 select-all">
            <code>{gitApplySnippet}</code>
          </div>
        </div>

        {/* Verify Bundle Snippet */}
        <div className="rounded-lg border border-border-subtle bg-surface-2 p-4 space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-border-subtle pb-2">
            <span className="font-bold text-slate-200 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" aria-hidden="true" />
              2. INDEPENDENT BUNDLE VERIFICATION
            </span>
            <button
              type="button"
              onClick={() => handleCopy(verifyCommandSnippet, setCopiedVerify)}
              className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-emerald-400 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500 rounded px-1"
              aria-label="Copy verify-bundle command"
            >
              {copiedVerify ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedVerify ? 'Copied!' : 'Copy'}</span>
            </button>
          </div>
          <div className="p-3 rounded bg-surface-inset border border-border-interactive text-slate-200 select-all">
            <code>{verifyCommandSnippet}</code>
          </div>
        </div>
      </div>

      {/* Ed25519 Key Fingerprint Trust Seal */}
      {signerFp && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/10 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-3">
            <KeyRound className="w-5 h-5 text-emerald-400 shrink-0" aria-hidden="true" />
            <div>
              <span className="text-emerald-300 font-bold">Ed25519 PUBLIC KEY SHA-256 FINGERPRINT:</span>
              <p className="text-slate-300 select-all break-all text-[11px]">{signerFp}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => handleCopy(signerFp, setCopiedFp)}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-surface-3 hover:bg-slate-700 text-slate-200 text-xs border border-border-subtle transition-colors shrink-0 self-start sm:self-auto"
          >
            {copiedFp ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedFp ? 'Copied!' : 'Copy Fingerprint'}</span>
          </button>
        </div>
      )}
    </section>
  );
};
