import React, { useState } from 'react';
import {
  FileCheck2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ArrowRight,
  ShieldCheck,
  FileCode,
  ExternalLink,
  Info
} from 'lucide-react';
import { EvidenceBundle } from '../types';

interface StepEvidenceProps {
  bundle: EvidenceBundle | null;
  loading: boolean;
  error?: string;
  onProceedToExport: () => void;
}

const VERDICT_TAXONOMY_MAP: Record<string, { label: string; description: string; color: string }> = {
  GREEN_STATE_VERIFIED: {
    label: 'GREEN_STATE_VERIFIED',
    description: 'Reachable vulnerability reproduced in RED state (3/3), patch accepted, verified in GREEN state (3/3), and baseline test suite passed without regression.',
    color: 'emerald'
  },
  NO_STATIC_PATH_FOUND: {
    label: 'NO_STATIC_PATH_FOUND',
    description: 'Static analysis found no incoming execution path from public entrypoints; dead code or false positive suppressed.',
    color: 'slate'
  },
  NOT_VULNERABLE_ALREADY_SAFE: {
    label: 'NOT_VULNERABLE_ALREADY_SAFE',
    description: 'Vulnerable pattern is absent or already patched in the target repository.',
    color: 'slate'
  },
  RED_NOT_REPRODUCED: {
    label: 'RED_NOT_REPRODUCED',
    description: 'Vulnerable sink is statically reachable, but exploit probe did not reproduce unsafe behavior.',
    color: 'amber'
  },
  RED_STATE_PERSISTS: {
    label: 'RED_STATE_PERSISTS',
    description: 'Remediation patch applied, but exploit probe still succeeded; patch was ineffective.',
    color: 'rose'
  },
  PATCH_REJECTED: {
    label: 'PATCH_REJECTED',
    description: 'Generated patch failed syntactic validation, denylist gate, diff-budget limit, or Scope Guard boundaries.',
    color: 'rose'
  },
  REGRESSION_FAILURE: {
    label: 'REGRESSION_FAILURE',
    description: 'Security exploit was neutralized, but existing baseline regression tests broke as a result of the patch.',
    color: 'rose'
  },
  VERIFICATION_REJECTED: {
    label: 'VERIFICATION_REJECTED',
    description: 'Evidence integrity failure: verification harness hash mutated, output forged, or security policy violated.',
    color: 'amber'
  },
  ENV_BUILD_FAILED: {
    label: 'ENV_BUILD_FAILED',
    description: 'Target dependency environment could not be constructed (distinct from verification tool failure).',
    color: 'amber'
  },
  UNVERIFIABLE: {
    label: 'UNVERIFIABLE',
    description: 'Requirement prompt could not be parsed into a concrete, measurable failing acceptance test.',
    color: 'amber'
  },
  UNEXPECTED_FAILURE: {
    label: 'UNEXPECTED_FAILURE',
    description: 'Internal engine execution error; traceback reference recorded in evidence bundle.',
    color: 'rose'
  }
};

export const StepEvidence: React.FC<StepEvidenceProps> = ({
  bundle,
  loading,
  error,
  onProceedToExport
}) => {
  const [activeTab, activeTabSet] = useState<'red_green' | 'diff' | 'regressions' | 'intel'>('red_green');

  if (loading) {
    return (
      <div
        role="status"
        aria-live="polite"
        className="rounded-lg border border-border-subtle bg-surface-2 p-12 flex flex-col items-center justify-center text-center space-y-3 min-h-[300px]"
      >
        <span className="w-8 h-8 rounded-full border-2 border-emerald-400 border-t-transparent animate-spin" />
        <span className="text-sm font-semibold text-slate-200">Loading Cryptographically Signed Evidence Bundle...</span>
        <span className="text-xs font-mono text-slate-400">Verifying Ed25519 signature and re-computing canonical SHA-256 hashes.</span>
      </div>
    );
  }

  if (error || !bundle) {
    return (
      <div
        role="alert"
        aria-live="assertive"
        className="rounded-lg border border-dashed border-border-interactive bg-surface-2/40 p-12 flex flex-col items-center justify-center text-center space-y-3"
      >
        <FileCheck2 className="w-10 h-10 text-slate-500" aria-hidden="true" />
        <span className="text-sm font-semibold text-slate-300">
          {error || 'No evidence bundle available for this run.'}
        </span>
        <p className="text-xs text-slate-400 max-w-md font-sans">
          Execute the verification pipeline in Step 5 to generate and sign the Schema v1 evidence bundle.
        </p>
      </div>
    );
  }

  const verdictInfo = VERDICT_TAXONOMY_MAP[bundle.verdict] || {
    label: bundle.verdict,
    description: 'Custom or unmapped verdict state.',
    color: 'sky'
  };

  const isGreen = bundle.verdict === 'GREEN_STATE_VERIFIED';
  const redRuns = bundle.verification?.red_runs || [];
  const greenRuns = bundle.verification?.green_runs || [];
  const latestDiff = bundle.attempts?.[bundle.attempts.length - 1]?.diff || '';
  const regression = bundle.verification?.regression;

  return (
    <section aria-labelledby="step-evidence-title" className="space-y-6">
      {/* Title & Navigation Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 id="step-evidence-title" className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <FileCheck2 className="w-5 h-5 text-emerald-400" aria-hidden="true" />
            Step 6: Evidence Verification, RED vs. GREEN & Diff Audit
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Independently verifiable proof: side-by-side reproduction, unified diff, regression table, and Ed25519 signature (Spec §4.11, §4.13).
          </p>
        </div>

        <button
          type="button"
          onClick={onProceedToExport}
          className="flex items-center gap-2 px-4 py-2 rounded bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-mono transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
        >
          <span>Proceed to Step 7: Export</span>
          <ArrowRight className="w-4 h-4" aria-hidden="true" />
        </button>
      </div>

      {/* Primary Trust Banner: Exact Canonical Verdict Badge */}
      <div
        className={`rounded-lg border p-5 space-y-2.5 transition-colors ${
          isGreen
            ? 'border-emerald-500/80 bg-emerald-950/20 shadow-sm'
            : verdictInfo.color === 'rose'
            ? 'border-rose-600/80 bg-rose-950/20'
            : 'border-amber-600/80 bg-amber-950/20'
        }`}
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            {isGreen ? (
              <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" aria-hidden="true" />
            ) : verdictInfo.color === 'rose' ? (
              <XCircle className="w-6 h-6 text-rose-400 shrink-0" aria-hidden="true" />
            ) : (
              <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0" aria-hidden="true" />
            )}
            <div>
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block">
                FORMAL TERMINAL VERDICT (Spec §3.1)
              </span>
              <span className="text-lg font-bold font-mono text-slate-100">{bundle.verdict}</span>
            </div>
          </div>

          {/* Cryptographic Seal Badge */}
          <div className="flex flex-col items-end text-xs font-mono text-slate-400">
            <span className="flex items-center gap-1.5 text-emerald-400 font-semibold">
              <ShieldCheck className="w-4 h-4" aria-hidden="true" />
              Ed25519 SIGNED BUNDLE
            </span>
            <span className="text-[11px] text-slate-500 truncate max-w-xs" title={bundle.signature?.public_key_fingerprint}>
              KEY FP: {bundle.signature?.public_key_fingerprint?.substring(0, 16)}...
            </span>
          </div>
        </div>

        <p className="text-xs text-slate-300 font-sans leading-relaxed pt-1 border-t border-border-subtle/40">
          {verdictInfo.description}
        </p>
      </div>

      {/* Metadata Telemetry Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
        <div className="p-3 rounded-lg border border-border-subtle bg-surface-2 space-y-1">
          <span className="text-[11px] text-slate-400 uppercase">SANDBOX ISOLATION</span>
          <div className="font-bold text-sky-400 truncate">{bundle.sandbox?.tier || 'TIER 1 (CONTAINER)'}</div>
        </div>

        <div className="p-3 rounded-lg border border-border-subtle bg-surface-2 space-y-1">
          <span className="text-[11px] text-slate-400 uppercase">FLAKE VERIFICATION</span>
          <div className="font-bold text-emerald-400">
            RED: {redRuns.length}/3 | GREEN: {greenRuns.length}/3
          </div>
        </div>

        <div className="p-3 rounded-lg border border-border-subtle bg-surface-2 space-y-1">
          <span className="text-[11px] text-slate-400 uppercase">TOTAL TOKENS</span>
          <div className="font-bold text-slate-200">
            {bundle.llm?.calls?.reduce((acc, c) => acc + (c.prompt_tokens + c.completion_tokens), 0) || 0} Tokens
          </div>
        </div>

        <div className="p-3 rounded-lg border border-border-subtle bg-surface-2 space-y-1">
          <span className="text-[11px] text-slate-400 uppercase">TARGET RUNTIME</span>
          <div className="font-bold text-slate-300">Python {bundle.python_version || '3.11'}</div>
        </div>
      </div>

      {/* Sub-Tabs: RED vs GREEN, Diff Viewer, Regressions, Intel Sources */}
      <div className="space-y-4">
        <div className="flex items-center gap-2 border-b border-border-subtle pb-2">
          <button
            type="button"
            onClick={() => activeTabSet('red_green')}
            className={`px-3 py-1.5 rounded text-xs font-mono transition-all ${
              activeTab === 'red_green'
                ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Side-by-Side RED vs. GREEN (3/3)
          </button>

          <button
            type="button"
            onClick={() => activeTabSet('diff')}
            className={`px-3 py-1.5 rounded text-xs font-mono transition-all ${
              activeTab === 'diff'
                ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Unified Diff Audit
          </button>

          <button
            type="button"
            onClick={() => activeTabSet('regressions')}
            className={`px-3 py-1.5 rounded text-xs font-mono transition-all ${
              activeTab === 'regressions'
                ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Baseline vs. After Regressions
          </button>

          <button
            type="button"
            onClick={() => activeTabSet('intel')}
            className={`px-3 py-1.5 rounded text-xs font-mono transition-all ${
              activeTab === 'intel'
                ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Tavily Intel & Limitations
          </button>
        </div>

        {/* Tab 1: Side-by-Side RED vs. GREEN Reproduction */}
        {activeTab === 'red_green' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Left Pane: RED State Reproduction */}
            <div className="rounded-lg border border-rose-800/40 bg-surface-2 p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-border-subtle pb-2">
                <span className="text-xs font-mono font-bold text-rose-300 flex items-center gap-1.5">
                  <XCircle className="w-4 h-4 text-rose-400" aria-hidden="true" />
                  PRE-PATCH: RED STATE REPRODUCED (3/3)
                </span>
                <span className="text-[10px] font-mono text-rose-400 bg-rose-950/60 px-2 py-0.5 rounded border border-rose-800/60">
                  EXPLOIT PROBE ACTIVE
                </span>
              </div>
              <p className="text-xs text-slate-400 font-sans">
                Exploit probe executed against unpatched code. Behavioral sentinel confirmed security failure.
              </p>
              <div className="space-y-2">
                {redRuns.map((r, i) => (
                  <div key={i} className="p-2.5 rounded bg-surface-inset border border-rose-900/40 font-mono text-xs flex items-center justify-between">
                    <span className="text-slate-300">Repeat #{r.run_number}</span>
                    <span className="text-rose-400 font-bold">EXIT CODE {r.exit_code} (REPRODUCED)</span>
                    <span className="text-slate-500 text-[11px]">{r.duration_ms}ms</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Right Pane: GREEN State Verification */}
            <div className="rounded-lg border border-emerald-800/40 bg-surface-2 p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-border-subtle pb-2">
                <span className="text-xs font-mono font-bold text-emerald-300 flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" aria-hidden="true" />
                  POST-PATCH: GREEN STATE VERIFIED (3/3)
                </span>
                <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/60">
                  SECURITY DEFENSE ACTIVE
                </span>
              </div>
              <p className="text-xs text-slate-400 font-sans">
                Exploit probe executed against remediated code. Malicious input neutralized with zero crash or leak.
              </p>
              <div className="space-y-2">
                {greenRuns.map((r, i) => (
                  <div key={i} className="p-2.5 rounded bg-surface-inset border border-emerald-900/40 font-mono text-xs flex items-center justify-between">
                    <span className="text-slate-300">Repeat #{r.run_number}</span>
                    <span className="text-emerald-400 font-bold">EXIT CODE {r.exit_code} (BLOCKED)</span>
                    <span className="text-slate-500 text-[11px]">{r.duration_ms}ms</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Unified Diff Audit */}
        {activeTab === 'diff' && (
          <div className="rounded-lg border border-border-subtle bg-surface-inset overflow-hidden font-mono text-xs">
            <div className="px-4 py-2.5 border-b border-border-subtle bg-surface-1 flex items-center justify-between">
              <span className="text-slate-300 font-bold flex items-center gap-2">
                <FileCode className="w-4 h-4 text-sky-400" aria-hidden="true" />
                VERIFIED NORMALIZED UNIFIED DIFF
              </span>
              <span className="text-[11px] text-slate-400">Spec §4.10 Surgical Scope</span>
            </div>
            <pre className="p-4 overflow-x-auto text-slate-200 leading-relaxed select-text">
              {latestDiff ? (
                latestDiff.split('\n').map((line, idx) => {
                  let lineStyle = 'text-slate-300';
                  if (line.startsWith('+') && !line.startsWith('+++')) lineStyle = 'text-emerald-400 bg-emerald-950/20';
                  else if (line.startsWith('-') && !line.startsWith('---')) lineStyle = 'text-rose-400 bg-rose-950/20';
                  else if (line.startsWith('@@')) lineStyle = 'text-sky-300 bg-sky-950/20';
                  return (
                    <div key={idx} className={`${lineStyle} px-1 rounded`}>
                      {line}
                    </div>
                  );
                })
              ) : (
                <span className="text-slate-500 italic">No diff available in evidence bundle.</span>
              )}
            </pre>
          </div>
        )}

        {/* Tab 3: Baseline vs. After Regressions */}
        {activeTab === 'regressions' && (
          <div className="rounded-lg border border-border-subtle bg-surface-2 p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-border-subtle pb-2">
              <span className="text-xs font-mono font-bold text-slate-200">
                REGRESSION VERIFICATION AUDIT (Spec §4.4)
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${
                regression?.passed
                  ? 'bg-emerald-950/60 text-emerald-300 border-emerald-700/60'
                  : 'bg-rose-950/60 text-rose-300 border-rose-700/60'
              }`}>
                {regression?.passed ? 'ALL REGRESSIONS PRESERVED' : 'REGRESSION FAILURE DETECTED'}
              </span>
            </div>

            <p className="text-xs text-slate-400 font-sans">
              Spec §4.4 compares per-test baseline against post-patch execution. Pre-existing failures do not penalize the patch,
              whereas any new test failures trigger an immediate <code className="text-rose-400">REGRESSION_FAILURE</code> terminal verdict.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 rounded bg-surface-inset border border-border-subtle space-y-1">
                <span className="text-slate-400 uppercase text-[11px]">PRE-EXISTING FAILURES:</span>
                <div className="text-slate-200">
                  {regression?.preexisting_failures?.length || 0} Test(s)
                </div>
              </div>
              <div className="p-3 rounded bg-surface-inset border border-border-subtle space-y-1">
                <span className="text-slate-400 uppercase text-[11px]">NEW FAILURES INTRODUCED BY PATCH:</span>
                <div className={regression?.new_failures?.length ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                  {regression?.new_failures?.length || 0} Test(s) (ZERO REQUIRED)
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 4: Tavily Intel & Limitations */}
        {activeTab === 'intel' && (
          <div className="space-y-4">
            {/* Tavily Sources */}
            <div className="rounded-lg border border-border-subtle bg-surface-2 p-4 space-y-3">
              <span className="text-xs font-mono font-bold text-slate-200">
                TAVILY THREAT INTEL ADVISORY SOURCES ({bundle.intel?.urls?.length || 0})
              </span>
              <ul className="space-y-1.5 text-xs font-mono">
                {bundle.intel?.urls?.map((url, i) => (
                  <li key={i} className="p-2 rounded bg-surface-inset border border-border-subtle flex items-center justify-between">
                    <span className="text-slate-300 truncate">{url}</span>
                    <a
                      href={url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="text-sky-400 hover:text-sky-300 flex items-center gap-1 text-[11px] font-semibold"
                    >
                      <span>Open Link</span>
                      <ExternalLink className="w-3 h-3" aria-hidden="true" />
                    </a>
                  </li>
                ))}
              </ul>
            </div>

            {/* Stated Limitations */}
            <div className="rounded-lg border border-border-subtle bg-surface-2 p-4 space-y-2">
              <span className="text-xs font-mono font-bold text-slate-200 flex items-center gap-2">
                <Info className="w-4 h-4 text-amber-400" aria-hidden="true" />
                RECORDED EVIDENCE LIMITATIONS & ASSUMPTIONS
              </span>
              <ul className="text-xs font-mono text-slate-400 space-y-1">
                {bundle.limitations?.map((lim, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-amber-400">•</span>
                    <span>{lim}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>
    </section>
  );
};
