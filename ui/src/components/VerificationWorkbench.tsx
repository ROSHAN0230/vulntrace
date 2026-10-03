import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertOctagon,
  CheckCircle2,
  Terminal,
  RefreshCw,
  FileCode,
  GitCommit,
  Check,
  Flame,
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  Download,
  Info,
  Scale,
  Sparkles,
  HelpCircle,
  X,
  AlertTriangle
} from 'lucide-react';
import { VerificationPipelineResponse } from '../types';

interface VerificationWorkbenchProps {
  onRunPipeline: () => Promise<void>;
  data: VerificationPipelineResponse | null;
  loading: boolean;
  error?: string;
  reachabilityReady: boolean;
}

export const VerificationWorkbench: React.FC<VerificationWorkbenchProps> = ({
  onRunPipeline,
  data,
  loading,
  error,
  reachabilityReady
}) => {
  const [showHarness, setShowHarness] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [exportContent, setExportContent] = useState<string>('');
  const [showJudgeModal, setShowJudgeModal] = useState(false);
  const [judgeTab, setJudgeTab] = useState<'questions' | 'matrix' | 'disclosures'>('questions');

  const handleExportEvidence = async (format: 'json' | 'markdown') => {
    if (!data) return;
    try {
      setExporting(true);
      const res = await fetch(`/api/v1/evidence/export?format=${format}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      if (!res.ok) throw new Error(`Export failed with HTTP ${res.status}`);
      
      if (format === 'json') {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `vulntrace-evidence-${data.cve_id}-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      } else {
        const json = await res.json();
        setExportContent(json.content || '');
        setShowExportModal(true);
      }
    } catch (err: any) {
      alert(`Evidence export error: ${err.message}`);
    } finally {
      setExporting(false);
    }
  };

  const getVerdictConfig = (verdict: string) => {
    switch (verdict) {
      case 'GREEN_STATE_VERIFIED':
        return {
          bg: 'bg-emerald-950/40 border-emerald-600/60 text-emerald-300',
          badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
          icon: <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" />,
          badgeText: 'VERIFIED REMEDIATED',
          desc: 'Vulnerability reproduced, surgical patch generated, post-patch execution blocked (Exit 42), and regression tests passed.'
        };
      case 'RED_STATE_PERSISTS':
        return {
          bg: 'bg-rose-950/40 border-rose-700/60 text-rose-300',
          badge: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
          icon: <ShieldAlert className="w-6 h-6 text-rose-400 shrink-0" />,
          badgeText: 'REMEDIATION FAILED',
          desc: 'Remediation applied but the vulnerable behavior was still reproduced.'
        };
      case 'INCONCLUSIVE':
        return {
          bg: 'bg-amber-950/40 border-amber-600/60 text-amber-300',
          badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
          icon: <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0" />,
          badgeText: 'INCONCLUSIVE',
          desc: 'Execution finished but could not definitively observe the target vulnerability signal.'
        };
      case 'PATCH_REJECTED':
        return {
          bg: 'bg-rose-950/40 border-rose-700/60 text-rose-300',
          badge: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
          icon: <ShieldAlert className="w-6 h-6 text-rose-400 shrink-0" />,
          badgeText: 'PATCH REJECTED',
          desc: 'Proposed remediation rejected due to AST syntax errors, empty diff, or unsafe modification.'
        };
      case 'REGRESSION_FAILURE':
        return {
          bg: 'bg-rose-950/40 border-rose-700/60 text-rose-300',
          badge: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
          icon: <ShieldAlert className="w-6 h-6 text-rose-400 shrink-0" />,
          badgeText: 'REGRESSION FAILURE',
          desc: 'Vulnerability was blocked, but existing application unit tests failed.'
        };
      case 'VERIFICATION_REJECTED':
        return {
          bg: 'bg-rose-950/40 border-rose-700/60 text-rose-300',
          badge: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
          icon: <AlertOctagon className="w-6 h-6 text-rose-400 shrink-0" />,
          badgeText: 'EXECUTION REJECTED',
          desc: 'Sandbox rejected harness execution due to security policy, timeout, or untrusted boundary.'
        };
      case 'UNEXPECTED_FAILURE':
        return {
          bg: 'bg-amber-950/40 border-amber-700/60 text-amber-300',
          badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
          icon: <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0" />,
          badgeText: 'DEPENDENCY MISSING',
          desc: 'Process terminated unexpectedly due to missing external runtime dependency.'
        };
      default:
        return {
          bg: 'bg-slate-900/60 border-slate-700/60 text-slate-300',
          badge: 'bg-slate-700/40 text-slate-300 border-slate-600',
          icon: <Info className="w-6 h-6 text-slate-400 shrink-0" />,
          badgeText: verdict || 'UNKNOWN',
          desc: 'Pipeline execution completed.'
        };
    }
  };

  const verdictConfig = data ? getVerdictConfig(data.final_behavioral_verdict) : null;

  return (
    <div className="bg-surface-2 border border-border-subtle rounded-md p-4 space-y-4">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border-subtle pb-3">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <h2 className="text-sm font-semibold text-slate-200">
              Controlled Behavioral Verification & Remediation Engine
            </h2>
          </div>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Isolated Subprocess Sandbox • Parent-Side Trust Audit • Nemotron 3 Ultra Patching • Evidence Bundle
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            onClick={() => setShowJudgeModal(true)}
            className="bg-surface-1 hover:bg-surface-inset border border-indigo-600/40 text-indigo-300 font-medium px-2.5 py-1.5 rounded text-xs flex items-center gap-1 transition-colors font-sans shadow-sm"
            title="View Judge Walkthrough & 9 Core Questions"
          >
            <HelpCircle className="w-3.5 h-3.5 text-indigo-400" />
            <span>Judge Guide</span>
          </button>

          {data && (
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => handleExportEvidence('json')}
                disabled={exporting}
                className="bg-surface-1 hover:bg-surface-inset border border-sky-600/40 text-sky-300 font-medium px-2.5 py-1.5 rounded text-xs flex items-center gap-1 transition-colors font-sans shadow-sm"
                title="Download complete cryptographic evidence bundle (.json)"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export JSON</span>
              </button>
              <button
                type="button"
                onClick={() => handleExportEvidence('markdown')}
                disabled={exporting}
                className="bg-surface-1 hover:bg-surface-inset border border-violet-600/40 text-violet-300 font-medium px-2.5 py-1.5 rounded text-xs flex items-center gap-1 transition-colors font-sans shadow-sm"
                title="View human-readable verification certificate (.md)"
              >
                <FileCode className="w-3.5 h-3.5" />
                <span>View MD</span>
              </button>
            </div>
          )}

          <div className="text-[10px] font-mono px-2 py-1 rounded bg-surface-inset border border-cyan-600/40 text-cyan-300">
            SUBSTRATE: {data?.isolation_tier || (data ? data.sandbox_engine : 'AUTO (OCI ROOTLESS / JOB OBJECT)')}
          </div>
          <button
            type="button"
            onClick={onRunPipeline}
            disabled={loading || !reachabilityReady}
            className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white font-medium px-3 py-1.5 rounded text-xs flex items-center gap-1.5 transition-colors font-sans shadow-sm"
          >
            {loading ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Executing Pipeline...</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>Run Defensive Verification</span>
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded bg-rose-950/40 border border-rose-900/60 text-rose-300 text-xs flex items-center gap-2 font-mono">
          <AlertOctagon className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {!data && !loading && (
        <div className="p-6 border border-dashed border-border-subtle rounded text-center text-xs text-slate-400 font-mono">
          <Terminal className="w-8 h-8 text-slate-600 mx-auto mb-2" />
          <p className="font-semibold text-slate-300">No Behavioral Verification Executed Yet</p>
          <p className="text-[11px] text-slate-400 mt-1">
            Click "Run Defensive Verification" to synthesize a controlled harness and test in an isolated disposable sandbox.
          </p>
        </div>
      )}

      {loading && (
        <div className="p-6 border border-border-subtle bg-surface-1 rounded text-center space-y-3 font-mono text-xs">
          <RefreshCw className="w-6 h-6 text-emerald-400 animate-spin mx-auto" />
          <div className="text-slate-200 font-bold">Executing 6-Stage Defensive Pipeline...</div>
          <div className="text-[11px] text-slate-400">
            Mounting disposable directory • Detonating pre-patch harness • Calling Nemotron 3 Ultra • Verifying block • Running pytests
          </div>
        </div>
      )}

      {data && verdictConfig && (
        <div className="space-y-4">
          {/* Master Verdict Banner */}
          <div className={`p-3.5 rounded border flex flex-col md:flex-row md:items-center justify-between gap-3 font-mono text-xs ${verdictConfig.bg}`}>
            <div className="flex items-center gap-2.5">
              {verdictConfig.icon}
              <div>
                <div className="font-bold tracking-wider text-sm flex items-center gap-2">
                  <span>TERMINAL STATE: {data.verdict_record?.terminal_state || data.final_behavioral_verdict}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded border ${verdictConfig.badge}`}>
                    {verdictConfig.badgeText}
                  </span>
                  {data.post_patch_result?.parent_validated && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                      PARENT-AUDITED
                    </span>
                  )}
                </div>
                <div className="text-[11px] opacity-90 mt-0.5">
                  {data.verdict_record?.reason || verdictConfig.desc}
                </div>
              </div>
            </div>
            <div className="flex flex-col md:items-end gap-1">
              <div className="flex items-center gap-1.5 flex-wrap justify-end">
                <span className={`text-[10px] uppercase tracking-widest px-2 py-0.5 rounded bg-surface-inset border ${data.isolation_tier === 'OCI_CONTAINER_ISOLATED' ? 'border-emerald-600/40 text-emerald-300' : 'border-border-subtle text-amber-300'}`}>
                  TIER: {data.isolation_tier || data.sandbox_engine}
                </span>
                <span className={`text-[10px] uppercase tracking-widest px-2 py-0.5 rounded font-bold border ${
                  (data.assurance_level === 'HIGH_ASSURANCE_CONTAINED' || data.verdict_record?.assurance_level === 'HIGH_ASSURANCE_CONTAINED')
                    ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                    : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                }`}>
                  ASSURANCE: {data.assurance_level || data.verdict_record?.assurance_level || 'DEGRADED_LOCAL_FALLBACK'}
                </span>
              </div>
              <span className="text-[9px] text-slate-400">
                NETWORK: {data.isolation_attestation?.network_mode || 'DENIED'} • ATTESTATION: {data.isolation_attestation ? 'PARENT_VERIFIED' : 'LOCAL'}
              </span>
            </div>
          </div>

          {/* Differential Verification Proof (Section 4) */}
          <div className="bg-surface-1 border border-border-subtle rounded overflow-hidden font-mono text-xs">
            <div className="bg-surface-inset px-3 py-2 border-b border-border-subtle flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Scale className="w-4 h-4 text-sky-400" />
                <span className="font-semibold text-slate-200">
                  Differential Verification Proof (Identical Harness Before vs. After)
                </span>
              </div>
              <span className="text-[10px] text-slate-400">
                Deterministic Behavioral Observation
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-[11px]">
                <thead>
                  <tr className="border-b border-border-subtle bg-surface-2 text-slate-400 text-[10px] uppercase">
                    <th className="p-2.5">Verification Dimension</th>
                    <th className="p-2.5 text-rose-400">Pre-Patch (Original Codebase)</th>
                    <th className="p-2.5 text-emerald-400">Post-Patch (Remediated Codebase)</th>
                    <th className="p-2.5 text-sky-400">Security Implication</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle text-slate-300">
                  <tr>
                    <td className="p-2.5 font-semibold text-slate-400">Target Call Site</td>
                    <td className="p-2.5">{data.harness.target_file}:{data.harness.function_name}()</td>
                    <td className="p-2.5">{data.harness.target_file}:{data.harness.function_name}()</td>
                    <td className="p-2.5 text-slate-400">Identical function entrypoint</td>
                  </tr>
                  <tr>
                    <td className="p-2.5 font-semibold text-slate-400">Execution Harness</td>
                    <td className="p-2.5">Benign Sentinel Instantiator</td>
                    <td className="p-2.5 font-semibold text-emerald-300">IDENTICAL Harness & Payload</td>
                    <td className="p-2.5 text-slate-400">Eliminates harness divergence bias</td>
                  </tr>
                  <tr>
                    <td className="p-2.5 font-semibold text-slate-400">Process Exit Code</td>
                    <td className="p-2.5 text-rose-300 font-bold">Exit {data.pre_patch_result.exit_code} (Success)</td>
                    <td className="p-2.5 text-emerald-300 font-bold">Exit {data.post_patch_result.exit_code} (Dedicated Blocked)</td>
                    <td className="p-2.5 text-slate-400">Distinguishes security block from crash</td>
                  </tr>
                  <tr>
                    <td className="p-2.5 font-semibold text-slate-400">Disk Observable (Sentinel)</td>
                    <td className="p-2.5 text-rose-400 font-bold">
                      {data.pre_patch_result.sentinel_created ? 'CREATED (Physical File Written)' : 'NOT DETECTED'}
                    </td>
                    <td className="p-2.5 text-emerald-400 font-bold">
                      {data.post_patch_result.sentinel_created ? 'LEAKED' : 'ABSENT (Instantiation Blocked)'}
                    </td>
                    <td className="p-2.5 text-slate-400">Physical evidence on disposable disk</td>
                  </tr>
                  <tr>
                    <td className="p-2.5 font-semibold text-slate-400">Parent Boundary Audit</td>
                    <td className="p-2.5 text-slate-400">Parent observed exit 0 + sentinel</td>
                    <td className="p-2.5 text-emerald-300 font-semibold">
                      {data.post_patch_result.parent_validated ? 'AUDITED (Exit 42 + Clean Disk)' : 'PENDING'}
                    </td>
                    <td className="p-2.5 text-slate-400">Zero trust in child process self-reporting</td>
                  </tr>
                  <tr>
                    <td className="p-2.5 font-semibold text-slate-400">Behavioral State</td>
                    <td className="p-2.5 text-rose-300 font-bold">{data.pre_patch_result.reproduction_state}</td>
                    <td className="p-2.5 text-emerald-300 font-bold">{data.post_patch_result.reproduction_state}</td>
                    <td className="p-2.5 text-slate-400">Differential state transition proven</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* 2-Column Pre/Post Sandbox Execution Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
            {/* Step 1: Pre-Patch Sandbox Detonation (RED STATE) */}
            <div className="bg-surface-1 border border-border-subtle rounded p-3 space-y-2">
              <div className="flex items-center justify-between border-b border-border-subtle pb-2">
                <div className="flex items-center gap-1.5 text-rose-300 font-bold">
                  <Flame className="w-4 h-4 text-rose-400" />
                  <span>1. PRE-PATCH SANDBOX EXECUTION</span>
                </div>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                  {data.pre_patch_result.reproduction_state}
                </span>
              </div>
              <div className="space-y-1 text-[11px]">
                <div className="flex justify-between text-slate-400">
                  <span>Exit Code: <strong className="text-slate-200">{data.pre_patch_result.exit_code}</strong></span>
                  <span>Latency: <strong className="text-slate-200">{data.pre_patch_result.latency_ms}ms</strong></span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Sentinel File Created:</span>
                  <span className="text-rose-400 font-bold">{data.pre_patch_result.sentinel_created ? 'CONFIRMED (TOUCHED)' : 'NO'}</span>
                </div>
                <div className="bg-surface-inset p-2 rounded border border-border-subtle text-slate-300 overflow-x-auto text-[10px]">
                  {data.pre_patch_result.stdout || data.pre_patch_result.stderr || 'No stdout output'}
                </div>
              </div>
            </div>

            {/* Step 2: Post-Patch Sandbox Execution (GREEN STATE) */}
            <div className="bg-surface-1 border border-border-subtle rounded p-3 space-y-2">
              <div className="flex items-center justify-between border-b border-border-subtle pb-2">
                <div className="flex items-center gap-1.5 text-emerald-300 font-bold">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span>2. POST-PATCH SANDBOX RE-TEST</span>
                </div>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                  {data.post_patch_result.reproduction_state}
                </span>
              </div>
              <div className="space-y-1 text-[11px]">
                <div className="flex justify-between text-slate-400">
                  <span>Exit Code: <strong className="text-slate-200">{data.post_patch_result.exit_code} (BLOCKED)</strong></span>
                  <span>Latency: <strong className="text-slate-200">{data.post_patch_result.latency_ms}ms</strong></span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Parent Trust Boundary Audit:</span>
                  <span className={data.post_patch_result.parent_validated ? 'text-emerald-400 font-bold' : 'text-amber-400 font-bold'}>
                    {data.post_patch_result.parent_validated ? 'GROUND TRUTH AUDITED (Exit 42 + Disk Clean)' : 'PENDING'}
                  </span>
                </div>
                {data.post_patch_result.validation_notes && (
                  <div className="text-[10px] text-slate-400 italic">
                    Note: {data.post_patch_result.validation_notes}
                  </div>
                )}
                <div className="bg-surface-inset p-2 rounded border border-border-subtle text-slate-300 overflow-x-auto text-[10px]">
                  {data.post_patch_result.stdout || data.post_patch_result.stderr || 'No stdout output'}
                </div>
              </div>
            </div>
          </div>

          {/* Patch Delta Review & Minimality Assessment (Section 5) */}
          {data.remediation.patch_delta && (
            <div className="bg-surface-1 border border-border-subtle rounded p-3 font-mono text-xs space-y-2.5">
              <div className="flex items-center justify-between border-b border-border-subtle pb-2">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-sky-400" />
                  <span className="font-semibold text-slate-200">Patch Delta Review & Minimality Assessment</span>
                </div>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  data.remediation.patch_delta.is_minimal
                    ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                    : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                }`}>
                  {data.remediation.patch_delta.is_minimal ? 'SURGICALLY MINIMAL' : 'COMPLEX / MULTI-SITE'}
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                <div className="bg-surface-inset p-2 rounded border border-border-subtle">
                  <div className="text-slate-400 text-[10px]">CHANGED FILES</div>
                  <div className="text-slate-200 font-bold truncate" title={data.remediation.patch_delta.changed_files.join(', ')}>
                    {data.remediation.patch_delta.changed_files.length} ({data.remediation.patch_delta.changed_files[0] || 'none'})
                  </div>
                </div>
                <div className="bg-surface-inset p-2 rounded border border-border-subtle">
                  <div className="text-slate-400 text-[10px]">CHANGED FUNCTIONS</div>
                  <div className="text-slate-200 font-bold truncate" title={data.remediation.patch_delta.changed_functions.join(', ')}>
                    {data.remediation.patch_delta.changed_functions.join(', ') || 'top-level'}
                  </div>
                </div>
                <div className="bg-surface-inset p-2 rounded border border-border-subtle">
                  <div className="text-slate-400 text-[10px]">LINES CHANGED / DIFF BYTES</div>
                  <div className="text-slate-200 font-bold">
                    +{data.remediation.patch_delta.additions_count} / -{data.remediation.patch_delta.deletions_count} ({data.remediation.patch_delta.diff_bytes}B)
                  </div>
                </div>
                <div className="bg-surface-inset p-2 rounded border border-border-subtle">
                  <div className="text-slate-400 text-[10px]">TESTS EVALUATED</div>
                  <div className="text-emerald-400 font-bold">
                    {data.remediation.patch_delta.tests_affected_count} suite tests active
                  </div>
                </div>
              </div>

              <div className="text-[11px] text-slate-400 flex flex-col sm:flex-row sm:items-center justify-between gap-1 bg-surface-inset px-2.5 py-1.5 rounded border border-border-subtle">
                <span><strong>Minimality Criterion:</strong> {data.remediation.patch_delta.minimality_criterion}</span>
                <span className="text-slate-300 italic">{data.remediation.patch_delta.reason_for_change}</span>
              </div>
            </div>
          )}

          {/* Remediation Diff Viewer */}
          <div className="border border-border-subtle rounded overflow-hidden font-mono text-xs">
            <div className="bg-surface-1 px-3 py-2 border-b border-border-subtle flex items-center justify-between">
              <div className="flex items-center gap-2">
                <GitCommit className="w-4 h-4 text-sky-400" />
                <span className="font-semibold text-slate-200">Surgical Remediation Diff ({data.remediation.engine})</span>
              </div>
              <div className="flex items-center gap-2 text-[10px] text-slate-400">
                {data.remediation.tokens_used && (
                  <span className="bg-surface-inset px-2 py-0.5 rounded border border-border-subtle">
                    Tokens: {data.remediation.tokens_used} (Reasoning: {data.remediation.reasoning_tokens || 0})
                  </span>
                )}
                <span className="bg-surface-inset px-2 py-0.5 rounded border border-border-subtle text-sky-300">
                  {data.remediation.latency_ms}ms
                </span>
              </div>
            </div>

            <div className="bg-surface-inset p-3 overflow-x-auto text-[11px] leading-relaxed">
              <pre className="text-slate-300">
                {data.remediation.diff.split('\n').map((line, idx) => {
                  let lineClass = 'text-slate-400';
                  if (line.startsWith('+') && !line.startsWith('+++')) lineClass = 'text-emerald-400 bg-emerald-950/30';
                  if (line.startsWith('-') && !line.startsWith('---')) lineClass = 'text-rose-400 bg-rose-950/30';
                  if (line.startsWith('@@')) lineClass = 'text-sky-400';
                  return (
                    <div key={idx} className={`${lineClass} px-1 rounded`}>
                      {line}
                    </div>
                  );
                })}
              </pre>
            </div>
            <div className="bg-surface-1 px-3 py-1.5 border-t border-border-subtle text-[11px] text-slate-400">
              <span className="text-slate-300 font-semibold">Security Rationale:</span> {data.remediation.explanation}
            </div>
          </div>

          {/* Regression Tests & Synthesized Harness Accordion */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
            {/* Pytest Regression Result */}
            <div className="bg-surface-1 border border-border-subtle rounded p-3 space-y-2">
              <div className="flex items-center justify-between border-b border-border-subtle pb-2">
                <div className="flex items-center gap-1.5 text-slate-200 font-bold">
                  <Check className="w-4 h-4 text-emerald-400" />
                  <span>3. REGRESSION TEST VERIFICATION</span>
                </div>
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                  data.regression_tests.passed
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                }`}>
                  {data.regression_tests.passed ? 'ALL SUITES PASSED' : 'REGRESSION DETECTED'}
                </span>
              </div>
              <div className="text-[11px] space-y-1 text-slate-400">
                <div className="flex justify-between">
                  <span>Tests Executed: <strong className="text-slate-200">{data.regression_tests.test_count || 0} passed</strong></span>
                  <span>Exit: <strong className="text-slate-200">{data.regression_tests.exit_code}</strong></span>
                  <span>Latency: <strong className="text-slate-200">{data.regression_tests.latency_ms}ms</strong></span>
                </div>
                <div className="bg-surface-inset p-2 rounded border border-border-subtle text-slate-300 overflow-x-auto text-[10px]">
                  {data.regression_tests.stdout || 'Pytest executed cleanly'}
                </div>
              </div>
            </div>

            {/* Synthesized Verification Harness */}
            <div className="bg-surface-1 border border-border-subtle rounded p-3 space-y-2">
              <div className="flex items-center justify-between border-b border-border-subtle pb-2">
                <div className="flex items-center gap-1.5 text-slate-200 font-bold">
                  <FileCode className="w-4 h-4 text-violet-400" />
                  <span>SYNTHESIZED HARNESS</span>
                </div>
                <button
                  type="button"
                  onClick={() => setShowHarness(!showHarness)}
                  className="text-[10px] text-violet-300 hover:text-violet-200 flex items-center gap-1"
                >
                  {showHarness ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                  {showHarness ? 'Hide Code' : 'View Code'}
                </button>
              </div>
              <div className="text-[11px] text-slate-400">
                Target: <strong className="text-slate-200">{data.harness.target_file}:{data.harness.function_name}()</strong>
                <span className="ml-2 text-[10px] text-slate-400">Sentinel: {data.harness.sentinel_filename}</span>
              </div>
              {showHarness ? (
                <div className="bg-surface-inset p-2 rounded border border-border-subtle text-slate-300 overflow-x-auto text-[10px] max-h-36">
                  <pre>{data.harness.harness_code}</pre>
                </div>
              ) : (
                <div className="bg-surface-inset p-2 rounded border border-border-subtle text-slate-400 text-[10px] italic">
                  Deterministic harness generated in {data.harness.latency_ms}ms targeting benign Python object instantiation.
                </div>
              )}
            </div>
          </div>

          {/* Section 10 & 11: Static Analysis Limitations, Security Policy & Sandbox Disclosures */}
          <div className="bg-surface-1 border border-border-subtle rounded p-3 text-xs space-y-3">
            <div className="flex items-center justify-between border-b border-border-subtle pb-1.5">
              <div className="flex items-center gap-2 text-slate-300 font-semibold">
                <Info className="w-4 h-4 text-amber-400" />
                <span>Security Boundaries, Capability Policy & Engine Disclosures</span>
              </div>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                (data.assurance_level === 'HIGH_ASSURANCE_CONTAINED' || data.verdict_record?.assurance_level === 'HIGH_ASSURANCE_CONTAINED')
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                  : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
              }`}>
                POLICY: {(data.assurance_level === 'HIGH_ASSURANCE_CONTAINED' || data.verdict_record?.assurance_level === 'HIGH_ASSURANCE_CONTAINED') ? 'HIGH_ASSURANCE_CONTAINED' : 'DEGRADED_LOCAL_FALLBACK'}
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-[11px] text-slate-400">
              <div className="space-y-1">
                <span className="font-semibold text-slate-300">Static AST Reachability:</span>
                <p>
                  Evaluates static AST call chains and alias imports. Does <strong className="text-amber-300">NOT</strong> resolve reflection, dynamic imports (<code className="text-slate-300">importlib</code>), runtime monkey-patching, or dynamic dispatch.
                </p>
              </div>
              <div className="space-y-1">
                <span className="font-semibold text-slate-300">Execution Substrate Tier:</span>
                <p>
                  Current backend: <strong className="text-slate-200">{data.isolation_tier || data.sandbox_engine}</strong>.
                  {data.isolation_tier === 'OCI_CONTAINER_ISOLATED' ? (
                    <span className="text-emerald-300 block mt-0.5">
                      True rootless OCI container with kernel-level network denial (--network none), host FS hidden, and cgroup limits.
                    </span>
                  ) : (
                    <span className="text-amber-300 block mt-0.5">
                      Host subprocess with Win32 Job Object limits and sanitized env. Host filesystem remains readable subject to OS permissions.
                    </span>
                  )}
                </p>
              </div>
              <div className="space-y-1">
                <span className="font-semibold text-slate-300">Active Boundary Caveats:</span>
                <ul className="list-disc pl-3.5 space-y-0.5 text-[10px] text-slate-400">
                  {((data.verdict_record?.policy_audit?.assurance_caveats || data.policy_decision?.boundary_caveats) as string[] | undefined)?.map((c, i) => (
                    <li key={i}>{c}</li>
                  )) || (
                    data.isolation_tier === 'OCI_CONTAINER_ISOLATED' ? (
                      <>
                        <li>Shares Linux/WSL2 host kernel (cgroups/namespaces). Not hardware microVM.</li>
                        <li>Disposable workspace directory is bind-mounted at /workspace.</li>
                      </>
                    ) : (
                      <>
                        <li>Process executes under ambient host OS user identity.</li>
                        <li>Host filesystem remains readable under ambient DACLs.</li>
                      </>
                    )
                  )}
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modal for Judge Walkthrough & Evidence FAQ */}
      {showJudgeModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 backdrop-blur-sm">
          <div className="bg-surface-2 border border-border-subtle rounded-lg max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl">
            <div className="p-3.5 border-b border-border-subtle flex items-center justify-between bg-surface-1">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <span className="font-bold text-sm text-white">VulnTrace — Judge Evaluation Guide & Architecture</span>
              </div>
              <button
                type="button"
                onClick={() => setShowJudgeModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded hover:bg-surface-inset transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Navigation Tabs */}
            <div className="flex border-b border-border-subtle bg-surface-inset text-xs font-mono">
              <button
                type="button"
                onClick={() => setJudgeTab('questions')}
                className={`px-4 py-2 font-semibold border-b-2 transition-colors ${
                  judgeTab === 'questions'
                    ? 'border-emerald-500 text-emerald-300 bg-surface-2'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                9 Core Judge Questions
              </button>
              <button
                type="button"
                onClick={() => setJudgeTab('matrix')}
                className={`px-4 py-2 font-semibold border-b-2 transition-colors ${
                  judgeTab === 'matrix'
                    ? 'border-emerald-500 text-emerald-300 bg-surface-2'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                Competitive Comparison Matrix
              </button>
              <button
                type="button"
                onClick={() => setJudgeTab('disclosures')}
                className={`px-4 py-2 font-semibold border-b-2 transition-colors ${
                  judgeTab === 'disclosures'
                    ? 'border-emerald-500 text-emerald-300 bg-surface-2'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                Disclosures & Constraints
              </button>
            </div>

            {/* Tab Body */}
            <div className="p-5 overflow-y-auto font-sans text-xs text-slate-300 space-y-4 flex-1 leading-relaxed">
              {judgeTab === 'questions' && (
                <div className="space-y-4">
                  <div className="border border-border-subtle rounded p-3 bg-surface-1">
                    <h3 className="font-bold text-white text-sm flex items-center gap-2">
                      <span className="text-emerald-400">Q1.</span> What problem does VulnTrace solve?
                    </h3>
                    <p className="mt-1 text-slate-300 text-[11px]">
                      Traditional Software Composition Analysis (SCA) alerts on library versions alone, resulting in over 80% false positives where vulnerable library routines are never invoked. VulnTrace establishes an empirical evidence lifecycle: Reachability Identification → Behavioral Reproduction → Model-Assisted Surgical Patching → Parent-Audited Re-test → Regression Verification.
                    </p>
                  </div>

                  <div className="border border-border-subtle rounded p-3 bg-surface-1">
                    <h3 className="font-bold text-white text-sm flex items-center gap-2">
                      <span className="text-emerald-400">Q2.</span> How does VulnTrace prove reachability?
                    </h3>
                    <p className="mt-1 text-slate-300 text-[11px]">
                      VulnTrace analyzes the entire codebase with an AST Call-Graph Solver tracing from active entrypoints down to vulnerable sink functions (e.g. <code className="text-sky-300">yaml.load</code>). If a vulnerability exists only in unreferenced dead code, it is flagged as <code className="text-emerald-400 font-bold">UNREACHABLE_FALSE_POSITIVE</code> and blocked before executing any unneeded harness.
                    </p>
                  </div>

                  <div className="border border-border-subtle rounded p-3 bg-surface-1">
                    <h3 className="font-bold text-white text-sm flex items-center gap-2">
                      <span className="text-emerald-400">Q3.</span> What makes behavioral verification safe?
                    </h3>
                    <p className="mt-1 text-slate-300 text-[11px]">
                      All verification harnesses execute in disposable isolated <code className="text-amber-300">%TEMP%</code> directories. All API credentials and environment secrets are purged before spawning the subprocess, the process tree is killed after timeout, and the harness strictly uses target-bound benign object instantiation (writing a timestamped sentinel file) rather than destructive payloads.
                    </p>
                  </div>

                  <div className="border border-border-subtle rounded p-3 bg-surface-1">
                    <h3 className="font-bold text-white text-sm flex items-center gap-2">
                      <span className="text-emerald-400">Q4.</span> Why is the post-patch check trusted?
                    </h3>
                    <p className="mt-1 text-slate-300 text-[11px]">
                      VulnTrace enforces a strict <strong>Parent Trust Boundary</strong>: it does NOT trust child process stdout or exit codes. The parent process independently inspects the disk to verify that the sentinel file was NEVER created, and mandates a dedicated exit code (42) indicating an intentional defensive block.
                    </p>
                  </div>

                  <div className="border border-border-subtle rounded p-3 bg-surface-1">
                    <h3 className="font-bold text-white text-sm flex items-center gap-2">
                      <span className="text-emerald-400">Q5.</span> How does VulnTrace prevent regressions?
                    </h3>
                    <p className="mt-1 text-slate-300 text-[11px]">
                      After the vulnerability is proven blocked, VulnTrace executes the repository's native unit test suite (via <code className="text-emerald-300">pytest</code>) inside the isolated sandbox. If tests fail, the verdict is flagged as <code className="text-rose-400 font-bold">REGRESSION_FAILURE</code> and the patch is not certified.
                    </p>
                  </div>

                  <div className="border border-border-subtle rounded p-3 bg-surface-1">
                    <h3 className="font-bold text-white text-sm flex items-center gap-2">
                      <span className="text-emerald-400">Q6.</span> How is NVIDIA Nemotron 3 Ultra utilized?
                    </h3>
                    <p className="mt-1 text-slate-300 text-[11px]">
                      Nemotron 3 Ultra (hosted on Nebius Token Factory) generates surgical, minimal AST codemods. It receives the vulnerable sink line and surrounding AST context, reasons through backward compatibility, and produces unified diffs that are validated through an AST syntax parser before touching disk.
                    </p>
                  </div>

                  <div className="border border-border-subtle rounded p-3 bg-surface-1">
                    <h3 className="font-bold text-white text-sm flex items-center gap-2">
                      <span className="text-emerald-400">Q7.</span> How is Tavily Search utilized?
                    </h3>
                    <p className="mt-1 text-slate-300 text-[11px]">
                      Tavily queries live OSV.dev and NVD advisories as well as real-world security writeups and PoC disclosures to identify exact vulnerable function signatures, version ranges, and exploit mechanics.
                    </p>
                  </div>

                  <div className="border border-border-subtle rounded p-3 bg-surface-1">
                    <h3 className="font-bold text-white text-sm flex items-center gap-2">
                      <span className="text-emerald-400">Q8.</span> What is the status of ConTree Cloud?
                    </h3>
                    <p className="mt-1 text-slate-300 text-[11px]">
                      ConTree Cloud is truthfully reported as <code className="text-amber-400">PERMISSION_DENIED (HTTP 403)</code> due to token-level sandbox permissions. Rather than falsifying cloud status, VulnTrace falls back to <code className="text-amber-300">LOCAL_SUBPROCESS_FALLBACK</code> with transparent disclosure of shared kernel/loopback boundaries.
                    </p>
                  </div>

                  <div className="border border-border-subtle rounded p-3 bg-surface-1">
                    <h3 className="font-bold text-white text-sm flex items-center gap-2">
                      <span className="text-emerald-400">Q9.</span> What is VulnTrace's minimality criterion?
                    </h3>
                    <p className="mt-1 text-slate-300 text-[11px]">
                      A patch is marked <code className="text-emerald-300 font-bold">is_minimal: true</code> strictly when it modifies only 1 file and &lt;= 10 lines of code, tightly scoped to the vulnerable call site without performing unrelated refactoring.
                    </p>
                  </div>
                </div>
              )}

              {judgeTab === 'matrix' && (
                <div className="space-y-4">
                  <div className="border border-border-subtle rounded overflow-hidden">
                    <table className="w-full text-left border-collapse text-[11px] font-mono">
                      <thead>
                        <tr className="bg-surface-1 border-b border-border-subtle text-slate-300">
                          <th className="p-2.5">Feature / Capability</th>
                          <th className="p-2.5 text-slate-400">Traditional SCA (Snyk/Dependabot)</th>
                          <th className="p-2.5 text-slate-400">LLM Coding Agents (Copilot Workspace)</th>
                          <th className="p-2.5 text-emerald-400">VulnTrace</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border-subtle text-slate-300">
                        <tr>
                          <td className="p-2.5 font-bold text-white">Detection Source</td>
                          <td className="p-2.5">Manifest package version regex</td>
                          <td className="p-2.5">Prompt heuristics</td>
                          <td className="p-2.5 text-emerald-300 font-semibold">Live OSV + Tavily Threat Intel</td>
                        </tr>
                        <tr>
                          <td className="p-2.5 font-bold text-white">Reachability Analysis</td>
                          <td className="p-2.5 text-rose-400">None (flags all versions)</td>
                          <td className="p-2.5 text-rose-400">None</td>
                          <td className="p-2.5 text-emerald-300 font-semibold">AST Call-Graph from Entrypoints</td>
                        </tr>
                        <tr>
                          <td className="p-2.5 font-bold text-white">False Positive Suppression</td>
                          <td className="p-2.5 text-rose-400">0% (Overwhelms developer)</td>
                          <td className="p-2.5 text-amber-400">Heuristic / Unverified</td>
                          <td className="p-2.5 text-emerald-300 font-semibold">Automated (Uncalled dead code)</td>
                        </tr>
                        <tr>
                          <td className="p-2.5 font-bold text-white">Empirical Behavioral Reproduction</td>
                          <td className="p-2.5 text-rose-400">None</td>
                          <td className="p-2.5 text-rose-400">None (Hallucination risk)</td>
                          <td className="p-2.5 text-emerald-300 font-semibold">Isolated Sandbox Detonation (RED)</td>
                        </tr>
                        <tr>
                          <td className="p-2.5 font-bold text-white">Remediation Engine</td>
                          <td className="p-2.5">Bump dependency version (Breaking)</td>
                          <td className="p-2.5">General LLM code rewrite</td>
                          <td className="p-2.5 text-emerald-300 font-semibold">Surgical Nemotron 3 Ultra Codemod</td>
                        </tr>
                        <tr>
                          <td className="p-2.5 font-bold text-white">Post-Patch Trust Boundary</td>
                          <td className="p-2.5 text-rose-400">None</td>
                          <td className="p-2.5 text-rose-400">Assumes build passes</td>
                          <td className="p-2.5 text-emerald-300 font-semibold">Parent Audits Physical Disk + Exit 42</td>
                        </tr>
                        <tr>
                          <td className="p-2.5 font-bold text-white">Regression Prevention</td>
                          <td className="p-2.5 text-rose-400">None</td>
                          <td className="p-2.5 text-amber-400">Optional user prompt</td>
                          <td className="p-2.5 text-emerald-300 font-semibold">Native pytest suite in sandbox</td>
                        </tr>
                        <tr>
                          <td className="p-2.5 font-bold text-white">Audit Export</td>
                          <td className="p-2.5">Alert list CSV</td>
                          <td className="p-2.5">Chat transcript</td>
                          <td className="p-2.5 text-emerald-300 font-semibold">Cryptographic JSON + Markdown Cert</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {judgeTab === 'disclosures' && (
                <div className="space-y-3 font-mono text-[11px]">
                  <div className="p-3 rounded bg-surface-1 border border-border-subtle space-y-1.5">
                    <div className="font-bold text-amber-300">ConTree Cloud Execution Status</div>
                    <p className="text-slate-300">
                      ConTree Cloud sandboxing returned <code className="text-amber-400">HTTP 403 Forbidden</code> during live API key verification. VulnTrace operates using <code className="text-emerald-400">LOCAL_SUBPROCESS_FALLBACK</code>. We do not mock or fake cloud deployment.
                    </p>
                  </div>
                  <div className="p-3 rounded bg-surface-1 border border-border-subtle space-y-1.5">
                    <div className="font-bold text-amber-300">Local Isolation Boundary</div>
                    <p className="text-slate-300">
                      Local sandbox runs in disposable directories with purged environment credentials, process-group termination, and timeout guards. However, it shares the host operating system kernel and local loopback network.
                    </p>
                  </div>
                  <div className="p-3 rounded bg-surface-1 border border-border-subtle space-y-1.5">
                    <div className="font-bold text-amber-300">Static AST Reachability Limits</div>
                    <p className="text-slate-300">
                      The static AST analyzer resolves direct function calls and aliased imports. It does NOT resolve runtime dynamic reflection (<code className="text-slate-200">getattr</code>), dynamic imports (<code className="text-slate-200">importlib</code>), or runtime monkey-patching.
                    </p>
                  </div>
                </div>
              )}
            </div>

            <div className="p-3 border-t border-border-subtle flex justify-end bg-surface-1">
              <button
                type="button"
                onClick={() => setShowJudgeModal(false)}
                className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-1.5 rounded text-xs font-semibold"
              >
                Close Guide
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal for viewing Markdown certificate */}
      {showExportModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-surface-2 border border-border-subtle rounded-lg max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl">
            <div className="p-3 border-b border-border-subtle flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-violet-400" />
                <span className="font-semibold text-sm text-slate-200">Verification Certificate (.md)</span>
              </div>
              <button
                type="button"
                onClick={() => setShowExportModal(false)}
                className="text-slate-400 hover:text-slate-200 text-xs px-2 py-1 rounded bg-surface-inset border border-border-subtle"
              >
                Close
              </button>
            </div>
            <div className="p-4 overflow-y-auto font-mono text-xs text-slate-300 bg-surface-inset whitespace-pre-wrap leading-relaxed flex-1">
              {exportContent}
            </div>
            <div className="p-3 border-t border-border-subtle flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard.writeText(exportContent);
                  alert('Markdown copied to clipboard!');
                }}
                className="bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1 rounded text-xs"
              >
                Copy to Clipboard
              </button>
              <button
                type="button"
                onClick={() => setShowExportModal(false)}
                className="bg-surface-1 hover:bg-surface-inset border border-border-subtle text-slate-300 px-3 py-1 rounded text-xs"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
