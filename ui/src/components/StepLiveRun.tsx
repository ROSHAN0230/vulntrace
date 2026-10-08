import React, { useRef, useEffect } from 'react';
import {
  PlayCircle,
  RefreshCw,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Terminal,
  Clock,
  Layers
} from 'lucide-react';
import { StudioEvent, TokenLedgerSummary, CanonicalVerdict } from '../types';

interface StepLiveRunProps {
  runId?: string;
  isExecuting: boolean;
  events: StudioEvent[];
  currentStage: string;
  verdict?: CanonicalVerdict | string;
  tokenLedger?: TokenLedgerSummary;
  error?: string;
  onExecute: () => void;
  onProceedToEvidence: () => void;
}

interface StageDefinition {
  id: string;
  name: string;
  description: string;
}

const STAGES: StageDefinition[] = [
  { id: 'ENVBUILD', name: 'Environment Build', description: 'Tier-1 isolated virtualenv provisioning' },
  { id: 'REPRODUCTION', name: 'RED State Reproduction', description: 'Flake check: RED 1/3, 2/3, 3/3 confirmed' },
  { id: 'REMEDIATION', name: 'Nemotron Remediation', description: 'Tier-3 Ultra surgical patch synthesis (N/3)' },
  { id: 'SCOPE_GUARD', name: 'Scope Guard Budget', description: 'Line budget and file boundary check' },
  { id: 'VERIFICATION', name: 'GREEN State Verification', description: 'Flake check: GREEN 1/3, 2/3, 3/3 confirmed' },
  { id: 'REGRESSION', name: 'Regression Suite', description: 'Baseline vs after-patch comparison' },
  { id: 'EVIDENCE', name: 'Evidence Signing', description: 'Canonical JSON (RFC 8785) & Ed25519 seal' }
];

export const StepLiveRun: React.FC<StepLiveRunProps> = ({
  runId,
  isExecuting,
  events,
  currentStage,
  verdict,
  tokenLedger,
  error,
  onExecute,
  onProceedToEvidence
}) => {
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll terminal smoothly without layout shifting
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events]);

  const isCompleted = verdict && verdict !== 'INITIALIZED' && verdict !== 'RUNNING';

  const getStageStatus = (stageId: string) => {
    const hasStageCompleted = events.some(
      (e) => (e.stage?.toUpperCase() === stageId || e.event_type === 'STAGE_COMPLETE') && e.stage?.toUpperCase().includes(stageId)
    );
    const isStageCurrent = currentStage?.toUpperCase().includes(stageId);

    if (hasStageCompleted) return 'COMPLETED';
    if (isStageCurrent && isExecuting) return 'ACTIVE';
    return 'PENDING';
  };

  return (
    <section aria-labelledby="step-live-run-title" className="space-y-6">
      {/* Title & Execution Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 id="step-live-run-title" className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <PlayCircle className="w-5 h-5 text-emerald-400" aria-hidden="true" />
            Step 5: Autonomous Execution & Live Event Stream
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Real-time SSE event streaming, 3x flake checks, and live token ledger telemetry (Spec §4.4, §4.13).
          </p>
        </div>

        <div className="flex items-center gap-2">
          {!isExecuting && !isCompleted && (
            <button
              type="button"
              onClick={onExecute}
              className="flex items-center gap-2 px-4 py-2 rounded bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-mono transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
            >
              <PlayCircle className="w-4 h-4" aria-hidden="true" />
              <span>Launch Verification Pipeline</span>
            </button>
          )}

          {isCompleted && (
            <button
              type="button"
              onClick={onProceedToEvidence}
              className="flex items-center gap-2 px-4 py-2 rounded bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-mono transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
            >
              <span>Inspect Step 6: Evidence Bundle</span>
              <ArrowRight className="w-4 h-4" aria-hidden="true" />
            </button>
          )}
        </div>
      </div>

      {/* Top Telemetry & Status Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
        {/* Pipeline Execution State */}
        <div className="rounded-lg border border-border-subtle bg-surface-2 p-3.5 space-y-1">
          <span className="text-[11px] text-slate-400 uppercase">PIPELINE EXECUTION STATE</span>
          <div className="flex items-center gap-2 text-sm font-bold">
            {isExecuting ? (
              <span className="flex items-center gap-2 text-sky-400">
                <RefreshCw className="w-4 h-4 animate-spin text-sky-400" aria-hidden="true" />
                <span>EXECUTING ({currentStage || 'PIPELINE'})</span>
              </span>
            ) : isCompleted ? (
              <span className="flex items-center gap-1.5 text-emerald-400">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" aria-hidden="true" />
                <span>TERMINAL: {verdict}</span>
              </span>
            ) : (
              <span className="text-slate-400">AWAITING TRIGGER</span>
            )}
          </div>
        </div>

        {/* Live Token Ledger Card */}
        <div className="rounded-lg border border-border-subtle bg-surface-2 p-3.5 space-y-1">
          <span className="text-[11px] text-slate-400 uppercase flex items-center justify-between">
            <span>LIVE TOKEN LEDGER</span>
            <Cpu className="w-3.5 h-3.5 text-sky-400" aria-hidden="true" />
          </span>
          <div className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <span>{tokenLedger ? `${tokenLedger.total_tokens} Total` : '0 Tokens'}</span>
            <span className="text-xs text-slate-400 font-normal">
              ({tokenLedger ? `${tokenLedger.prompt_tokens} in / ${tokenLedger.completion_tokens} out` : '0 in / 0 out'})
            </span>
          </div>
        </div>

        {/* Flake Check Invariant */}
        <div className="rounded-lg border border-border-subtle bg-surface-2 p-3.5 space-y-1">
          <span className="text-[11px] text-slate-400 uppercase">FLAKE CHECK INVARIANT</span>
          <div className="text-sm font-bold text-emerald-400 flex items-center gap-2">
            <span className="px-1.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/60 text-xs text-emerald-300">
              3/3 REPEATS MANDATORY
            </span>
            <span className="text-[11px] text-slate-400 font-normal">Spec §4.4</span>
          </div>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div
          role="alert"
          aria-live="assertive"
          className="rounded-lg border border-rose-800/60 bg-rose-950/30 p-4 text-xs font-mono text-rose-200 space-y-1"
        >
          <div className="flex items-center gap-2 font-semibold text-rose-400">
            <AlertTriangle className="w-4 h-4 text-rose-500" aria-hidden="true" />
            <span>EXECUTION FAILURE / REJECTION</span>
          </div>
          <p className="text-rose-300 font-sans">{error}</p>
        </div>
      )}

      {/* Main Execution View: Stage Timeline & SSE Terminal */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Stage Timeline (4 cols) */}
        <div className="lg:col-span-5 rounded-lg border border-border-subtle bg-surface-2 p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-border-subtle pb-2">
            <span className="text-xs font-mono font-bold text-slate-200 flex items-center gap-2">
              <Layers className="w-4 h-4 text-emerald-400" aria-hidden="true" />
              EXECUTION STAGE TIMELINE
            </span>
            <span className="text-[11px] font-mono text-slate-400">7 Stages</span>
          </div>

          <ol className="space-y-2 text-xs font-mono">
            {STAGES.map((s, idx) => {
              const status = getStageStatus(s.id);
              let icon = <Clock className="w-4 h-4 text-slate-500" />;
              let textClass = 'text-slate-400';
              let borderClass = 'border-border-subtle bg-surface-inset';

              if (status === 'COMPLETED') {
                icon = <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
                textClass = 'text-slate-200 font-semibold';
                borderClass = 'border-emerald-500/40 bg-emerald-950/10';
              } else if (status === 'ACTIVE') {
                icon = <RefreshCw className="w-4 h-4 text-sky-400 animate-spin" />;
                textClass = 'text-sky-300 font-bold';
                borderClass = 'border-sky-500/60 bg-sky-950/20';
              }

              return (
                <li key={s.id} className={`p-2.5 rounded border transition-colors flex items-start gap-3 ${borderClass}`}>
                  <div className="mt-0.5 shrink-0">{icon}</div>
                  <div className="space-y-0.5 flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <span className={textClass}>
                        {idx + 1}. {s.name}
                      </span>
                      <span className="text-[10px] text-slate-500 uppercase">{status}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 truncate">{s.description}</p>
                  </div>
                </li>
              );
            })}
          </ol>
        </div>

        {/* Fixed Height Live Log Terminal (7 cols) — Prevent Layout Shift */}
        <div className="lg:col-span-7 rounded-lg border border-border-subtle bg-surface-inset overflow-hidden flex flex-col min-h-[460px] max-h-[500px]">
          {/* Terminal Header */}
          <div className="px-4 py-2.5 border-b border-border-subtle bg-surface-1 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2 text-slate-300 font-bold">
              <Terminal className="w-4 h-4 text-emerald-400" aria-hidden="true" />
              <span>LIVE SSE TELEMETRY STREAM</span>
            </div>
            <div className="flex items-center gap-2 text-[11px] text-slate-400">
              <span className={`w-2 h-2 rounded-full ${isExecuting ? 'bg-emerald-400 animate-ping' : 'bg-slate-500'}`} />
              <span>{events.length} EVENTS</span>
            </div>
          </div>

          {/* Terminal Body */}
          <div className="p-4 overflow-y-auto flex-1 font-mono text-xs space-y-2 select-text">
            {events.length === 0 ? (
              <div className="text-slate-500 italic py-12 text-center">
                Awaiting pipeline trigger. Real-time events from `/runs/{runId || ':id'}/events` will stream here.
              </div>
            ) : (
              events.map((ev, i) => (
                <div key={i} className="flex items-start gap-2 text-slate-300 leading-relaxed break-all">
                  <span className="text-slate-500 text-[10px] select-none shrink-0 mt-0.5">
                    {ev.created_at ? new Date(ev.created_at).toISOString().substring(11, 23) : `[00:00.${String(i).padStart(3, '0')}]`}
                  </span>
                  <span className={`px-1.5 py-0.2 rounded text-[10px] shrink-0 font-bold ${
                    ev.event_type === 'ERROR'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : ev.event_type === 'STAGE_COMPLETE'
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      : 'bg-slate-800 text-sky-300 border border-slate-700'
                  }`}>
                    {ev.stage || 'STAGE'}
                  </span>
                  <span className="text-slate-200">{ev.message}</span>
                </div>
              ))
            )}
            <div ref={terminalEndRef} />
          </div>
        </div>
      </div>
    </section>
  );
};
