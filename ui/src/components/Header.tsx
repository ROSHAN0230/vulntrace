import React from 'react';
import {
  ShieldCheck,
  Cpu,
  Sun,
  Moon,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Copy,
  Check
} from 'lucide-react';
import { SystemHealthResponse, TokenLedgerSummary } from '../types';

interface HeaderProps {
  runId?: string;
  verdict?: string;
  sandboxTier?: string;
  tokenLedger?: TokenLedgerSummary;
  health: SystemHealthResponse | null;
  healthLoading?: boolean;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  runId,
  verdict,
  sandboxTier,
  tokenLedger,
  health,
  healthLoading,
  theme,
  onToggleTheme
}) => {
  const [copiedRunId, setCopiedRunId] = React.useState(false);

  const handleCopyRunId = () => {
    if (!runId) return;
    navigator.clipboard.writeText(runId);
    setCopiedRunId(true);
    setTimeout(() => setCopiedRunId(false), 2000);
  };

  const getVerdictBadge = () => {
    if (!verdict || verdict === 'READY' || verdict === 'INITIALIZED') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-medium bg-slate-800/60 text-slate-300 border border-slate-700/60">
          <span className="w-2 h-2 rounded-full bg-slate-400" />
          {verdict || 'AWAITING_RUN'}
        </span>
      );
    }

    if (verdict === 'GREEN_STATE_VERIFIED') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-600/60 shadow-sm shadow-emerald-950/50">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          GREEN_STATE_VERIFIED
        </span>
      );
    }

    if (verdict === 'RED_STATE_PERSISTS' || verdict === 'PATCH_REJECTED' || verdict === 'REGRESSION_FAILURE') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-semibold bg-rose-950/60 text-rose-300 border border-rose-700/60">
          <XCircle className="w-3.5 h-3.5 text-rose-400" />
          {verdict}
        </span>
      );
    }

    if (verdict === 'UNVERIFIABLE' || verdict === 'ENV_BUILD_FAILED' || verdict === 'VERIFICATION_REJECTED') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-semibold bg-amber-950/60 text-amber-300 border border-amber-600/60">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          {verdict}
        </span>
      );
    }

    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-semibold bg-sky-950/60 text-sky-300 border border-sky-700/60">
        <span className="w-2 h-2 rounded-full bg-sky-400 animate-pulse" />
        {verdict}
      </span>
    );
  };

  const getTierBadge = () => {
    const isTier1 = sandboxTier?.includes('TIER_1') || sandboxTier?.includes('CONTAINER');
    return (
      <span
        className={`inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono font-medium border ${
          isTier1
            ? 'bg-sky-950/40 text-sky-300 border-sky-700/40'
            : 'bg-amber-950/40 text-amber-300 border-amber-700/40'
        }`}
        title={isTier1 ? 'Hardened Rootless Container Isolation (--network none, read-only rootfs)' : 'Tier 0 Local Subprocess (Curated / Fallback Only)'}
      >
        <span className="font-semibold">{isTier1 ? 'TIER 1' : 'TIER 0'}</span>
        <span className="opacity-70 text-[10px] uppercase">({isTier1 ? 'CONTAINER' : 'LOCAL'})</span>
      </span>
    );
  };

  return (
    <header className="border-b border-border-subtle bg-surface-1 dark:bg-[#090d16] light:bg-white px-4 md:px-6 py-3 flex flex-wrap items-center justify-between gap-3 sticky top-0 z-30 transition-colors">
      {/* Brand & Run Identity */}
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-inner">
          <ShieldCheck className="w-5 h-5" aria-hidden="true" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="text-base font-bold tracking-tight text-slate-100 dark:text-white light:text-slate-900 font-sans">
              VulnTrace Studio
            </span>
            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold flex items-center gap-1">
              {healthLoading && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />}
              v0.1.0 SPEC §4.13
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            {runId ? (
              <button
                type="button"
                onClick={handleCopyRunId}
                className="flex items-center gap-1 text-slate-300 hover:text-emerald-400 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500 rounded px-1"
                aria-label={`Copy active run id ${runId}`}
                title="Click to copy Run ID"
              >
                <span>RUN: {runId}</span>
                {copiedRunId ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 opacity-60" />}
              </button>
            ) : (
              <span>AUTONOMOUS CVE REPRODUCTION & PATCHING</span>
            )}
          </div>
        </div>
      </div>

      {/* Telemetry & Badges */}
      <div className="flex items-center flex-wrap gap-2">
        {/* Sandbox Tier */}
        {getTierBadge()}

        {/* Verdict Badge */}
        {getVerdictBadge()}

        {/* Token Ledger Pill */}
        {tokenLedger && (
          <div
            className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded text-xs font-mono bg-surface-2 dark:bg-[#0f172a] light:bg-slate-100 border border-border-subtle dark:border-slate-800 text-slate-300"
            title={`Prompt: ${tokenLedger.prompt_tokens} | Completion: ${tokenLedger.completion_tokens} | Latency: ${tokenLedger.latency_ms.toFixed(1)}ms`}
          >
            <Cpu className="w-3.5 h-3.5 text-sky-400" aria-hidden="true" />
            <span>TOKENS: <strong className="text-slate-100">{tokenLedger.total_tokens}</strong></span>
            <span className="text-slate-500">|</span>
            <span className="text-[11px] text-slate-400">{tokenLedger.latency_ms.toFixed(0)}ms</span>
          </div>
        )}

        {/* Provider Indicators */}
        <div className="hidden lg:flex items-center gap-1.5 pl-2 border-l border-border-subtle">
          <div
            className={`w-2 h-2 rounded-full ${
              health?.providers?.nebius_token_factory?.status === 'ONLINE' ? 'bg-emerald-400' : 'bg-slate-500'
            }`}
            title={`Nemotron: ${health?.providers?.nebius_token_factory?.status || 'CHECKING'}`}
          />
          <span className="text-[11px] font-mono text-slate-400">NEMOTRON</span>

          <div
            className={`w-2 h-2 rounded-full ml-2 ${
              health?.providers?.tavily_search?.status === 'ONLINE' ? 'bg-emerald-400' : 'bg-slate-500'
            }`}
            title={`Tavily: ${health?.providers?.tavily_search?.status || 'CHECKING'}`}
          />
          <span className="text-[11px] font-mono text-slate-400">TAVILY</span>
        </div>

        {/* Theme Toggle Button */}
        <button
          type="button"
          onClick={onToggleTheme}
          className="p-1.5 rounded border border-border-subtle dark:border-slate-800 text-slate-300 hover:text-white hover:bg-surface-2 dark:hover:bg-slate-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 transition-colors ml-1"
          aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {theme === 'dark' ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-sky-400" />}
        </button>
      </div>
    </header>
  );
};
