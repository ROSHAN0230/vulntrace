import React, { useState } from 'react';
import {
  SlidersHorizontal,
  ShieldCheck,
  FileCode,
  Check,
  Edit3,
  XCircle,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Plus,
  Trash2,
  Lock
} from 'lucide-react';
import { RepairPlan } from '../types';

interface StepPlanProps {
  initialFiles: string[];
  currentPlan: RepairPlan | null;
  loading: boolean;
  error?: string;
  onApprovePlan: (plan: { files_to_touch: string[]; strategy: string; diff_budget_lines: number; max_files: number }) => void;
  onCancelPlan: () => void;
  onProceedToLiveRun: () => void;
}

export const StepPlan: React.FC<StepPlanProps> = ({
  initialFiles,
  currentPlan,
  loading,
  error,
  onApprovePlan,
  onCancelPlan,
  onProceedToLiveRun
}) => {
  const [isEditing, setIsEditing] = useState(!currentPlan);
  const [files, setFiles] = useState<string[]>(
    currentPlan?.files_to_touch?.length
      ? currentPlan.files_to_touch
      : initialFiles?.length
      ? initialFiles
      : ['app.py']
  );
  const [newFile, setNewFile] = useState('');
  const [diffBudget, setDiffBudget] = useState(currentPlan?.diff_budget_lines || 30);
  const [maxFiles, setMaxFiles] = useState(currentPlan?.max_files || 3);
  const [strategy, setStrategy] = useState(currentPlan?.strategy || 'surgical_sink_hardening');

  const handleAddFile = () => {
    if (!newFile.trim()) return;
    if (!files.includes(newFile.trim())) {
      setFiles([...files, newFile.trim()]);
    }
    setNewFile('');
  };

  const handleRemoveFile = (f: string) => {
    setFiles(files.filter((item) => item !== f));
  };

  const handleApprove = () => {
    onApprovePlan({
      files_to_touch: files,
      strategy,
      diff_budget_lines: Number(diffBudget),
      max_files: Number(maxFiles)
    });
    setIsEditing(false);
  };

  // Calculate percentage for diff budget meter (range 10 to 50)
  const budgetPercentage = Math.min(100, Math.max(0, ((diffBudget - 10) / (50 - 10)) * 100));

  return (
    <section aria-labelledby="step-plan-title" className="space-y-5">
      {/* Title & Navigation Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 id="step-plan-title" className="text-base font-bold text-slate-100 flex items-center gap-2 font-sans">
            <SlidersHorizontal className="w-5 h-5 text-emerald-400" aria-hidden="true" />
            Step 4: Remediation Plan &amp; Scope-Guard Security Checkpoint
          </h2>
          <p className="text-xs text-slate-400 font-sans mt-0.5">
            Enforce strict file boundaries and diff budgets before autonomous LLM execution (Spec §4.10, §4.13).
          </p>
        </div>

        {currentPlan && currentPlan.user_approved && !isEditing && (
          <button
            type="button"
            onClick={onProceedToLiveRun}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-sans transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 self-start sm:self-auto"
          >
            <span>Proceed to Step 5: Live Run</span>
            <ArrowRight className="w-4 h-4" aria-hidden="true" />
          </button>
        )}
      </div>

      {/* Authoritative Security Checkpoint Banner */}
      <div className="rounded-lg border border-indigo-700/60 bg-gradient-to-r from-indigo-950/40 via-surface-2 to-indigo-950/20 p-4 text-xs space-y-2 shadow-sm">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 font-semibold text-indigo-300 font-sans">
            <Lock className="w-4 h-4 text-indigo-400 shrink-0" aria-hidden="true" />
            <span>Authoritative Security Control Checkpoint — Scope Guard Verification</span>
          </div>
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-indigo-950/80 text-indigo-300 border border-indigo-700/60">
            DETERMINISTIC GATE
          </span>
        </div>
        <p className="text-slate-300 leading-relaxed font-sans text-xs">
          The autonomous repair model operates under strict deterministic constraints. If any generated patch touches
          files outside the approved list, exceeds the diff lines budget, or modifies unauthorized symbols,
          the run is immediately halted with <code className="text-rose-400 font-mono bg-rose-950/60 px-1 py-0.5 rounded border border-rose-800/60 font-semibold">SCOPE_VIOLATION_BLOCKED</code>.
        </p>
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] font-mono text-indigo-400/90 pt-0.5">
          <span>• Max Files: {maxFiles}</span>
          <span>• Max Diff Budget: &le;{diffBudget} lines</span>
          <span>• Symbol Mutation: Denied outside target</span>
        </div>
      </div>

      {/* Loading State */}
      {loading && (
        <div
          role="status"
          aria-live="polite"
          className="rounded-lg border border-border-subtle bg-surface-2 p-8 flex flex-col items-center justify-center text-center space-y-3"
        >
          <RefreshCw className="w-7 h-7 text-emerald-400 animate-spin" aria-hidden="true" />
          <span className="text-sm font-semibold text-slate-200 font-sans">Authorizing Plan &amp; Registering Scope Guard Invariants...</span>
          <span className="text-xs font-sans text-slate-400 max-w-md">
            Validating file boundaries, diff line budgets, and locking execution parameters (Spec §4.10).
          </span>
        </div>
      )}

      {/* Error State */}
      {error && (
        <div
          role="alert"
          aria-live="assertive"
          className="rounded-lg border border-rose-800/60 bg-rose-950/30 p-4 text-xs text-rose-200 space-y-1"
        >
          <div className="flex items-center gap-2 font-semibold text-rose-400 font-sans">
            <AlertTriangle className="w-4 h-4 text-rose-500" aria-hidden="true" />
            <span>Plan Approval Error</span>
          </div>
          <p className="text-rose-300 font-sans">{error}</p>
        </div>
      )}

      {/* Main Checkpoint Card */}
      <div className="rounded-lg border border-border-subtle bg-surface-2 p-5 space-y-5">
        <div className="flex items-center justify-between border-b border-border-subtle pb-3">
          <div className="flex items-center gap-2 text-xs font-sans font-bold text-slate-200">
            <FileCode className="w-4 h-4 text-sky-400" aria-hidden="true" />
            <span>Remediation Scope &amp; Budget Boundary Configuration</span>
          </div>
          {currentPlan && !isEditing && (
            <button
              type="button"
              onClick={() => setIsEditing(true)}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-sans font-medium bg-surface-3 hover:bg-slate-700 text-slate-200 border border-border-subtle transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
            >
              <Edit3 className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Modify Checkpoint</span>
            </button>
          )}
        </div>

        {/* Form Controls Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs">
          {/* Column 1: Files to Touch Boundaries */}
          <div className="space-y-2.5">
            <div className="flex items-center justify-between text-[11px] font-sans font-semibold text-slate-300 uppercase tracking-wide">
              <label htmlFor="new-file-input">Approved Files to Touch:</label>
              <span className="font-mono text-slate-400">
                {files.length} / max {maxFiles}
              </span>
            </div>

            <div className="space-y-1.5">
              {files.map((file, idx) => (
                <div key={idx} className="flex items-center justify-between p-2.5 rounded-md bg-surface-inset border border-border-interactive">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0" aria-hidden="true" />
                    <span className="font-mono text-slate-100 font-semibold truncate break-all">{file}</span>
                  </div>
                  {isEditing && files.length > 1 && (
                    <button
                      type="button"
                      onClick={() => handleRemoveFile(file)}
                      className="text-slate-500 hover:text-rose-400 transition-colors p-1 rounded hover:bg-surface-3 ml-2"
                      aria-label={`Remove file ${file}`}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              ))}
            </div>

            {isEditing && files.length < maxFiles && (
              <div className="flex items-center gap-2 pt-1">
                <input
                  id="new-file-input"
                  name="new-file-input"
                  aria-label="Add custom file to approved list"
                  type="text"
                  value={newFile}
                  onChange={(e) => setNewFile(e.target.value)}
                  placeholder="e.g. parser.py"
                  className="flex-1 px-3 py-1.5 rounded-md bg-surface-inset border border-border-interactive text-slate-100 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
                />
                <button
                  type="button"
                  onClick={handleAddFile}
                  disabled={!newFile.trim()}
                  className="px-3 py-1.5 rounded-md bg-surface-3 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs font-sans font-medium border border-border-subtle flex items-center gap-1 transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Add File</span>
                </button>
              </div>
            )}
          </div>

          {/* Column 2: Strategy & Diff Budget Meter */}
          <div className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="plan-strategy" className="block text-slate-300 font-sans font-semibold uppercase text-[11px] tracking-wide">
                Remediation Strategy:
              </label>
              <select
                id="plan-strategy"
                disabled={!isEditing}
                value={strategy}
                onChange={(e) => setStrategy(e.target.value)}
                className="w-full px-3 py-2 rounded-md bg-surface-inset border border-border-interactive text-slate-100 font-sans text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 disabled:opacity-80"
              >
                <option value="surgical_sink_hardening">Surgical Sink Hardening (Scope Guarded)</option>
                <option value="safe_loader_replacement">SafeLoader Explicit Replacement</option>
                <option value="strict_ast_codemod">Strict AST Codemod Defense</option>
              </select>
            </div>

            {/* Diff Budget Slider with Visual Meter */}
            <div className="space-y-2 p-3 rounded-md bg-surface-inset border border-border-subtle">
              <div className="flex items-center justify-between text-slate-300 font-sans font-semibold text-[11px] tracking-wide">
                <label htmlFor="diff-budget-slider">DIFF BUDGET LIMIT:</label>
                <span className="font-mono text-emerald-400 font-bold text-xs bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/60">
                  &le; {diffBudget} lines
                </span>
              </div>

              {/* Slider Input */}
              <input
                id="diff-budget-slider"
                type="range"
                min={10}
                max={50}
                step={5}
                disabled={!isEditing}
                value={diffBudget}
                onChange={(e) => setDiffBudget(Number(e.target.value))}
                className="w-full accent-emerald-500 cursor-pointer disabled:opacity-80 h-1.5 bg-slate-800 rounded-lg appearance-none"
              />

              {/* Visual Budget Progress Meter Bar */}
              <div className="space-y-1 pt-1">
                <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden border border-slate-700/60">
                  <div
                    className={`h-full transition-all rounded-full ${
                      diffBudget <= 25
                        ? 'bg-emerald-500'
                        : diffBudget <= 35
                        ? 'bg-sky-500'
                        : 'bg-amber-500'
                    }`}
                    style={{ width: `${budgetPercentage}%` }}
                    role="progressbar"
                    aria-valuenow={diffBudget}
                    aria-valuemin={10}
                    aria-valuemax={50}
                  />
                </div>
                <div className="flex justify-between text-[10px] font-mono text-slate-400">
                  <span>10 lines (Tight)</span>
                  <span className="text-emerald-400 font-semibold">&le;30 (Spec §4.10)</span>
                  <span>50 lines (Max)</span>
                </div>
              </div>

              <span className="text-[11px] text-slate-400 font-sans block pt-0.5">
                Spec §4.10 limit: Patches with added/modified lines &gt; {diffBudget} will be rejected.
              </span>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="max-files-input" className="block text-slate-300 font-sans font-semibold text-[11px] uppercase tracking-wide">
                Maximum Files to Modify:
              </label>
              <input
                id="max-files-input"
                type="number"
                min={1}
                max={5}
                disabled={!isEditing}
                value={maxFiles}
                onChange={(e) => setMaxFiles(Number(e.target.value))}
                className="w-24 px-3 py-1.5 rounded-md bg-surface-inset border border-border-interactive text-slate-100 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 disabled:opacity-80"
              />
            </div>
          </div>
        </div>

        {/* Action Controls & Authoritative Operator Approval Button */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-border-subtle">
          <div className="flex items-center gap-2">
            {isEditing ? (
              <button
                type="button"
                onClick={handleApprove}
                disabled={loading || files.length === 0}
                className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-bold text-xs font-sans transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
              >
                {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4 stroke-[2.5]" />}
                <span>Authorize Remediation Scope &amp; Enforce Budget</span>
              </button>
            ) : (
              <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-emerald-950/60 border border-emerald-600/70 text-emerald-300 text-xs font-sans font-semibold">
                <Check className="w-4 h-4 text-emerald-400 stroke-[3]" aria-hidden="true" />
                <span>Authorized by Operator: &le;{diffBudget} lines, {files.length} file(s)</span>
              </div>
            )}

            <button
              type="button"
              onClick={onCancelPlan}
              className="flex items-center gap-1.5 px-3 py-2 rounded-md bg-surface-3 hover:bg-slate-700 text-slate-300 text-xs font-sans border border-border-subtle transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
            >
              <XCircle className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
              <span>Reset Plan</span>
            </button>
          </div>

          {currentPlan && !isEditing && (
            <button
              type="button"
              onClick={onProceedToLiveRun}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-sans transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
            >
              <span>Execute Verification Pipeline</span>
              <ArrowRight className="w-4 h-4" aria-hidden="true" />
            </button>
          )}
        </div>
      </div>
    </section>
  );
};
