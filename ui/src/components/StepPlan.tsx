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
  Trash2
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

  return (
    <section aria-labelledby="step-plan-title" className="space-y-6">
      {/* Title & Navigation Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 id="step-plan-title" className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <SlidersHorizontal className="w-5 h-5 text-emerald-400" aria-hidden="true" />
            Step 4: Remediation Plan & Scope-Guard Budgeting
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Enforce strict file boundaries and diff budgets before autonomous LLM execution (Spec §4.10, §4.13).
          </p>
        </div>

        {currentPlan && currentPlan.user_approved && !isEditing && (
          <button
            type="button"
            onClick={onProceedToLiveRun}
            className="flex items-center gap-2 px-4 py-2 rounded bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-mono transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            <span>Proceed to Step 5: Live Run</span>
            <ArrowRight className="w-4 h-4" aria-hidden="true" />
          </button>
        )}
      </div>

      {/* Scope Guard Security Explanation */}
      <div className="rounded-lg border border-indigo-800/40 bg-indigo-950/20 p-4 text-xs font-mono text-indigo-200/90 space-y-2">
        <div className="flex items-center gap-2 font-semibold text-indigo-300">
          <ShieldCheck className="w-4 h-4 text-indigo-400 shrink-0" aria-hidden="true" />
          <span>SCOPE GUARD DETERMINISTIC BUDGET ENFORCEMENT</span>
        </div>
        <p className="text-slate-300 leading-relaxed font-sans text-xs">
          The autonomous repair model operates under strict deterministic constraints. If any generated patch touches
          files outside the approved list, exceeds the maximum diff lines budget, or modifies unauthorized symbols,
          the run is immediately halted with <code className="text-rose-400 bg-rose-950/40 px-1 py-0.5 rounded border border-rose-800/40">SCOPE_VIOLATION_BLOCKED</code>.
        </p>
      </div>

      {/* Error State */}
      {error && (
        <div
          role="alert"
          aria-live="assertive"
          className="rounded-lg border border-rose-800/60 bg-rose-950/30 p-4 text-xs font-mono text-rose-200 space-y-1"
        >
          <div className="flex items-center gap-2 font-semibold text-rose-400">
            <AlertTriangle className="w-4 h-4 text-rose-500" aria-hidden="true" />
            <span>PLAN APPROVAL ERROR</span>
          </div>
          <p className="text-rose-300 font-sans">{error}</p>
        </div>
      )}

      {/* Plan Card */}
      <div className="rounded-lg border border-border-subtle bg-surface-2 p-5 space-y-5">
        <div className="flex items-center justify-between border-b border-border-subtle pb-3">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-200">
            <FileCode className="w-4 h-4 text-sky-400" aria-hidden="true" />
            <span>REMEDIATION SCOPE & BUDGET CONFIGURATION</span>
          </div>
          {currentPlan && !isEditing && (
            <button
              type="button"
              onClick={() => setIsEditing(true)}
              className="flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono bg-surface-3 hover:bg-slate-700 text-slate-200 border border-border-subtle transition-colors"
            >
              <Edit3 className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Edit Plan</span>
            </button>
          )}
        </div>

        {/* Form Controls */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs font-mono">
          {/* Files to Touch */}
          <div className="space-y-2">
            <label className="block text-slate-300 font-semibold uppercase text-[11px]">
              APPROVED FILES TO TOUCH ({files.length} / max {maxFiles}):
            </label>
            <div className="space-y-1.5">
              {files.map((file, idx) => (
                <div key={idx} className="flex items-center justify-between p-2 rounded bg-surface-inset border border-border-interactive">
                  <span className="text-slate-100 font-semibold">{file}</span>
                  {isEditing && files.length > 1 && (
                    <button
                      type="button"
                      onClick={() => handleRemoveFile(file)}
                      className="text-slate-500 hover:text-rose-400 transition-colors p-0.5"
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
                  className="flex-1 px-2.5 py-1.5 rounded bg-surface-inset border border-border-interactive text-slate-100 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
                />
                <button
                  type="button"
                  onClick={handleAddFile}
                  disabled={!newFile.trim()}
                  className="px-3 py-1.5 rounded bg-surface-3 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs font-mono border border-border-subtle flex items-center gap-1"
                >
                  <Plus className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Add</span>
                </button>
              </div>
            )}
          </div>

          {/* Strategy & Budget Constraints */}
          <div className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="plan-strategy" className="block text-slate-300 font-semibold uppercase text-[11px]">
                REMEDIATION STRATEGY:
              </label>
              <select
                id="plan-strategy"
                disabled={!isEditing}
                value={strategy}
                onChange={(e) => setStrategy(e.target.value)}
                className="w-full px-3 py-2 rounded bg-surface-inset border border-border-interactive text-slate-100 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 disabled:opacity-80"
              >
                <option value="surgical_sink_hardening">Surgical Sink Hardening (Scope Guarded)</option>
                <option value="safe_loader_replacement">SafeLoader Explicit Replacement</option>
                <option value="strict_ast_codemod">Strict AST Codemod Defense</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-slate-300 font-semibold text-[11px]">
                <label htmlFor="diff-budget-slider">DIFF BUDGET LIMIT:</label>
                <span className="text-emerald-400 font-bold">&le; {diffBudget} lines</span>
              </div>
              <input
                id="diff-budget-slider"
                type="range"
                min={10}
                max={50}
                step={5}
                disabled={!isEditing}
                value={diffBudget}
                onChange={(e) => setDiffBudget(Number(e.target.value))}
                className="w-full accent-emerald-500 cursor-pointer disabled:opacity-80"
              />
              <span className="text-[10px] text-slate-400 block">
                Spec §4.10 limit: Patches with added/modified lines &gt; {diffBudget} will be rejected.
              </span>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="max-files-input" className="block text-slate-300 font-semibold text-[11px]">
                MAXIMUM FILES TO MODIFY:
              </label>
              <input
                id="max-files-input"
                type="number"
                min={1}
                max={5}
                disabled={!isEditing}
                value={maxFiles}
                onChange={(e) => setMaxFiles(Number(e.target.value))}
                className="w-24 px-2.5 py-1.5 rounded bg-surface-inset border border-border-interactive text-slate-100 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 disabled:opacity-80"
              />
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-border-subtle">
          <div className="flex items-center gap-2">
            {isEditing ? (
              <button
                type="button"
                onClick={handleApprove}
                disabled={loading || files.length === 0}
                className="flex items-center gap-2 px-4 py-2 rounded bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-bold text-xs font-mono transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
              >
                {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4 stroke-[3]" />}
                <span>Approve Plan & Enforce Scope Guard</span>
              </button>
            ) : (
              <div className="flex items-center gap-2 text-emerald-400 text-xs font-mono font-semibold">
                <Check className="w-4 h-4 stroke-[3]" aria-hidden="true" />
                <span>Plan Approved by Operator (&le;{diffBudget} lines, {files.length} file(s))</span>
              </div>
            )}

            <button
              type="button"
              onClick={onCancelPlan}
              className="flex items-center gap-1.5 px-3 py-2 rounded bg-surface-3 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-border-subtle transition-colors"
            >
              <XCircle className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
              <span>Cancel / Reset Plan</span>
            </button>
          </div>

          {currentPlan && !isEditing && (
            <button
              type="button"
              onClick={onProceedToLiveRun}
              className="flex items-center gap-2 px-4 py-2 rounded bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-mono transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
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
