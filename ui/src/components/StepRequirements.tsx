import React, { useState } from 'react';
import {
  FileCode2,
  Sparkles,
  AlertTriangle,
  CheckCircle2,
  ArrowRight,
  ShieldAlert,
  Send,
  RefreshCw,
  Check
} from 'lucide-react';
import { ParsedSpec } from '../types';

interface StepRequirementsProps {
  currentRequirement: string;
  parsedSpec: ParsedSpec | null;
  isVerifiable: boolean;
  warning?: string;
  loading: boolean;
  error?: string;
  onSubmitRequirement: (promptText: string) => void;
  onProceedToPlan: () => void;
}

const TEMPLATES = [
  {
    title: 'Surgical Deserialization Patch (Spec §4.9)',
    text: 'Surgically patch arbitrary YAML deserialization in parse_app_config, preserve custom loader class extensions and regression tests, diff budget <= 30 lines'
  },
  {
    title: 'CVE-2020-14343 SafeLoader Hardening',
    text: 'Harden CVE-2020-14343 unsafe YAML loader, preserve custom loader class extensions, diff budget <= 25 lines'
  },
  {
    title: 'Sink Hardening & Invariant Protection',
    text: 'Fix unsafe deserialization sink, forbid arbitrary object instantiation, preserve backward-compatible public API signatures'
  },
  {
    title: 'Vague / Unverifiable Input (Demonstrate AC)',
    text: 'make it better and fix all bugs'
  }
];

export const StepRequirements: React.FC<StepRequirementsProps> = ({
  currentRequirement,
  parsedSpec,
  isVerifiable,
  warning,
  loading,
  error,
  onSubmitRequirement,
  onProceedToPlan
}) => {
  const [inputText, setInputText] = useState(
    currentRequirement || 'Surgically patch arbitrary YAML deserialization in parse_app_config, preserve custom loader class extensions and regression tests, diff budget <= 30 lines'
  );

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim()) return;
    onSubmitRequirement(inputText.trim());
  };

  const handleApplyTemplate = (tmpl: string) => {
    setInputText(tmpl);
    onSubmitRequirement(tmpl);
  };

  return (
    <section aria-labelledby="step-requirements-title" className="space-y-5">
      {/* Title & Navigation Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 id="step-requirements-title" className="text-base font-bold text-slate-100 flex items-center gap-2 font-sans">
            <FileCode2 className="w-5 h-5 text-emerald-400" aria-hidden="true" />
            Step 3: Repair Intent &amp; Formal Specification Verification
          </h2>
          <p className="text-xs text-slate-400 font-sans mt-0.5">
            Capture natural-language requirements and parse into verifiable acceptance invariants (Spec §4.9, §4.13).
          </p>
        </div>

        {parsedSpec && isVerifiable && (
          <button
            type="button"
            onClick={onProceedToPlan}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-sans transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 self-start sm:self-auto"
          >
            <span>Proceed to Step 4: Plan</span>
            <ArrowRight className="w-4 h-4" aria-hidden="true" />
          </button>
        )}
      </div>

      {/* Sequential 3-Phase Flow Layout */}
      <div className="space-y-4">
        {/* PHASE 1: Natural Language Intent Input */}
        <div className="rounded-lg border border-border-subtle bg-surface-2 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-border-subtle pb-2.5">
            <div className="flex items-center gap-2 font-sans font-bold text-xs text-slate-200">
              <span className="w-5 h-5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-[11px] flex items-center justify-center font-bold">
                1
              </span>
              <span>Phase 1: Natural Language Intent &amp; Preservation Scope</span>
            </div>
            <span className="text-[11px] font-mono text-slate-400">Operator Specification</span>
          </div>

          <form onSubmit={handleSubmit} className="space-y-3.5">
            <div className="space-y-1.5">
              <label htmlFor="requirement-prompt" className="block text-xs font-sans font-medium text-slate-300">
                Enter Repair Prompt &amp; Invariant Boundaries:
              </label>
              <textarea
                id="requirement-prompt"
                rows={3}
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder="e.g. Surgically patch arbitrary YAML deserialization in parse_config, preserve existing regression tests, diff budget <= 30 lines"
                className="w-full px-3 py-2 rounded-md bg-surface-inset border border-border-interactive text-slate-100 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 resize-none leading-relaxed"
              />
            </div>

            {/* Quick Fill Templates */}
            <div className="space-y-1.5">
              <span className="text-[11px] font-sans text-slate-400 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-amber-400" aria-hidden="true" />
                Quick-fill specification templates:
              </span>
              <div className="flex flex-wrap gap-2">
                {TEMPLATES.map((tmpl, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => handleApplyTemplate(tmpl.text)}
                    className="px-2.5 py-1 rounded-md text-[11px] font-sans bg-surface-3 hover:bg-slate-700 text-slate-300 border border-border-subtle transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
                  >
                    {tmpl.title}
                  </button>
                ))}
              </div>
            </div>

            <div className="pt-1">
              <button
                type="submit"
                disabled={loading || !inputText.trim()}
                className="flex items-center gap-2 px-4 py-2 rounded-md bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-bold text-xs font-sans transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
              >
                {loading ? (
                  <RefreshCw className="w-4 h-4 animate-spin" aria-hidden="true" />
                ) : (
                  <Send className="w-4 h-4" aria-hidden="true" />
                )}
                <span>Parse &amp; Evaluate Intent</span>
              </button>
            </div>
          </form>
        </div>

        {/* Loading State */}
        {loading && (
          <div
            role="status"
            aria-live="polite"
            className="rounded-lg border border-border-subtle bg-surface-2 p-8 flex flex-col items-center justify-center text-center space-y-3"
          >
            <RefreshCw className="w-7 h-7 text-emerald-400 animate-spin" aria-hidden="true" />
            <span className="text-sm font-semibold text-slate-200 font-sans">Evaluating Natural Language Invariants &amp; Syntactic Boundaries...</span>
            <span className="text-xs font-sans text-slate-400 max-w-md">
              Converting operator intent into formal acceptance invariants and checking for verifiable targets (Spec §4.9).
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
              <AlertTriangle className="w-4 h-4 text-rose-500 shrink-0" aria-hidden="true" />
              <span>Intent Parsing Error</span>
            </div>
            <p className="text-rose-300 font-sans">{error}</p>
          </div>
        )}

        {/* Warning State: UNVERIFIABLE Requirement Card (Prominent & Unambiguous) */}
        {warning && !isVerifiable && (
          <div
            role="alert"
            aria-live="assertive"
            className="rounded-lg border-2 border-amber-500/80 bg-amber-950/30 p-5 space-y-3 shadow-sm shadow-amber-950/40"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5 text-amber-300 font-sans font-bold text-sm">
                <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0" aria-hidden="true" />
                <span>UNVERIFIABLE SPECIFICATION WARNING (Spec §3.1, §4.9)</span>
              </div>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-950/80 text-amber-300 border border-amber-600/80">
                CANONICAL: UNVERIFIABLE
              </span>
            </div>

            <p className="text-xs text-amber-100 font-sans leading-relaxed">
              {warning}
            </p>

            <div className="text-[11px] font-sans text-amber-300/90 bg-amber-950/50 p-3 rounded-md border border-amber-800/50 space-y-1">
              <div className="font-semibold text-amber-200">Specification Guardrail Invariant:</div>
              <div>
                The engine refuses to generate untestable or unconstrained patches. To proceed, specify concrete targets:
              </div>
              <ul className="list-disc pl-4 space-y-0.5 text-amber-200/80 pt-1 font-mono text-[10px]">
                <li>Explicit vulnerable sink (e.g. <code className="text-amber-100 bg-amber-900/60 px-1 py-0.5 rounded">yaml.load</code>)</li>
                <li>Preservation constraints (e.g. <code className="text-amber-100 bg-amber-900/60 px-1 py-0.5 rounded">preserve existing regression tests</code>)</li>
                <li>Diff line bounds (e.g. <code className="text-amber-100 bg-amber-900/60 px-1 py-0.5 rounded">diff budget &lt;= 30 lines</code>)</li>
              </ul>
            </div>
          </div>
        )}

        {/* PHASE 2 & PHASE 3 Panels (When Verifiable) */}
        {parsedSpec && isVerifiable && (
          <>
            {/* PHASE 2: Formal Syntactic Specification Preview */}
            <div className="rounded-lg border border-border-subtle bg-surface-2 p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-border-subtle pb-2.5">
                <div className="flex items-center gap-2 font-sans font-bold text-xs text-slate-200">
                  <span className="w-5 h-5 rounded bg-sky-500/10 border border-sky-500/30 text-sky-400 font-mono text-[11px] flex items-center justify-center font-bold">
                    2
                  </span>
                  <span>Phase 2: Formal Syntactic Specification Preview</span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/70 text-emerald-300 border border-emerald-700/70">
                  VERIFIABLE SPEC
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                {/* Must Fix Target */}
                <div className="rounded-md border border-border-interactive bg-surface-inset p-3.5 space-y-1.5">
                  <span className="text-[11px] font-sans font-semibold text-slate-400 uppercase tracking-wide">
                    Target to Fix (Surgical Sink)
                  </span>
                  <div className="font-mono font-bold text-rose-300 break-all">{parsedSpec.must_fix}</div>
                  <span className="text-[11px] font-sans text-slate-400 block">
                    Isolated execution sink mapped for deterministic neutralization.
                  </span>
                </div>

                {/* Constraints */}
                <div className="rounded-md border border-border-interactive bg-surface-inset p-3.5 space-y-1.5">
                  <span className="text-[11px] font-sans font-semibold text-slate-400 uppercase tracking-wide">
                    Syntactic &amp; Scope Constraints
                  </span>
                  <ul className="text-slate-200 space-y-1 font-mono text-xs">
                    {parsedSpec.constraints.map((c, i) => (
                      <li key={i} className="flex items-center gap-1.5">
                        <span className="text-emerald-400">•</span>
                        <span>{c}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>

            {/* PHASE 3: Deterministic Acceptance Conditions & Guardrails Checklist */}
            <div className="rounded-lg border border-border-subtle bg-surface-2 p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-border-subtle pb-2.5">
                <div className="flex items-center gap-2 font-sans font-bold text-xs text-slate-200">
                  <span className="w-5 h-5 rounded bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 font-mono text-[11px] flex items-center justify-center font-bold">
                    3
                  </span>
                  <span>Phase 3: Deterministic Acceptance Conditions &amp; Guardrails Checklist</span>
                </div>
                <span className="text-[11px] font-mono text-slate-400">Spec §4.9 Acceptance Verification</span>
              </div>

              {/* Preserved Behaviors */}
              <div className="space-y-2">
                <span className="text-[11px] font-sans font-semibold text-slate-400 uppercase tracking-wide block">
                  Preserved Behaviors &amp; Architectural Invariants:
                </span>
                <div className="flex flex-wrap gap-2">
                  {parsedSpec.must_preserve.map((p, i) => (
                    <span
                      key={i}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-surface-3 text-sky-300 border border-border-subtle text-xs font-mono"
                    >
                      <Check className="w-3 h-3 text-sky-400" aria-hidden="true" />
                      <span>{p}</span>
                    </span>
                  ))}
                </div>
              </div>

              {/* Mandatory Acceptance Tests */}
              <div className="space-y-2 pt-1">
                <span className="text-[11px] font-sans font-semibold text-slate-400 uppercase tracking-wide block">
                  Mandatory Acceptance Test Oracle Checks:
                </span>
                <div className="space-y-2">
                  {parsedSpec.acceptance_tests.map((t, i) => (
                    <div
                      key={i}
                      className="p-3 rounded-md bg-surface-inset border border-border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono"
                    >
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" aria-hidden="true" />
                        <span className="text-slate-200 font-semibold">{t.name}</span>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-800/60 self-start sm:self-auto">
                        {t.status} ({t.oracle})
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </section>
  );
};
