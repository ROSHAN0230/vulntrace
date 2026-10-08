import React, { useState } from 'react';
import {
  FileCode2,
  Sparkles,
  AlertTriangle,
  CheckCircle2,
  ArrowRight,
  ShieldAlert,
  Send,
  RefreshCw
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
    text: 'Surgically patch arbitrary YAML deserialization in parse_config, preserve existing regression tests, diff budget <= 30 lines'
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
    currentRequirement || 'Surgically patch arbitrary YAML deserialization in parse_config, preserve existing regression tests, diff budget <= 30 lines'
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
    <section aria-labelledby="step-requirements-title" className="space-y-6">
      {/* Title & Navigation Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 id="step-requirements-title" className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <FileCode2 className="w-5 h-5 text-emerald-400" aria-hidden="true" />
            Step 3: Repair Intent & Formal Specification Preview
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Capture natural-language requirements and parse into verifiable acceptance invariants (Spec §4.9, §4.13).
          </p>
        </div>

        {parsedSpec && isVerifiable && (
          <button
            type="button"
            onClick={onProceedToPlan}
            className="flex items-center gap-2 px-4 py-2 rounded bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-mono transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            <span>Proceed to Step 4: Plan</span>
            <ArrowRight className="w-4 h-4" aria-hidden="true" />
          </button>
        )}
      </div>

      {/* Main Interactive Form */}
      <form onSubmit={handleSubmit} className="rounded-lg border border-border-subtle bg-surface-2 p-5 space-y-4">
        <div className="space-y-2">
          <label htmlFor="requirement-prompt" className="block text-xs font-mono font-semibold text-slate-200">
            ENTER REPAIR INTENT & PRESERVATION CONSTRAINTS:
          </label>
          <textarea
            id="requirement-prompt"
            rows={3}
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="e.g. Surgically patch arbitrary YAML deserialization in parse_config, preserve existing regression tests, diff budget <= 30 lines"
            className="w-full px-3 py-2 rounded bg-surface-inset border border-border-interactive text-slate-100 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 resize-none"
          />
        </div>

        {/* Quick Fill Templates */}
        <div className="space-y-2">
          <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" aria-hidden="true" />
            QUICK-FILL SPECIFICATION TEMPLATES:
          </span>
          <div className="flex flex-wrap gap-2">
            {TEMPLATES.map((tmpl, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleApplyTemplate(tmpl.text)}
                className="px-2.5 py-1 rounded text-[11px] font-mono bg-surface-3 hover:bg-slate-700 text-slate-300 border border-border-subtle transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
              >
                {tmpl.title}
              </button>
            ))}
          </div>
        </div>

        <button
          type="submit"
          disabled={loading || !inputText.trim()}
          className="flex items-center gap-2 px-4 py-2 rounded bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-bold text-xs font-mono transition-all shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
        >
          {loading ? (
            <RefreshCw className="w-4 h-4 animate-spin" aria-hidden="true" />
          ) : (
            <Send className="w-4 h-4" aria-hidden="true" />
          )}
          <span>Parse & Evaluate Intent</span>
        </button>
      </form>

      {/* Error State */}
      {error && (
        <div
          role="alert"
          aria-live="assertive"
          className="rounded-lg border border-rose-800/60 bg-rose-950/30 p-4 text-xs font-mono text-rose-200 space-y-1"
        >
          <div className="flex items-center gap-2 font-semibold text-rose-400">
            <AlertTriangle className="w-4 h-4 text-rose-500" aria-hidden="true" />
            <span>INTENT PARSING ERROR</span>
          </div>
          <p className="text-rose-300 font-sans">{error}</p>
        </div>
      )}

      {/* Warning State: UNVERIFIABLE Requirement */}
      {warning && !isVerifiable && (
        <div
          role="alert"
          aria-live="assertive"
          className="rounded-lg border border-amber-600/70 bg-amber-950/30 p-5 space-y-3"
        >
          <div className="flex items-center gap-2 text-amber-300 font-mono font-bold text-xs">
            <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0" aria-hidden="true" />
            <span>UNVERIFIABLE SPECIFICATION WARNING (Spec §3.1, §4.9)</span>
          </div>
          <p className="text-xs text-amber-200/90 font-sans leading-relaxed">
            {warning}
          </p>
          <div className="text-[11px] font-mono text-amber-400/80 bg-amber-950/40 p-2.5 rounded border border-amber-800/40">
            <strong>Rule:</strong> The engine refuses to generate untestable or unconstrained patches.
            Specify explicit sinks (e.g., <code className="text-amber-200">yaml.load</code>),
            preservation targets (e.g., <code className="text-amber-200">preserve regression tests</code>), or line budgets.
          </div>
        </div>
      )}

      {/* Verifiable State: Parsed Specification Preview */}
      {parsedSpec && isVerifiable && (
        <div className="rounded-lg border border-border-subtle bg-surface-2 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-border-subtle pb-2">
            <span className="text-xs font-mono font-bold text-slate-200 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" aria-hidden="true" />
              PARSED SPECIFICATION PREVIEW (VERIFIABLE)
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-700/60">
              VERIFIABLE SPEC
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            {/* Must Fix Target */}
            <div className="rounded border border-border-interactive bg-surface-inset p-3 space-y-1">
              <span className="text-[11px] text-slate-400 uppercase">TARGET TO FIX:</span>
              <div className="font-bold text-rose-300">{parsedSpec.must_fix}</div>
            </div>

            {/* Constraints */}
            <div className="rounded border border-border-interactive bg-surface-inset p-3 space-y-1">
              <span className="text-[11px] text-slate-400 uppercase">SYNTACTIC & SCOPE CONSTRAINTS:</span>
              <ul className="text-slate-200 space-y-0.5">
                {parsedSpec.constraints.map((c, i) => (
                  <li key={i} className="flex items-center gap-1.5">
                    <span className="text-emerald-400">•</span>
                    <span>{c}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Preservation Targets & Acceptance Tests */}
          <div className="space-y-3 pt-2 text-xs font-mono">
            <div>
              <span className="text-[11px] text-slate-400 uppercase block mb-1">PRESERVED BEHAVIORS & INVARIANTS:</span>
              <div className="flex flex-wrap gap-2">
                {parsedSpec.must_preserve.map((p, i) => (
                  <span key={i} className="px-2.5 py-1 rounded bg-surface-3 text-sky-300 border border-border-subtle">
                    {p}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <span className="text-[11px] text-slate-400 uppercase block mb-1">MANDATORY ACCEPTANCE TESTS:</span>
              <div className="space-y-1.5">
                {parsedSpec.acceptance_tests.map((t, i) => (
                  <div key={i} className="p-2 rounded bg-surface-inset border border-border-subtle flex items-center justify-between">
                    <span className="text-slate-200 font-semibold">{t.name}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950/40 text-emerald-300 border border-emerald-800/40">
                      {t.status} ({t.oracle})
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};
