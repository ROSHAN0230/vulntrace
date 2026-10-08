import React from 'react';
import {
  FolderGit2,
  LineChart,
  FileCode2,
  SlidersHorizontal,
  PlayCircle,
  FileCheck2,
  Download,
  Check
} from 'lucide-react';

export type StepNumber = 1 | 2 | 3 | 4 | 5 | 6 | 7;

interface StepItem {
  number: StepNumber;
  label: string;
  shortDesc: string;
  icon: React.ReactNode;
}

const STEPS: StepItem[] = [
  { number: 1, label: 'Source', shortDesc: 'Intake & Sandbox', icon: <FolderGit2 className="w-4 h-4" /> },
  { number: 2, label: 'Analysis', shortDesc: 'AST & Intel', icon: <LineChart className="w-4 h-4" /> },
  { number: 3, label: 'Requirements', shortDesc: 'Intent & Spec', icon: <FileCode2 className="w-4 h-4" /> },
  { number: 4, label: 'Plan', shortDesc: 'Scope Guard', icon: <SlidersHorizontal className="w-4 h-4" /> },
  { number: 5, label: 'Live Run', shortDesc: 'SSE Pipeline', icon: <PlayCircle className="w-4 h-4" /> },
  { number: 6, label: 'Evidence', shortDesc: 'RED/GREEN Diff', icon: <FileCheck2 className="w-4 h-4" /> },
  { number: 7, label: 'Export', shortDesc: 'Bundle & .diff', icon: <Download className="w-4 h-4" /> },
];

interface StepperNavProps {
  currentStep: StepNumber;
  completedSteps: Set<StepNumber>;
  onSelectStep: (step: StepNumber) => void;
}

export const StepperNav: React.FC<StepperNavProps> = ({
  currentStep,
  completedSteps,
  onSelectStep
}) => {
  return (
    <nav
      aria-label="Studio 7-Step Remediation Workflow"
      className="border-b border-border-subtle bg-surface-1/80 dark:bg-[#070b14]/90 px-4 md:px-6 py-2.5 overflow-x-auto scrollbar-none"
    >
      <ol className="flex items-center min-w-max gap-1 md:gap-2">
        {STEPS.map((step, idx) => {
          const isActive = currentStep === step.number;
          const isCompleted = completedSteps.has(step.number);
          const isClickable = isCompleted || step.number <= currentStep || (step.number === currentStep + 1 && isCompleted);

          let stateStyle = 'text-slate-500 border-transparent hover:text-slate-400 hover:bg-surface-2/40';
          let badgeStyle = 'bg-surface-3 text-slate-400 border border-border-subtle';

          if (isActive) {
            stateStyle = 'text-emerald-300 bg-emerald-950/40 border-emerald-500/50 shadow-sm';
            badgeStyle = 'bg-emerald-500 text-slate-950 font-bold';
          } else if (isCompleted) {
            stateStyle = 'text-slate-200 hover:text-emerald-300 hover:bg-surface-2/80';
            badgeStyle = 'bg-emerald-950 border border-emerald-600/60 text-emerald-400';
          }

          return (
            <li key={step.number} className="flex items-center">
              <button
                type="button"
                onClick={() => onSelectStep(step.number)}
                disabled={!isClickable && !isCompleted && step.number > currentStep}
                aria-current={isActive ? 'step' : undefined}
                aria-label={`Step ${step.number}: ${step.label} (${step.shortDesc})`}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-mono transition-all border ${stateStyle} focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 disabled:opacity-40 disabled:cursor-not-allowed`}
              >
                {/* Step Badge */}
                <span className={`w-5 h-5 rounded flex items-center justify-center text-[10px] font-bold ${badgeStyle}`}>
                  {isCompleted && !isActive ? (
                    <Check className="w-3.5 h-3.5 stroke-[3]" aria-hidden="true" />
                  ) : (
                    step.number
                  )}
                </span>

                {/* Step Label */}
                <div className="flex flex-col text-left">
                  <span className="font-semibold tracking-tight">{step.label}</span>
                  <span className="text-[10px] opacity-60 hidden xl:inline">{step.shortDesc}</span>
                </div>
              </button>

              {/* Step Connector Line */}
              {idx < STEPS.length - 1 && (
                <div
                  className={`w-3 md:w-6 h-[1px] mx-1 transition-colors ${
                    completedSteps.has(step.number) ? 'bg-emerald-500/50' : 'bg-border-subtle'
                  }`}
                  aria-hidden="true"
                />
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
};
