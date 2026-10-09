import React from 'react';
import {
  FolderGit2,
  LineChart,
  FileCode2,
  SlidersHorizontal,
  PlayCircle,
  FileCheck2,
  Download,
  Check,
  Lock
} from 'lucide-react';

export type StepNumber = 1 | 2 | 3 | 4 | 5 | 6 | 7;

interface StepItem {
  number: StepNumber;
  label: string;
  shortDesc: string;
  icon: React.ReactNode;
}

const STEPS: StepItem[] = [
  { number: 1, label: 'Source', shortDesc: 'Intake & Sandbox', icon: <FolderGit2 className="w-3.5 h-3.5" aria-hidden="true" /> },
  { number: 2, label: 'Analysis', shortDesc: 'AST & Intel', icon: <LineChart className="w-3.5 h-3.5" aria-hidden="true" /> },
  { number: 3, label: 'Requirements', shortDesc: 'Intent & Spec', icon: <FileCode2 className="w-3.5 h-3.5" aria-hidden="true" /> },
  { number: 4, label: 'Plan', shortDesc: 'Scope Guard', icon: <SlidersHorizontal className="w-3.5 h-3.5" aria-hidden="true" /> },
  { number: 5, label: 'Live Run', shortDesc: 'SSE Pipeline', icon: <PlayCircle className="w-3.5 h-3.5" aria-hidden="true" /> },
  { number: 6, label: 'Evidence', shortDesc: 'RED/GREEN Diff', icon: <FileCheck2 className="w-3.5 h-3.5" aria-hidden="true" /> },
  { number: 7, label: 'Export', shortDesc: 'Bundle & .diff', icon: <Download className="w-3.5 h-3.5" aria-hidden="true" /> },
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
      className="border-b border-border-subtle bg-surface-1/90 dark:bg-[#070b14]/95 px-4 md:px-6 py-2.5 overflow-x-auto scrollbar-none"
    >
      <ol className="flex items-center min-w-max gap-1.5 md:gap-2">
        {STEPS.map((step, idx) => {
          const isActive = currentStep === step.number;
          const isCompleted = completedSteps.has(step.number);
          const isLocked = !isCompleted && step.number > currentStep;
          const isClickable = isCompleted || step.number <= currentStep || (step.number === currentStep + 1 && isCompleted);

          let stateStyle = 'text-slate-400 border-border-subtle/40 bg-surface-2/30 hover:text-slate-200 hover:bg-surface-2/60';
          let badgeStyle = 'bg-surface-3 text-slate-300 border border-slate-700/60';

          if (isActive) {
            stateStyle = 'text-emerald-300 bg-emerald-950/40 border-emerald-500/60 shadow-sm ring-1 ring-emerald-500/20';
            badgeStyle = 'bg-emerald-500 text-slate-950 font-bold';
          } else if (isCompleted) {
            stateStyle = 'text-slate-200 hover:text-emerald-300 hover:bg-surface-2/80 border-slate-800';
            badgeStyle = 'bg-emerald-950 border border-emerald-600/70 text-emerald-400';
          } else if (isLocked) {
            stateStyle = 'text-slate-400 border-slate-800/40 bg-surface-1/40 cursor-not-allowed';
            badgeStyle = 'bg-slate-800/60 text-slate-400 border border-slate-800';
          }

          return (
            <li key={step.number} className="flex items-center">
              <button
                type="button"
                onClick={() => onSelectStep(step.number)}
                disabled={isLocked && !isClickable}
                aria-current={isActive ? 'step' : undefined}
                aria-label={`Step ${step.number}: ${step.label} (${step.shortDesc})${isCompleted ? ' - Completed' : isActive ? ' - Active' : ' - Locked'}`}
                className={`flex items-center gap-2.5 px-3 py-1.5 rounded-lg text-xs transition-all border ${stateStyle} focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500`}
              >
                {/* Step Badge */}
                <span className={`w-5 h-5 rounded flex items-center justify-center font-mono text-[10px] ${badgeStyle}`}>
                  {isCompleted && !isActive ? (
                    <Check className="w-3.5 h-3.5 stroke-[2.5]" aria-hidden="true" />
                  ) : isLocked ? (
                    <Lock className="w-2.5 h-2.5 text-slate-400" aria-hidden="true" />
                  ) : (
                    step.number
                  )}
                </span>

                {/* Step Label */}
                <div className="flex flex-col text-left font-sans">
                  <span className={`font-medium tracking-tight ${isActive ? 'font-semibold text-emerald-300' : isCompleted ? 'text-slate-200' : 'text-slate-400'}`}>
                    {step.label}
                  </span>
                  <span className="text-[10px] text-slate-400 font-normal hidden xl:inline">{step.shortDesc}</span>
                </div>
              </button>

              {/* Step Connector Line */}
              {idx < STEPS.length - 1 && (
                <div
                  className={`w-3 md:w-5 h-[1px] mx-1 transition-colors ${
                    completedSteps.has(step.number) ? 'bg-emerald-500/60' : 'bg-border-subtle'
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
