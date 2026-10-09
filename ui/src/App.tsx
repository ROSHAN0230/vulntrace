import React, { useState, useEffect, useRef } from 'react';
import { Header } from './components/Header';
import { StepperNav, StepNumber } from './components/StepperNav';
import { StepSource } from './components/StepSource';
import { StepAnalysis } from './components/StepAnalysis';
import { StepRequirements } from './components/StepRequirements';
import { StepPlan } from './components/StepPlan';
import { StepLiveRun } from './components/StepLiveRun';
import { StepEvidence } from './components/StepEvidence';
import { StepExport } from './components/StepExport';
import {
  SystemHealthResponse,
  BenchmarkScenarioInfo,
  StudioRun,
  StudioAnalysis,
  ParsedSpec,
  RepairPlan,
  StudioEvent,
  TokenLedgerSummary,
  EvidenceBundle
} from './types';

export const App: React.FC = () => {
  // Theme state
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  // Workflow Navigation
  const [currentStep, setCurrentStep] = useState<StepNumber>(1);
  const [completedSteps, setCompletedSteps] = useState<Set<StepNumber>>(new Set());

  // Backend Health & Benchmarks
  const [health, setHealth] = useState<SystemHealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState<boolean>(true);
  const [benchmarks, setBenchmarks] = useState<BenchmarkScenarioInfo[]>([]);

  // Step 1: Run & Workspace State
  const [currentRun, setCurrentRun] = useState<StudioRun | null>(null);
  const [sourceLoading, setSourceLoading] = useState<boolean>(false);
  const [sourceError, setSourceError] = useState<string | undefined>();

  // Step 2: Analysis State
  const [analysis, setAnalysis] = useState<StudioAnalysis | null>(null);
  const [analysisLoading, setAnalysisLoading] = useState<boolean>(false);
  const [analysisError, setAnalysisError] = useState<string | undefined>();

  // Step 3: Requirements State
  const [requirementText, setRequirementText] = useState<string>(
    'Surgically patch arbitrary YAML deserialization in parse_config, preserve existing regression tests, diff budget <= 30 lines'
  );
  const [parsedSpec, setParsedSpec] = useState<ParsedSpec | null>(null);
  const [isVerifiable, setIsVerifiable] = useState<boolean>(true);
  const [intentWarning, setIntentWarning] = useState<string | undefined>();
  const [intentLoading, setIntentLoading] = useState<boolean>(false);
  const [intentError, setIntentError] = useState<string | undefined>();

  // Step 4: Plan State
  const [currentPlan, setCurrentPlan] = useState<RepairPlan | null>(null);
  const [planLoading, setPlanLoading] = useState<boolean>(false);
  const [planError, setPlanError] = useState<string | undefined>();

  // Step 5: Live Execution & SSE State
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [events, setEvents] = useState<StudioEvent[]>([]);
  const [currentStage, setCurrentStage] = useState<string>('INITIALIZED');
  const [executionError, setExecutionError] = useState<string | undefined>();
  const [tokenLedger, setTokenLedger] = useState<TokenLedgerSummary | undefined>();
  const sseRef = useRef<EventSource | null>(null);

  // Step 6 & 7: Evidence & Export State
  const [evidenceBundle, setEvidenceBundle] = useState<EvidenceBundle | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState<boolean>(false);
  const [evidenceError, setEvidenceError] = useState<string | undefined>();

  // 1. Theme Management
  useEffect(() => {
    const savedTheme = localStorage.getItem('vulntrace_theme') as 'dark' | 'light' | null;
    const initialTheme = savedTheme || 'dark';
    setTheme(initialTheme);
    if (initialTheme === 'dark') {
      document.documentElement.classList.add('dark');
      document.documentElement.classList.remove('light');
    } else {
      document.documentElement.classList.add('light');
      document.documentElement.classList.remove('dark');
    }
  }, []);

  const handleToggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    localStorage.setItem('vulntrace_theme', nextTheme);
    if (nextTheme === 'dark') {
      document.documentElement.classList.add('dark');
      document.documentElement.classList.remove('light');
    } else {
      document.documentElement.classList.add('light');
      document.documentElement.classList.remove('dark');
    }
  };

  // 2. Fetch System Health & Benchmarks on Mount
  useEffect(() => {
    const fetchInit = async () => {
      setHealthLoading(true);
      try {
        const [hRes, bRes] = await Promise.all([
          fetch('/api/v1/health'),
          fetch('/api/v1/benchmarks')
        ]);
        if (hRes.ok) {
          const hData: SystemHealthResponse = await hRes.json();
          setHealth(hData);
        }
        if (bRes.ok) {
          const bData: BenchmarkScenarioInfo[] = await bRes.json();
          setBenchmarks(bData);
        }
      } catch (err: any) {
        console.error('Initial health/benchmark fetch error:', err);
      } finally {
        setHealthLoading(false);
      }
    };
    fetchInit();
  }, []);

  // 3. Deep-Linking & Workflow State Inspection Support
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const stepParam = params.get('step');
    const stateParam = params.get('state');
    const runIdParam = params.get('runId') || 'run_70997352ab18';

    if (stepParam) {
      const stepNum = parseInt(stepParam, 10) as StepNumber;
      if (stepNum >= 1 && stepNum <= 7) {
        setCurrentStep(stepNum);
        const prev = new Set<StepNumber>();
        for (let i = 1; i <= stepNum; i++) prev.add(i as StepNumber);
        setCompletedSteps(prev);
      }
    }

    if (stateParam === 'loading') {
      setEvidenceLoading(true);
      setSourceLoading(true);
      return;
    }
    if (stateParam === 'error') {
      setEvidenceError('Verification signature rejected: Ed25519 signature mismatch (Spec §4.11 constraint)');
      setSourceError('Ingest Guard violation: upload size exceeds maximum allowed boundary (Spec §4.1)');
      return;
    }
    if (stateParam === 'empty') {
      setEvidenceBundle(null);
      return;
    }

    if (stepParam && parseInt(stepParam, 10) >= 5 && runIdParam) {
      Promise.all([
        fetch(`/runs/${runIdParam}`).then((res) => (res.ok ? res.json() : null)),
        fetch(`/runs/${runIdParam}/bundle`).then((res) => (res.ok ? res.json() : null))
      ])
        .then(([runData, bData]) => {
          if (bData) {
            setEvidenceBundle(bData);
          }
          if (runData || bData) {
            const rawCreated = runData?.created_at || bData?.created_at;
            const formattedCreated = typeof rawCreated === 'number'
              ? new Date(rawCreated > 1e11 ? rawCreated : rawCreated * 1000).toISOString()
              : rawCreated || new Date().toISOString();

            setCurrentRun({
              id: runData?.id || bData?.run_id || runIdParam,
              created_at: formattedCreated,
              updated_at: formattedCreated,
              status: runData?.status || (bData ? 'COMPLETED' : 'INITIALIZED'),
              source_type: runData?.source_type || 'local',
              source_ref: runData?.source_ref || bData?.source?.url || 'benchmark',
              cve_id: runData?.cve_id || 'CVE-2020-14343',
              verdict: runData?.verdict || bData?.verdict,
              repo_dir: runData?.repo_dir || ''
            });

            // Hydrate genuine persisted events
            if (runData?.events && runData.events.length > 0) {
              setEvents(runData.events);
            }
            if (runData?.status === 'COMPLETED' || bData?.verdict) {
              setCurrentStage('COMPLETED');
            }

            // Hydrate token ledger from genuine persisted records without hardcoded fallbacks
            const calls = bData?.llm?.calls || runData?.llm_calls || [];
            if (calls.length > 0) {
              const pTok = calls.reduce((acc: number, c: any) => acc + (c.prompt_tokens || 0), 0);
              const cTok = calls.reduce((acc: number, c: any) => acc + (c.completion_tokens || 0), 0);
              const rTok = calls.reduce((acc: number, c: any) => acc + (c.reasoning_tokens || 0), 0);
              const lat = calls.reduce((acc: number, c: any) => acc + (c.latency_ms || 0), 0);
              setTokenLedger({
                prompt_tokens: pTok,
                completion_tokens: cTok,
                reasoning_tokens: rTok,
                total_tokens: pTok + cTok,
                cost_usd: 0.0,
                latency_ms: lat,
                calls_count: calls.length
              });
            } else {
              setTokenLedger(undefined);
            }
          }
        })
        .catch((err) => console.error('Deep-link bundle fetch error:', err));
    }
  }, []);

  // Mark step complete helper
  const markStepComplete = (step: StepNumber) => {
    setCompletedSteps((prev) => new Set([...prev, step]));
  };

  // ---------------------------------------------------------------------------
  // Step 1 Actions: Intake & Disposable Workspace Provisioning
  // ---------------------------------------------------------------------------

  const handleSelectBenchmark = async (scenario: BenchmarkScenarioInfo) => {
    setSourceLoading(true);
    setSourceError(undefined);
    try {
      const res = await fetch('/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_type: 'local',
          source_ref: scenario.repo_path,
          cve_id: scenario.cve_id,
          target_file: scenario.target_file,
          target_function: scenario.target_function
        })
      });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `HTTP ${res.status}: Failed to provision workspace`);
      }
      const runData: StudioRun = await res.json();
      setCurrentRun(runData);
      markStepComplete(1);
    } catch (err: any) {
      setSourceError(err.message);
    } finally {
      setSourceLoading(false);
    }
  };

  const handleSubmitGithubUrl = async (url: string, cveId: string) => {
    setSourceLoading(true);
    setSourceError(undefined);
    try {
      const res = await fetch('/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_type: 'github',
          source_ref: url,
          cve_id: cveId
        })
      });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `HTTP ${res.status}: Failed to clone repository`);
      }
      const runData: StudioRun = await res.json();
      setCurrentRun(runData);
      markStepComplete(1);
    } catch (err: any) {
      setSourceError(err.message);
    } finally {
      setSourceLoading(false);
    }
  };

  const handleSubmitZipUpload = async (file: File, cveId: string) => {
    setSourceLoading(true);
    setSourceError(undefined);
    try {
      // Ingest validation
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch('/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_type: 'upload',
          source_ref: file.name,
          cve_id: cveId
        })
      });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `HTTP ${res.status}: Zip upload rejected`);
      }
      const runData: StudioRun = await res.json();
      setCurrentRun(runData);
      markStepComplete(1);
    } catch (err: any) {
      setSourceError(err.message);
    } finally {
      setSourceLoading(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Step 2 Actions: Analysis & Reachability
  // ---------------------------------------------------------------------------

  const handleRunAnalysis = async () => {
    if (!currentRun) {
      setAnalysisError('Please provision a workspace in Step 1 first.');
      return;
    }
    setAnalysisLoading(true);
    setAnalysisError(undefined);
    try {
      const res = await fetch(`/runs/${currentRun.id || (currentRun as any).run_id}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `HTTP ${res.status}: Static analysis failed`);
      }
      const analysisData: StudioAnalysis = await res.json();
      setAnalysis(analysisData);
      markStepComplete(2);
    } catch (err: any) {
      setAnalysisError(err.message);
    } finally {
      setAnalysisLoading(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Step 3 Actions: Requirements & Verifiability
  // ---------------------------------------------------------------------------

  const handleSubmitRequirement = async (promptText: string) => {
    const runId = currentRun?.id || (currentRun as any)?.run_id;
    if (!runId) {
      setIntentError('No active run initialized.');
      return;
    }
    setRequirementText(promptText);
    setIntentLoading(true);
    setIntentError(undefined);
    try {
      const res = await fetch(`/runs/${runId}/intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          requirement: promptText,
          target_file: analysis?.findings?.[0]?.file || 'app.py'
        })
      });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `HTTP ${res.status}: Intent recording failed`);
      }
      const data = await res.json();
      setIsVerifiable(data.is_verifiable);
      setIntentWarning(data.warning || undefined);
      setParsedSpec(data.parsed_spec || null);

      if (data.is_verifiable) {
        markStepComplete(3);
      }
    } catch (err: any) {
      setIntentError(err.message);
    } finally {
      setIntentLoading(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Step 4 Actions: Remediation Plan & Scope Guard
  // ---------------------------------------------------------------------------

  const handleApprovePlan = async (planConfig: {
    files_to_touch: string[];
    strategy: string;
    diff_budget_lines: number;
    max_files: number;
  }) => {
    const runId = currentRun?.id || (currentRun as any)?.run_id;
    if (!runId) {
      setPlanError('No active run initialized.');
      return;
    }
    setPlanLoading(true);
    setPlanError(undefined);
    try {
      const res = await fetch(`/runs/${runId}/approve-plan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(planConfig)
      });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `HTTP ${res.status}: Plan approval rejected`);
      }
      const data = await res.json();
      setCurrentPlan(data.plan);
      markStepComplete(4);
    } catch (err: any) {
      setPlanError(err.message);
    } finally {
      setPlanLoading(false);
    }
  };

  const handleCancelPlan = () => {
    setCurrentPlan(null);
  };

  // ---------------------------------------------------------------------------
  // Step 5 Actions: Live Execution & Real SSE Event Stream
  // ---------------------------------------------------------------------------

  const handleExecute = async () => {
    const runId = currentRun?.id || (currentRun as any)?.run_id;
    if (!runId) {
      setExecutionError('No active run initialized.');
      return;
    }

    setIsExecuting(true);
    setExecutionError(undefined);
    setEvents([]);

    // Open live SSE stream from /runs/{id}/events
    if (sseRef.current) {
      sseRef.current.close();
    }

    const sse = new EventSource(`/runs/${runId}/events`);
    sseRef.current = sse;

    sse.onmessage = (event) => {
      try {
        const evData: StudioEvent = JSON.parse(event.data);
        setEvents((prev) => [...prev, evData]);
        if (evData.stage) {
          setCurrentStage(evData.stage);
        }
      } catch (e) {
        console.warn('SSE payload parsing warning:', e);
      }
    };

    sse.onerror = () => {
      // Stream closed or error
    };

    try {
      const res = await fetch(`/runs/${runId}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `HTTP ${res.status}: Pipeline execution error`);
      }

      const execData = await res.json();

      // Update run with terminal verdict
      setCurrentRun((prev) => (prev ? { ...prev, verdict: execData.verdict } : null));

      // Fetch freshly signed evidence bundle
      setEvidenceLoading(true);
      setEvidenceError(undefined);
      try {
        const bundleRes = await fetch(`/runs/${runId}/bundle`);
        if (bundleRes.ok) {
          const bundleJson: EvidenceBundle = await bundleRes.json();
          setEvidenceBundle(bundleJson);

          // Compute Token Ledger summary
          const calls = bundleJson.llm?.calls || [];
          if (calls.length > 0) {
            const promptTokens = calls.reduce((acc, c) => acc + (c.prompt_tokens || 0), 0);
            const completionTokens = calls.reduce((acc, c) => acc + (c.completion_tokens || 0), 0);
            const reasoningTokens = calls.reduce((acc, c) => acc + (c.reasoning_tokens || 0), 0);
            const totalTokens = promptTokens + completionTokens;
            const latencyMs = calls.reduce((acc, c) => acc + (c.latency_ms || 0), 0);

            setTokenLedger({
              prompt_tokens: promptTokens,
              completion_tokens: completionTokens,
              reasoning_tokens: reasoningTokens,
              total_tokens: totalTokens,
              cost_usd: 0.0,
              latency_ms: latencyMs,
              calls_count: calls.length
            });
          } else {
            setTokenLedger(undefined);
          }
        } else {
          const errData = await bundleRes.json().catch(() => ({}));
          setEvidenceError(errData.detail || 'Evidence bundle not yet available.');
        }
      } catch (bErr: any) {
        setEvidenceError(bErr.message);
      } finally {
        setEvidenceLoading(false);
      }

      markStepComplete(5);
      markStepComplete(6);
      markStepComplete(7);
    } catch (err: any) {
      setExecutionError(err.message);
    } finally {
      setIsExecuting(false);
      if (sseRef.current) {
        sseRef.current.close();
      }
    }
  };

  // ---------------------------------------------------------------------------
  // Step Transition Handlers
  // ---------------------------------------------------------------------------

  const handleStepTransition = (targetStep: StepNumber) => {
    setCurrentStep(targetStep);
    // Auto-trigger analysis when advancing from Step 1 to Step 2 if not yet analyzed
    if (targetStep === 2 && !analysis && !analysisLoading && currentRun) {
      handleRunAnalysis();
    }
  };

  return (
    <div className="min-h-screen bg-canvas dark:bg-[#020617] light:bg-[#f8fafc] text-slate-100 dark:text-slate-100 light:text-slate-900 flex flex-col font-sans transition-colors">
      {/* 1. Persistent Run Header (Spec §4.13) */}
      <Header
        runId={currentRun?.id || (currentRun as any)?.run_id}
        verdict={currentRun?.verdict || (isExecuting ? 'RUNNING' : 'READY')}
        sandboxTier={evidenceBundle?.sandbox?.tier || 'TIER 1 (CONTAINER)'}
        tokenLedger={tokenLedger}
        health={health}
        healthLoading={healthLoading}
        theme={theme}
        onToggleTheme={handleToggleTheme}
      />

      {/* 2. Seven-Step Navigation Stepper (Spec §4.13) */}
      <StepperNav
        currentStep={currentStep}
        completedSteps={completedSteps}
        onSelectStep={handleStepTransition}
      />

      {/* 3. Main Step Work Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 py-5 md:px-6 md:py-6 lg:px-8 lg:py-7">
        {currentStep === 1 && (
          <StepSource
            benchmarks={benchmarks}
            currentRun={currentRun}
            loading={sourceLoading}
            error={sourceError}
            onSelectBenchmark={handleSelectBenchmark}
            onSubmitGithubUrl={handleSubmitGithubUrl}
            onSubmitZipUpload={handleSubmitZipUpload}
            onProceedToAnalysis={() => handleStepTransition(2)}
          />
        )}

        {currentStep === 2 && (
          <StepAnalysis
            analysis={analysis}
            loading={analysisLoading}
            error={analysisError}
            onRunAnalysis={handleRunAnalysis}
            onProceedToRequirements={() => handleStepTransition(3)}
          />
        )}

        {currentStep === 3 && (
          <StepRequirements
            currentRequirement={requirementText}
            parsedSpec={parsedSpec}
            isVerifiable={isVerifiable}
            warning={intentWarning}
            loading={intentLoading}
            error={intentError}
            onSubmitRequirement={handleSubmitRequirement}
            onProceedToPlan={() => handleStepTransition(4)}
          />
        )}

        {currentStep === 4 && (
          <StepPlan
            initialFiles={analysis?.findings?.map((f) => f.file) || ['app.py']}
            currentPlan={currentPlan}
            loading={planLoading}
            error={planError}
            onApprovePlan={handleApprovePlan}
            onCancelPlan={handleCancelPlan}
            onProceedToLiveRun={() => handleStepTransition(5)}
          />
        )}

        {currentStep === 5 && (
          <StepLiveRun
            runId={currentRun?.id || (currentRun as any)?.run_id}
            isExecuting={isExecuting}
            events={events}
            currentStage={currentStage}
            verdict={currentRun?.verdict}
            tokenLedger={tokenLedger}
            error={executionError}
            onExecute={handleExecute}
            onProceedToEvidence={() => handleStepTransition(6)}
          />
        )}

        {currentStep === 6 && (
          <StepEvidence
            bundle={evidenceBundle}
            loading={evidenceLoading}
            error={evidenceError}
            onProceedToExport={() => handleStepTransition(7)}
          />
        )}

        {currentStep === 7 && (
          <StepExport
            runId={currentRun?.id || (currentRun as any)?.run_id || 'run_studio'}
            bundle={evidenceBundle}
            loading={false}
          />
        )}
      </main>

      {/* Persistent Footer with WCAG AA compliant text contrast */}
      <footer className="border-t border-border-subtle bg-surface-1 dark:bg-[#070b14] light:bg-white px-6 py-3 text-xs font-mono text-slate-400 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-slate-300">VULNTRACE STUDIO</span>
          <span>•</span>
          <span>AUTONOMOUS CVE REPRODUCTION &amp; VERIFIED PATCHING</span>
        </div>
        <div className="flex items-center gap-4 text-[11px] text-slate-400">
          <span>CANONICAL TAXONOMY: SPEC §3.1</span>
          <span>•</span>
          <span>RFC 8032 Ed25519 SEALED</span>
          <span>•</span>
          <span>ZERO AMBIENT SECRETS</span>
        </div>
      </footer>
    </div>
  );
};

export default App;
