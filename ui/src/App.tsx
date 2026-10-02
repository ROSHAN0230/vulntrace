import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { RepoSelector } from './components/RepoSelector';
import { CveInspector } from './components/CveInspector';
import { AstGraphView } from './components/AstGraphView';
import { VerificationWorkbench } from './components/VerificationWorkbench';
import { ExecutionTerminal } from './components/ExecutionTerminal';
import {
  SystemHealthResponse,
  RepoInspectResponse,
  CveQueryResponse,
  AstAnalyzeResponse,
  VerificationPipelineResponse,
  BenchmarkScenarioInfo,
  LogLine
} from './types';

export const App: React.FC = () => {
  const [health, setHealth] = useState<SystemHealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState<boolean>(true);

  const [benchmarks, setBenchmarks] = useState<BenchmarkScenarioInfo[]>([]);
  const [activeScenario, setActiveScenario] = useState<BenchmarkScenarioInfo | null>(null);

  const [repoData, setRepoData] = useState<RepoInspectResponse | null>(null);
  const [repoLoading, setRepoLoading] = useState<boolean>(false);
  const [repoError, setRepoError] = useState<string | undefined>();

  const [cveData, setCveData] = useState<CveQueryResponse | null>(null);
  const [cveLoading, setCveLoading] = useState<boolean>(false);
  const [cveError, setCveError] = useState<string | undefined>();

  const [astData, setAstData] = useState<AstAnalyzeResponse | null>(null);
  const [astLoading, setAstLoading] = useState<boolean>(false);
  const [astError, setAstError] = useState<string | undefined>();

  const [verificationData, setVerificationData] = useState<VerificationPipelineResponse | null>(null);
  const [verificationLoading, setVerificationLoading] = useState<boolean>(false);
  const [verificationError, setVerificationError] = useState<string | undefined>();

  const [logs, setLogs] = useState<LogLine[]>([]);

  const addLog = (stage: LogLine['stage'], message: string, level: LogLine['level'] = 'info') => {
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
    setLogs((prev) => [
      ...prev,
      {
        id: Math.random().toString(36).substring(2, 9),
        timestamp: timeStr,
        stage,
        message,
        level
      }
    ]);
  };

  // 1. Fetch system health and benchmark scenarios on mount
  useEffect(() => {
    const initApp = async () => {
      setHealthLoading(true);
      addLog('SYSTEM', 'Connecting to VulnTrace API (/api/v1/health & /api/v1/benchmarks)...', 'info');
      try {
        const [healthRes, benchRes] = await Promise.all([
          fetch('/api/v1/health'),
          fetch('/api/v1/benchmarks')
        ]);

        if (healthRes.ok) {
          const hData: SystemHealthResponse = await healthRes.json();
          setHealth(hData);
          addLog('SYSTEM', `Health check passed. ${Object.keys(hData.providers).length} providers probed.`, 'success');
        }

        if (benchRes.ok) {
          const bData: BenchmarkScenarioInfo[] = await benchRes.json();
          setBenchmarks(bData);
          if (bData.length > 0) {
            setActiveScenario(bData[0]);
            addLog('SYSTEM', `Loaded ${bData.length} Phase 3 benchmark scenarios. Default: ${bData[0].name}`, 'info');
            // Auto inspect default
            handleInspectRepo(bData[0].repo_path);
          }
        }
      } catch (err: any) {
        addLog('SYSTEM', `Initialization error: ${err.message}`, 'error');
      } finally {
        setHealthLoading(false);
      }
    };
    initApp();
  }, []);

  // 2. Action: Inspect Repository
  const handleInspectRepo = async (path: string) => {
    setRepoLoading(true);
    setRepoError(undefined);
    addLog('REPO', `Inspecting repository manifests at: ${path}`, 'info');

    try {
      const resp = await fetch('/api/v1/repo/inspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_path: path })
      });

      if (!resp.ok) {
        const errJson = await resp.json().catch(() => ({}));
        throw new Error(errJson.detail || `HTTP ${resp.status}: ${resp.statusText}`);
      }

      const data: RepoInspectResponse = await resp.json();
      setRepoData(data);
      addLog('REPO', `Inspection complete: ${data.python_files_count} modules, ${data.dependencies.length} packages found.`, 'success');
    } catch (err: any) {
      setRepoError(err.message);
      addLog('REPO', `Inspection error: ${err.message}`, 'error');
    } finally {
      setRepoLoading(false);
    }
  };

  // 3. Action: Query CVE Threat Intelligence
  const handleQueryCve = async (cveId: string) => {
    setCveLoading(true);
    setCveError(undefined);
    addLog('INTEL', `Fetching live OSV advisory and Tavily PoCs for: ${cveId}`, 'info');

    try {
      const resp = await fetch('/api/v1/intel/cve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cve_id: cveId, query_tavily: true })
      });

      if (!resp.ok) {
        const errJson = await resp.json().catch(() => ({}));
        throw new Error(errJson.detail || `HTTP ${resp.status}: ${resp.statusText}`);
      }

      const data: CveQueryResponse = await resp.json();
      setCveData(data);
      if (data.found) {
        addLog('INTEL', `Advisory retrieved (${data.latency_ms}ms). Found ${data.affected_packages.length} affected ranges, ${data.pocs.length} Tavily PoCs.`, 'success');
      } else {
        addLog('INTEL', `CVE not found in database: ${data.cve_id}`, 'warn');
      }
    } catch (err: any) {
      setCveError(err.message);
      addLog('INTEL', `Intelligence retrieval failed: ${err.message}`, 'error');
    } finally {
      setCveLoading(false);
    }
  };

  // 4. Action: Run AST Call-Graph Reachability Solver
  const handleRunAst = async () => {
    const targetPath = repoData?.repo_path || activeScenario?.repo_path;
    if (!targetPath) {
      setAstError('Please inspect a valid target repository first.');
      return;
    }

    setAstLoading(true);
    setAstError(undefined);
    addLog('AST', `Parsing AST call-graph across: ${targetPath}...`, 'info');

    try {
      const resp = await fetch('/api/v1/ast/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_path: targetPath })
      });

      if (!resp.ok) {
        const errJson = await resp.json().catch(() => ({}));
        throw new Error(errJson.detail || `HTTP ${resp.status}: ${resp.statusText}`);
      }

      const data: AstAnalyzeResponse = await resp.json();
      setAstData(data);

      if (data.verdict === 'REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED' || data.verdict === 'REACHABLE_CALL_PATH_IDENTIFIED') {
        addLog('AST', `REACHABLE CALL PATH: ${data.reachable_vulnerabilities_count} active call path(s) identified. Controlled behavioral verification required.`, 'warn');
      } else if (data.verdict === 'UNREACHABLE_FALSE_POSITIVE') {
        addLog('AST', `FALSE POSITIVE CONFIRMED: Vulnerability isolated in unreferenced dead code (${data.unreachable_dead_code_count} dead site(s)).`, 'success');
      } else {
        addLog('AST', `Analysis finished (${data.latency_ms}ms). No target symbols found.`, 'info');
      }
    } catch (err: any) {
      setAstError(err.message);
      addLog('AST', `AST solver error: ${err.message}`, 'error');
    } finally {
      setAstLoading(false);
    }
  };

  // 5. Action: Execute Phase 3 Controlled Defensive Verification Pipeline
  const handleRunVerification = async () => {
    const targetRepo = repoData?.repo_path || activeScenario?.repo_path;
    if (!targetRepo) {
      setVerificationError('Please inspect a target repository first.');
      return;
    }

    // Determine target file and function dynamically from active scenario or AST findings
    let targetFile = activeScenario?.target_file || 'service.py';
    let targetFunction = activeScenario?.target_function || 'load_user_config';

    if (astData && astData.discovered_calls.length > 0) {
      const firstCall = astData.discovered_calls.find(c => c.reachable) || astData.discovered_calls[0];
      targetFile = firstCall.file;
      targetFunction = firstCall.function_name;
    }

    setVerificationLoading(true);
    setVerificationError(undefined);

    const jobId = 'job_' + Math.random().toString(36).substring(2, 10);
    addLog('SYSTEM', `Initiating verification pipeline session [${jobId}] on ${targetFile}:${targetFunction}()...`, 'info');

    // Subscribe to SSE events
    const eventSource = new EventSource(`/api/v1/pipeline/stream/${jobId}`);
    eventSource.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.stage && payload.message) {
          addLog(payload.stage as any, payload.message, payload.event_type === 'ERROR' ? 'error' : 'info');
        }
      } catch (e) {
        // Heartbeat or raw message
      }
    };

    try {
      const resp = await fetch(`/api/v1/pipeline/run?job_id=${jobId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo_path: targetRepo,
          cve_id: cveData?.cve_id || activeScenario?.cve_id || 'CVE-2020-14343',
          target_file: targetFile,
          target_function: targetFunction,
          vulnerable_symbol: 'yaml.load',
          use_nemotron: true
        })
      });

      if (!resp.ok) {
        const errJson = await resp.json().catch(() => ({}));
        throw new Error(errJson.detail || `HTTP ${resp.status}: ${resp.statusText}`);
      }

      const data: VerificationPipelineResponse = await resp.json();
      setVerificationData(data);
      addLog('VERIFICATION', `Defensive verification complete: ${data.final_behavioral_verdict} (${data.total_pipeline_ms}ms)`, 'success');
    } catch (err: any) {
      setVerificationError(err.message);
      addLog('ERROR', `Verification pipeline failed: ${err.message}`, 'error');
    } finally {
      eventSource.close();
      setVerificationLoading(false);
    }
  };

  const handleSelectScenario = (sc: BenchmarkScenarioInfo) => {
    setActiveScenario(sc);
    setAstData(null);
    setVerificationData(null);
    addLog('SYSTEM', `Switched active benchmark scenario to: ${sc.name}`, 'info');
  };

  return (
    <div className="min-h-screen bg-canvas text-slate-100 flex flex-col font-sans">
      <Header health={health} loading={healthLoading} />

      <main className="flex-1 p-5 max-w-[1720px] w-full mx-auto grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column: Repository, Intelligence, and Terminal (5 cols) */}
        <div className="lg:col-span-5 space-y-5 flex flex-col">
          <RepoSelector
            onInspect={handleInspectRepo}
            data={repoData}
            loading={repoLoading}
            error={repoError}
            benchmarks={benchmarks}
            activeScenario={activeScenario}
            onSelectScenario={handleSelectScenario}
          />
          <CveInspector
            onQuery={handleQueryCve}
            data={cveData}
            loading={cveLoading}
            error={cveError}
          />
          <div className="flex-1 min-h-[300px]">
            <ExecutionTerminal
              logs={logs}
              onClear={() => setLogs([])}
              statusText={
                verificationLoading
                  ? 'Executing sandbox verification & Nemotron patch...'
                  : astLoading || repoLoading || cveLoading
                  ? 'Executing backend query...'
                  : undefined
              }
            />
          </div>
        </div>

        {/* Right Column: AST Call-Graph & Behavioral Verification Workbench (7 cols) */}
        <div className="lg:col-span-7 space-y-5 flex flex-col">
          <AstGraphView
            onAnalyze={handleRunAst}
            data={astData}
            loading={astLoading}
            error={astError}
          />
          <VerificationWorkbench
            onRunPipeline={handleRunVerification}
            data={verificationData}
            loading={verificationLoading}
            error={verificationError}
            reachabilityReady={Boolean(astData && astData.reachable_vulnerabilities_count > 0)}
          />
        </div>
      </main>
    </div>
  );
};

export default App;
