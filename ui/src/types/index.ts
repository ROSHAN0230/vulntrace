export interface ProviderStatus {
  name: string;
  configured: boolean;
  status: string;
  latency_ms?: number;
  detail?: string;
  available_models?: string[];
}

export interface SystemHealthResponse {
  version: string;
  providers: Record<string, ProviderStatus>;
}

export interface DependencyItem {
  name: string;
  version_spec: string;
  manifest_source: string;
  ecosystem: string;
}

export interface RepoInspectResponse {
  repo_path: string;
  exists: boolean;
  git_branch?: string;
  git_commit?: string;
  manifest_files: string[];
  python_files_count: number;
  dependencies: DependencyItem[];
  error?: string;
}

export interface AdvisoryCommitRange {
  type: string;
  repo?: string;
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

export interface AffectedPackage {
  package_name: string;
  ecosystem: string;
  ranges: AdvisoryCommitRange[];
  database_cpe?: string;
}

export interface PocFinding {
  title: string;
  url: string;
  snippet: string;
  source: string;
}

export interface CveQueryResponse {
  cve_id: string;
  found: boolean;
  aliases: string[];
  summary: string;
  details: string;
  affected_packages: AffectedPackage[];
  cvss_score?: number;
  pocs: PocFinding[];
  source_url: string;
  latency_ms: number;
  error?: string;
}

export interface CallGraphNode {
  id: string;
  label: string;
  file: string;
  node_type: 'ENTRYPOINT' | 'FUNCTION' | 'VULNERABLE_CALL' | 'DEAD_CODE';
  line_number: number;
  is_vulnerable: boolean;
  vulnerability_details?: string;
}

export interface CallGraphEdge {
  source: string;
  target: string;
  call_name: string;
}

export interface VulnerableCallSite {
  file: string;
  function_name: string;
  call_name: string;
  line_number: number;
  reachable: boolean;
  call_path_from_entrypoint: string[];
}

export interface AstAnalyzeResponse {
  repo_path: string;
  analyzed_files: string[];
  total_functions: number;
  discovered_calls: VulnerableCallSite[];
  reachable_vulnerabilities_count: number;
  unreachable_dead_code_count: number;
  verdict: 'REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED' | 'REACHABLE_CALL_PATH_IDENTIFIED' | 'REACHABLE_CONFIRMED' | 'UNREACHABLE_FALSE_POSITIVE' | 'NO_VULNERABILITIES_FOUND';
  nodes: CallGraphNode[];
  edges: CallGraphEdge[];
  latency_ms: number;
  error?: string;
}

export interface HarnessGenerateResponse {
  cve_id: string;
  target_file: string;
  function_name: string;
  harness_code: string;
  sentinel_filename: string;
  latency_ms: number;
}

export interface SandboxExecutionResult {
  exit_code: number;
  stdout: string;
  stderr: string;
  latency_ms: number;
  sentinel_created: boolean;
  reproduction_state: 'RED_STATE_REPRODUCED' | 'GREEN_STATE_BLOCKED' | 'INCONCLUSIVE' | 'TIMED_OUT' | 'ERROR' | 'UNEXPECTED_FAILURE' | 'VERIFICATION_REJECTED';
  assertion_result?: string;
  exception_type?: string;
  structured_evidence?: Record<string, any>;
  parent_validated?: boolean;
  validation_notes?: string;
  sandbox_engine: string;
  disposable_dir?: string;
  error?: string;
}

export interface PatchDeltaMetadata {
  changed_files: string[];
  changed_functions: string[];
  additions_count: number;
  deletions_count: number;
  total_lines_changed: number;
  diff_bytes: number;
  is_minimal: boolean;
  minimality_criterion: string;
  tests_affected_count: number;
  reason_for_change: string;
}

export interface RemediationResponse {
  cve_id: string;
  target_file: string;
  engine: string;
  diff: string;
  explanation: string;
  tokens_used?: number;
  reasoning_tokens?: number;
  latency_ms: number;
  success: boolean;
  validation_status?: string;
  patch_delta?: PatchDeltaMetadata;
  error?: string;
}

export interface FinalVerdictRecord {
  terminal_state: string;
  cve_id: string;
  repo_path: string;
  reason: string;
  timestamp: number;
  evidence_summary: Record<string, any>;
  is_safe_claim: boolean;
  limitations: string[];
  assurance_level?: string;
  policy_audit?: Record<string, any>;
}

export interface VerificationPipelineResponse {
  cve_id: string;
  repo_path: string;
  reachability_verdict: string;
  harness: HarnessGenerateResponse;
  pre_patch_result: SandboxExecutionResult;
  remediation: RemediationResponse;
  post_patch_result: SandboxExecutionResult;
  regression_tests: {
    passed: boolean;
    exit_code: number;
    stdout: string;
    stderr: string;
    test_count?: number;
    latency_ms: number;
    error?: string;
  };
  final_behavioral_verdict: string;
  structured_evidence?: Record<string, any>;
  verdict_record?: FinalVerdictRecord;
  sandbox_engine: string;
  cloud_status: string;
  total_pipeline_ms: number;
  isolation_tier?: string;
  isolation_attestation?: Record<string, any>;
  assurance_level?: string;
  policy_decision?: Record<string, any>;
}

export interface BenchmarkScenarioInfo {
  id: string;
  name: string;
  description: string;
  cve_id: string;
  repo_path: string;
  target_file: string;
  target_function: string;
  expected_reachability: string;
  expected_behavioral_verdict: string;
  highlight: string;
}

export interface LogLine {
  id: string;
  timestamp: string;
  stage: 'INTEL' | 'REPO' | 'AST' | 'HARNESS' | 'REPRODUCTION' | 'PATCH' | 'VERIFICATION' | 'REGRESSION' | 'SYSTEM' | 'ERROR';
  message: string;
  level: 'info' | 'warn' | 'error' | 'success';
}
