"""
VulnTrace Data Models & API Contracts
Defines schemas for repository inspection, CVE intelligence, AST reachability, and pipeline streaming.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

# --- Provider Health ---
class ProviderStatus(BaseModel):
    name: str
    configured: bool
    status: str  # "ONLINE", "UNAUTHORIZED", "MISSING_KEY", "FORBIDDEN"
    latency_ms: Optional[float] = None
    detail: Optional[str] = None
    available_models: List[str] = Field(default_factory=list)

class SystemHealthResponse(BaseModel):
    version: str = "0.1.0"
    providers: Dict[str, ProviderStatus]

# --- Repository Inspection ---
class DependencyItem(BaseModel):
    name: str
    version_spec: str
    manifest_source: str  # "requirements.txt", "pyproject.toml", "package.json"
    ecosystem: str        # "PyPI", "npm"

class RepoInspectRequest(BaseModel):
    repo_path: str

class RepoInspectResponse(BaseModel):
    repo_path: str
    exists: bool
    git_branch: Optional[str] = None
    git_commit: Optional[str] = None
    manifest_files: List[str] = Field(default_factory=list)
    python_files_count: int = 0
    dependencies: List[DependencyItem] = Field(default_factory=list)
    error: Optional[str] = None

# --- CVE Intelligence ---
class AdvisoryCommitRange(BaseModel):
    type: str
    repo: Optional[str] = None
    introduced: Optional[str] = None
    fixed: Optional[str] = None
    last_affected: Optional[str] = None

class AffectedPackage(BaseModel):
    package_name: str
    ecosystem: str
    ranges: List[AdvisoryCommitRange] = Field(default_factory=list)
    database_cpe: Optional[str] = None

class PocFinding(BaseModel):
    title: str
    url: str
    snippet: str
    source: str

class CveQueryRequest(BaseModel):
    cve_id: str
    query_tavily: bool = True

class CveQueryResponse(BaseModel):
    cve_id: str
    found: bool
    aliases: List[str] = Field(default_factory=list)
    summary: str
    details: str
    affected_packages: List[AffectedPackage] = Field(default_factory=list)
    cvss_score: Optional[float] = None
    pocs: List[PocFinding] = Field(default_factory=list)
    source_url: str
    latency_ms: float
    error: Optional[str] = None

# --- AST Call-Graph Reachability ---
class CallGraphNode(BaseModel):
    id: str               # e.g., "service.py:load_user_config"
    label: str            # e.g., "load_user_config()"
    file: str             # e.g., "service.py"
    node_type: str        # "ENTRYPOINT", "FUNCTION", "VULNERABLE_CALL", "DEAD_CODE"
    line_number: int
    is_vulnerable: bool = False
    vulnerability_details: Optional[str] = None

class CallGraphEdge(BaseModel):
    source: str           # node id
    target: str           # node id
    call_name: str        # e.g., "yaml.load"

class VulnerableCallSite(BaseModel):
    file: str
    function_name: str
    call_name: str
    line_number: int
    reachable: bool
    call_path_from_entrypoint: List[str] = Field(default_factory=list)

class AstAnalyzeRequest(BaseModel):
    repo_path: str
    target_symbols: List[str] = Field(default_factory=lambda: [
        "yaml.load", "yaml.full_load", "os.system", "subprocess.Popen",
        "subprocess.call", "pickle.loads", "pickle.load", "eval", "exec"
    ])
    entrypoints: List[str] = Field(default_factory=list)

class AstAnalyzeResponse(BaseModel):
    repo_path: str
    analyzed_files: List[str]
    total_functions: int
    discovered_calls: List[VulnerableCallSite]
    reachable_vulnerabilities_count: int
    unreachable_dead_code_count: int
    verdict: str  # "REACHABLE_CALL_PATH_IDENTIFIED", "UNREACHABLE_FALSE_POSITIVE", "NO_VULNERABILITIES_FOUND"
    nodes: List[CallGraphNode]
    edges: List[CallGraphEdge]
    latency_ms: float
    error: Optional[str] = None

# --- Phase 2: Verification Harness & Execution ---
class HarnessGenerateRequest(BaseModel):
    repo_path: str
    cve_id: str
    target_file: str
    function_name: str
    vulnerable_call: str
    sentinel_filename: Optional[str] = None

class HarnessGenerateResponse(BaseModel):
    cve_id: str
    target_file: str
    function_name: str
    harness_code: str
    sentinel_filename: str
    latency_ms: float

class SandboxExecutionResult(BaseModel):
    exit_code: int
    stdout: str
    stderr: str
    latency_ms: float
    sentinel_created: bool
    reproduction_state: str  # "RED_STATE_REPRODUCED", "GREEN_STATE_BLOCKED", "INCONCLUSIVE", "TIMED_OUT", "ERROR", "UNEXPECTED_FAILURE", "VERIFICATION_REJECTED"
    assertion_result: Optional[str] = None
    exception_type: Optional[str] = None
    structured_evidence: Optional[Dict[str, Any]] = None
    parent_validated: bool = False
    validation_notes: Optional[str] = None
    sandbox_engine: str      # "LOCAL_SUBPROCESS_FALLBACK", "CONTREE_CLOUD"
    disposable_dir: Optional[str] = None
    error: Optional[str] = None

class RemediationRequest(BaseModel):
    repo_path: str
    cve_id: str
    target_file: str
    vulnerable_call: str
    use_nemotron: bool = True
    allow_ast_fallback: bool = False
    advisory_summary: Optional[str] = None

class PatchDeltaMetadata(BaseModel):
    changed_files: List[str] = Field(default_factory=list)
    changed_functions: List[str] = Field(default_factory=list)
    additions_count: int = 0
    deletions_count: int = 0
    total_lines_changed: int = 0
    diff_bytes: int = 0
    is_minimal: bool = True
    minimality_criterion: str = "<= 10 lines changed, strictly scoped to target sink"
    tests_affected_count: int = 0
    reason_for_change: str = ""

class RemediationResponse(BaseModel):
    cve_id: str
    target_file: str
    engine: str  # "NVIDIA_NEMOTRON_3_ULTRA", "AST_DETERMINISTIC_CODEMOD", "SKIPPED", "REJECTED"
    diff: str
    explanation: str
    tokens_used: Optional[int] = None
    reasoning_tokens: Optional[int] = None
    latency_ms: float
    success: bool
    validation_status: Optional[str] = None  # "ACCEPTED", "REJECTED_SYNTAX_ERROR", "REJECTED_EMPTY", "SKIPPED"
    patch_delta: Optional[PatchDeltaMetadata] = None
    model_name: Optional[str] = None
    error: Optional[str] = None

class BenchmarkScenarioInfo(BaseModel):
    id: str
    name: str
    description: str
    cve_id: str
    repo_path: str
    target_file: str
    target_function: str
    expected_reachability: str
    expected_behavioral_verdict: str
    highlight: str

class VerificationPipelineRequest(BaseModel):
    repo_path: str
    cve_id: str
    target_file: Optional[str] = None
    target_function: Optional[str] = None
    vulnerable_symbol: Optional[str] = None
    sentinel_filename: Optional[str] = None
    entrypoints: List[str] = Field(default_factory=list)
    use_nemotron: bool = True
    query_tavily: bool = True
    advisory_summary: Optional[str] = None

# --- Formal Evidence Schema (Phase 4) ---
class RepositoryEvidence(BaseModel):
    repo_path: str
    manifest_files: List[str] = Field(default_factory=list)
    dependencies: List[DependencyItem] = Field(default_factory=list)
    python_files_count: int = 0
    git_commit: Optional[str] = None

class AdvisoryEvidence(BaseModel):
    cve_id: str
    found: bool
    summary: str
    affected_packages: List[AffectedPackage] = Field(default_factory=list)
    cvss_score: Optional[float] = None
    pocs_count: int = 0
    pocs: List[PocFinding] = Field(default_factory=list)
    source_url: str
    tavily_latency_ms: Optional[float] = None

class ReachabilityEvidence(BaseModel):
    target_symbol: str
    discovered_call_sites_count: int
    reachable_vulnerabilities_count: int
    unreachable_dead_code_count: int
    entrypoints: List[str] = Field(default_factory=list)
    call_paths: List[List[str]] = Field(default_factory=list)
    verdict: str  # "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED", "UNREACHABLE_FALSE_POSITIVE", "NO_VULNERABILITIES_FOUND"

class BehaviorEvidence(BaseModel):
    pre_patch_exit_code: int
    pre_patch_sentinel_observed: bool
    pre_patch_state: str  # "RED_STATE_REPRODUCED", "INCONCLUSIVE", "UNEXPECTED_FAILURE", "VERIFICATION_REJECTED"
    pre_patch_assertion: Optional[str] = None
    post_patch_exit_code: int
    post_patch_sentinel_observed: bool
    post_patch_state: str # "GREEN_STATE_BLOCKED", "VERIFICATION_REJECTED", "RED_STATE_PERSISTS", "UNEXPECTED_FAILURE"
    post_patch_assertion: Optional[str] = None
    parent_validated: bool = False
    validation_notes: Optional[str] = None

class PatchEvidence(BaseModel):
    engine: str           # "NVIDIA_NEMOTRON_3_ULTRA", "AST_DETERMINISTIC_CODEMOD", "SKIPPED", "FAILED"
    target_file: str
    diff: str
    validation_status: str # "ACCEPTED", "REJECTED_SYNTAX_ERROR", "REJECTED_EMPTY", "REJECTED_API_ERROR", "SKIPPED"
    tokens_used: Optional[int] = None
    reasoning_tokens: Optional[int] = None
    latency_ms: float
    success: bool

class RegressionEvidence(BaseModel):
    executed: bool
    passed: bool
    test_count: int
    failures_count: int = 0
    latency_ms: float
    error: Optional[str] = None

class ExecutionEvidence(BaseModel):
    sandbox_engine: str   # "LOCAL_SUBPROCESS_FALLBACK"
    cloud_status: str     # "PERMISSION_DENIED (HTTP 403)"
    disposable_dir: Optional[str] = None
    purged_env_secrets_count: int = 0
    timeout_seconds: float = 10.0
    parent_audit_passed: bool = False
    isolation_limits: Dict[str, str] = Field(default_factory=lambda: {
        "isolated": "disposable directory copy, purged credentials/secrets, timeout watchdog, process-tree termination",
        "unisolated": "shared host OS kernel, host localhost loopback"
    })

class FinalVerdictRecord(BaseModel):
    terminal_state: str  # "GREEN_STATE_VERIFIED", "UNREACHABLE_FALSE_POSITIVE", "INCONCLUSIVE", "PATCH_REJECTED", "REGRESSION_FAILURE", "UNEXPECTED_FAILURE", "VERIFICATION_REJECTED"
    cve_id: str
    repo_path: str
    reason: str
    timestamp: float
    evidence_summary: Dict[str, Any]
    is_safe_claim: bool = False  # Explicit: local reachability does NOT claim absolute safety
    limitations: List[str] = Field(default_factory=lambda: [
        "Static AST analysis cannot resolve reflection, dynamic imports (importlib), or runtime monkey-patching.",
        "Local subprocess sandbox shares host kernel and is labeled LOCAL_SUBPROCESS_FALLBACK.",
        "ConTree cloud execution is currently blocked (PERMISSION_DENIED HTTP 403)."
    ])

class VerificationPipelineResponse(BaseModel):
    cve_id: str
    repo_path: str
    reachability_verdict: str  # "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED", "UNREACHABLE_FALSE_POSITIVE"
    harness: HarnessGenerateResponse
    pre_patch_result: SandboxExecutionResult   # RED STATE
    remediation: RemediationResponse
    post_patch_result: SandboxExecutionResult  # GREEN STATE
    regression_tests: Dict[str, Any]           # pytest results
    final_behavioral_verdict: str              # "GREEN_STATE_VERIFIED", "RED_STATE_PERSISTS", "REGRESSION_FAILURE", "INCONCLUSIVE", "PATCH_REJECTED", "UNREACHABLE_FALSE_POSITIVE", "UNEXPECTED_FAILURE", "VERIFICATION_REJECTED"
    structured_evidence: Optional[Dict[str, Any]] = None
    verdict_record: Optional[FinalVerdictRecord] = None
    sandbox_engine: str                        # "LOCAL_SUBPROCESS_FALLBACK"
    cloud_status: str                          # "PERMISSION_DENIED (HTTP 403)"
    total_pipeline_ms: float

# --- Streaming Pipeline Event ---
class PipelineEvent(BaseModel):
    event_type: str  # "LOG", "STAGE_START", "STAGE_COMPLETE", "STATE_TRANSITION", "ERROR"
    stage: str       # "INTEL", "AST", "HARNESS", "REPRODUCTION", "PATCH", "VERIFICATION", "REGRESSION"
    message: str
    data: Optional[Dict[str, Any]] = None
    timestamp: float

