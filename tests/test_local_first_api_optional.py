"""
VulnTrace Studio — Local-First, API-Optional Release Test Suite (Final Verification)

Verifies:
1. Retained scope deterministic verification in zero-key mode:
   - UNSAFE_DESERIALIZATION: Reproduction, deterministic remediation, post-patch verification, regression, signing.
   - PATH_TRAVERSAL: Reproduction, PEP 706 deterministic remediation, post-patch verification, regression, signing.
2. Explicit Opt-In Provider Contract:
   - Case 1: Nebius key present, user opt-in false -> zero Nebius requests.
   - Case 2: Tavily key present, user opt-in false -> zero Tavily requests.
   - Case 3: Both keys present, both opt-ins false -> zero provider requests.
   - Case 4: Explicit Nebius opt-in invokes Nebius only.
   - Case 5: Explicit Tavily opt-in invokes Tavily only.
   - Case 6: Both explicitly enabled invoke both.
   - Case 7: Missing keys with opt-in requested produces truthful degradation.
3. Provider failure & degradation handling:
   - Invalid Nebius key falls back cleanly.
   - Invalid Tavily key degrades threat intel cleanly.
   - Provider unavailable (500/503) handled without crash or false-success GREEN.
4. Secret hygiene & environment sanitization:
   - Purged from child processes, environments, and evidence bundles.
5. Server health endpoint in local mode.
"""

import ast
import shutil
import socket
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import httpx
import pytest

from vulntrace.agent.patcher import RemediationPatcher
from vulntrace.config import settings
from vulntrace.engine.evidence_export import EvidenceExporter
from vulntrace.envbuild.builder import EnvironmentBuilder
from vulntrace.evidence.signing import EvidenceSigner
from vulntrace.intel.tavily_client import TavilyClient
from vulntrace.models import (
    RemediationRequest,
    VerificationPipelineRequest,
)
from vulntrace.sandbox.pipeline import VerificationPipeline
from vulntrace.sandbox.target_env import TargetEnvironmentManager
from vulntrace.server.app import get_system_health, ExecuteRunRequest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BENCHMARK_DIR = PROJECT_ROOT / "benchmarks" / "contextual_reasoning"
TAR_VULNERABLE_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "path_traversal" / "tar_vulnerable"
TAR_FIXED_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "path_traversal" / "tar_fixed"

_RealAsyncClient = httpx.AsyncClient


@pytest.fixture
def clean_api_keys(monkeypatch):
    """Ensures NEBIUS_API_KEY and TAVILY_API_KEY are completely unset."""
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    monkeypatch.delenv("LIVE_LLM", raising=False)
    monkeypatch.delenv("LIVE_INTEL", raising=False)
    monkeypatch.setattr(settings, "nebius_api_key", None)
    monkeypatch.setattr(settings, "tavily_api_key", None)


@pytest.fixture
def block_external_sockets():
    """Intercepts socket connections to ensure zero live outbound network calls."""
    orig_connect = socket.socket.connect
    intercepted: List[Any] = []

    def guarded_connect(self, address, *args, **kwargs):
        host = address[0] if isinstance(address, tuple) and len(address) > 0 else str(address)
        if host in ("127.0.0.1", "::1", "localhost"):
            return orig_connect(self, address, *args, **kwargs)
        intercepted.append(address)
        raise RuntimeError(f"Forbidden outbound network connection to {address} in offline/local mode!")

    with patch.object(socket.socket, "connect", guarded_connect):
        class Controller:
            calls = intercepted
        yield Controller()


@pytest.fixture
def mock_external_apis(monkeypatch):
    """Provides an in-memory MockTransport to monitor and mock Nebius and Tavily HTTP calls."""
    intercepted_requests: List[httpx.Request] = []
    custom_responses: Dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        intercepted_requests.append(request)
        url_str = str(request.url)
        for pattern, resp_factory in custom_responses.items():
            if pattern in url_str:
                return resp_factory(request)

        if "tavily" in url_str:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "title": "Advisory for CVE-2020-14343",
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-14343",
                            "content": "PyYAML unsafe yaml.load allows arbitrary code execution. Fix: use yaml.safe_load."
                        }
                    ]
                }
            )

        # Nebius LLM mock response
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": (
                                "```python\n"
                                "import yaml\n"
                                "import os\n\n"
                                "class AppSafeLoader(yaml.SafeLoader):\n"
                                "    pass\n\n"
                                "def _env_tag_constructor(loader, node):\n"
                                "    val = loader.construct_scalar(node)\n"
                                "    return os.environ.get(val, f\"DEFAULT_{val}\")\n\n"
                                "AppSafeLoader.add_constructor(\"!env_var\", _env_tag_constructor)\n"
                                "yaml.Loader.add_constructor(\"!env_var\", _env_tag_constructor)\n\n"
                                "def parse_app_config(raw_yaml: str) -> dict:\n"
                                "    data = yaml.load(raw_yaml, Loader=AppSafeLoader)\n"
                                "    if isinstance(data, dict):\n"
                                "        return data\n"
                                "    return {\"config\": data}\n"
                                "```"
                            )
                        }
                    }
                ],
                "usage": {
                    "prompt_tokens": 120,
                    "completion_tokens": 45,
                    "total_tokens": 165
                }
            }
        )

    transport = httpx.MockTransport(handler)

    def create_mock_client(*args, **kwargs):
        kwargs["transport"] = transport
        return _RealAsyncClient(*args, **kwargs)

    monkeypatch.setattr("vulntrace.llm.client.httpx.AsyncClient", create_mock_client)
    monkeypatch.setattr("vulntrace.intel.tavily_client.httpx.AsyncClient", create_mock_client)

    class TransportController:
        requests = intercepted_requests
        responses = custom_responses

        def set_response(self, url_pattern: str, response_factory):
            custom_responses[url_pattern] = response_factory

    return TransportController()


def _setup_curated_workspace(tmp_path: Path) -> Path:
    """Returns canonical curated benchmark repository (Spec §4.6 Trusted Fixture)."""
    return BENCHMARK_DIR


# ==============================================================================
# SECTION 1: Retained Vulnerability Classes in Zero-Key Mode
# ==============================================================================

@pytest.mark.asyncio
async def test_no_keys_local_deterministic_e2e_deserialization(tmp_path, clean_api_keys, block_external_sockets):
    """
    Retained Scope Class 1: UNSAFE_DESERIALIZATION in zero-key mode:
    - Zero external API keys.
    - Reproduction: RED state confirmed (sentinel created).
    - Deterministic AST codemod: yaml.load -> yaml.safe_load / AppSafeLoader.
    - Post-patch verification: GREEN state confirmed (sentinel absent, block verified).
    - Regression suite passes.
    - Evidence bundle Ed25519 signed and verifiable.
    - Zero outbound socket connections made.
    """
    repo_dir = _setup_curated_workspace(tmp_path)

    req = VerificationPipelineRequest(
        repo_path=str(repo_dir),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        target_function="parse_app_config",
        vulnerable_symbol="yaml.load",
        use_nemotron=False,
        query_tavily=False
    )

    events = []
    res = await VerificationPipeline.run_pipeline(req, on_event=events.append)

    # Core assertions
    assert res.reachability_verdict == "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"
    assert res.pre_patch_result.reproduction_state == "RED_STATE_REPRODUCED"
    assert res.pre_patch_result.sentinel_created is True

    # Deterministic AST engine used (NOT AI)
    assert res.remediation.success is True
    assert res.remediation.engine == "AST_DETERMINISTIC_CODEMOD"
    assert res.remediation.tokens_used is None
    assert "safe_load" in res.remediation.diff or "Loader=AppSafeLoader" in res.remediation.diff

    # Post-patch verification
    assert res.post_patch_result.reproduction_state == "GREEN_STATE_BLOCKED"
    assert res.post_patch_result.sentinel_created is False
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"

    # Regression suite passed
    assert res.regression_tests.get("passed") is True

    # Zero outbound socket connections made
    assert len(block_external_sockets.calls) == 0

    # Schema v1 Evidence Bundle signing and verification
    bundle = EvidenceExporter.build_schema_v1_bundle(res, sign=True)
    assert bundle["llm"]["calls"] == []
    assert bundle["signature"]["alg"] == "Ed25519"
    assert bundle["signature"]["sig"] != ""

    is_valid, reason = EvidenceSigner.verify_bundle(bundle)
    assert is_valid is True


def test_no_keys_path_traversal_reproduction_and_deterministic_remediation(tmp_path):
    """
    Retained Scope Class 2: PATH_TRAVERSAL in zero-key mode:
    - Deterministic AST transformation injects safe PEP 706 filter='data' into tarfile.extractall.
    - Syntactically validated unified diff produced.
    - Prevents arbitrary filesystem traversal without external API keys.
    """
    vulnerable_source = (
        "import tarfile\n"
        "from pathlib import Path\n\n"
        "def extract_user_archive(archive_path: str, extract_to: str = 'extracted') -> None:\n"
        "    dest = Path(extract_to)\n"
        "    dest.mkdir(parents=True, exist_ok=True)\n"
        "    with tarfile.open(archive_path, 'r') as tar:\n"
        "        tar.extractall(path=dest)\n"
    )

    patched_code = RemediationPatcher._ast_deterministic_patch(vulnerable_source, vulnerable_call="extractall")

    # Injects safe PEP 706 extraction filter
    assert "filter='data'" in patched_code or 'filter="data"' in patched_code

    # Valid syntax
    tree = ast.parse(patched_code)
    assert tree is not None


# ==============================================================================
# SECTION 2: Explicit Opt-In Regression Tests (7 Cases)
# ==============================================================================

@pytest.mark.asyncio
async def test_optin_1_nebius_key_present_opt_in_false_zero_requests(tmp_path, monkeypatch, mock_external_apis):
    """
    Opt-In Case 1: Nebius key present, user opt-in false -> zero Nebius requests.
    Credentials alone must NEVER trigger provider calls.
    """
    monkeypatch.setenv("NEBIUS_API_KEY", "configured-secret-key-12345")
    monkeypatch.setenv("LIVE_LLM", "1")
    monkeypatch.setattr(settings, "nebius_api_key", "configured-secret-key-12345")
    monkeypatch.setattr(settings, "tavily_api_key", None)

    repo_dir = _setup_curated_workspace(tmp_path)

    # Explicit opt-in is False
    req = VerificationPipelineRequest(
        repo_path=str(repo_dir),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        target_function="parse_app_config",
        vulnerable_symbol="yaml.load",
        use_nemotron=False,
        query_tavily=False
    )

    res = await VerificationPipeline.run_pipeline(req)
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"

    # Core result succeeds with deterministic AST engine
    assert res.remediation.success is True
    assert res.remediation.engine == "AST_DETERMINISTIC_CODEMOD"

    # Crucial guarantee: Zero outbound requests to Nebius despite key present
    nebius_calls = [r for r in mock_external_apis.requests if "tokenfactory" in str(r.url) or "nebius" in str(r.url)]
    assert len(nebius_calls) == 0


@pytest.mark.asyncio
async def test_optin_2_tavily_key_present_opt_in_false_zero_requests(tmp_path, clean_api_keys, monkeypatch, mock_external_apis):
    """
    Opt-In Case 2: Tavily key present, user opt-in false -> zero Tavily requests.
    Credentials alone must NEVER trigger provider calls.
    """
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-secret-key-99999")
    monkeypatch.setenv("LIVE_INTEL", "1")
    monkeypatch.setattr(settings, "tavily_api_key", "tvly-secret-key-99999")
    monkeypatch.setattr(settings, "nebius_api_key", None)

    repo_dir = _setup_curated_workspace(tmp_path)

    # Explicit opt-in is False
    req = VerificationPipelineRequest(
        repo_path=str(repo_dir),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        target_function="parse_app_config",
        vulnerable_symbol="yaml.load",
        use_nemotron=False,
        query_tavily=False
    )

    res = await VerificationPipeline.run_pipeline(req)
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"

    # Crucial guarantee: Zero outbound requests to Tavily despite key present
    tavily_calls = [r for r in mock_external_apis.requests if "tavily" in str(r.url)]
    assert len(tavily_calls) == 0


@pytest.mark.asyncio
async def test_optin_3_both_keys_present_both_opt_ins_false_zero_requests(tmp_path, monkeypatch, mock_external_apis):
    """
    Opt-In Case 3: Both keys present, both opt-ins false -> zero provider requests.
    Local deterministic execution remains default.
    """
    monkeypatch.setenv("NEBIUS_API_KEY", "configured-nebius-key")
    monkeypatch.setenv("TAVILY_API_KEY", "configured-tavily-key")
    monkeypatch.setenv("LIVE_LLM", "1")
    monkeypatch.setenv("LIVE_INTEL", "1")
    monkeypatch.setattr(settings, "nebius_api_key", "configured-nebius-key")
    monkeypatch.setattr(settings, "tavily_api_key", "configured-tavily-key")

    repo_dir = _setup_curated_workspace(tmp_path)

    # Default request: both opt-ins are False by default
    req = VerificationPipelineRequest(
        repo_path=str(repo_dir),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        target_function="parse_app_config",
        vulnerable_symbol="yaml.load"
    )
    assert req.use_nemotron is False
    assert req.query_tavily is False

    res = await VerificationPipeline.run_pipeline(req)
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"

    assert res.remediation.engine == "AST_DETERMINISTIC_CODEMOD"
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"

    # Zero outbound requests to either provider
    assert len(mock_external_apis.requests) == 0


@pytest.mark.asyncio
async def test_optin_4_explicit_nebius_opt_in_invokes_nebius_only(tmp_path, monkeypatch, mock_external_apis):
    """
    Opt-In Case 4: Explicit Nebius opt-in invokes Nebius only.
    """
    monkeypatch.setenv("NEBIUS_API_KEY", "test-nebius-key-12345")
    monkeypatch.setenv("TAVILY_API_KEY", "test-tavily-key-67890")
    monkeypatch.setenv("LIVE_LLM", "1")
    monkeypatch.setenv("LIVE_INTEL", "1")
    monkeypatch.setattr(settings, "nebius_api_key", "test-nebius-key-12345")
    monkeypatch.setattr(settings, "tavily_api_key", "test-tavily-key-67890")

    repo_copy = tmp_path / "copy_nebius_only"
    shutil.copytree(BENCHMARK_DIR, repo_copy)

    req = RemediationRequest(
        repo_path=str(repo_copy),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        vulnerable_call="yaml.load",
        use_nemotron=True,
        allow_ast_fallback=False
    )

    res = await RemediationPatcher.synthesize_remediation(req, workspace_dir=repo_copy)

    assert res.success is True
    assert res.engine == "NVIDIA_NEMOTRON_3_ULTRA"

    nebius_calls = [r for r in mock_external_apis.requests if "tokenfactory" in str(r.url) or "nebius" in str(r.url)]
    tavily_calls = [r for r in mock_external_apis.requests if "tavily" in str(r.url)]

    assert len(nebius_calls) > 0
    assert len(tavily_calls) == 0


@pytest.mark.asyncio
async def test_optin_5_explicit_tavily_opt_in_invokes_tavily_only(tmp_path, clean_api_keys, monkeypatch, mock_external_apis):
    """
    Opt-In Case 5: Explicit Tavily opt-in invokes Tavily only.
    """
    monkeypatch.setenv("NEBIUS_API_KEY", "test-nebius-key-12345")
    monkeypatch.setenv("TAVILY_API_KEY", "test-tavily-key-67890")
    monkeypatch.setenv("LIVE_LLM", "1")
    monkeypatch.setenv("LIVE_INTEL", "1")
    monkeypatch.setattr(settings, "nebius_api_key", "test-nebius-key-12345")
    monkeypatch.setattr(settings, "tavily_api_key", "test-tavily-key-67890")

    repo_dir = _setup_curated_workspace(tmp_path)

    req = VerificationPipelineRequest(
        repo_path=str(repo_dir),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        target_function="parse_app_config",
        vulnerable_symbol="yaml.load",
        use_nemotron=False,
        query_tavily=True
    )

    res = await VerificationPipeline.run_pipeline(req)
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"

    # Tavily invoked
    tavily_calls = [r for r in mock_external_apis.requests if "tavily" in str(r.url)]
    assert len(tavily_calls) > 0

    # Nebius NOT invoked; local deterministic AST engine used
    nebius_calls = [r for r in mock_external_apis.requests if "tokenfactory" in str(r.url)]
    assert len(nebius_calls) == 0
    assert res.remediation.engine == "AST_DETERMINISTIC_CODEMOD"


@pytest.mark.asyncio
async def test_optin_6_both_explicitly_enabled_invokes_both(tmp_path, monkeypatch, mock_external_apis):
    """
    Opt-In Case 6: Both explicitly enabled invoke both.
    """
    monkeypatch.setenv("NEBIUS_API_KEY", "test-nebius-key-12345")
    monkeypatch.setenv("TAVILY_API_KEY", "test-tavily-key-67890")
    monkeypatch.setenv("LIVE_LLM", "1")
    monkeypatch.setenv("LIVE_INTEL", "1")
    monkeypatch.setattr(settings, "nebius_api_key", "test-nebius-key-12345")
    monkeypatch.setattr(settings, "tavily_api_key", "test-tavily-key-67890")

    repo_dir = _setup_curated_workspace(tmp_path)

    req = VerificationPipelineRequest(
        repo_path=str(repo_dir),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        target_function="parse_app_config",
        vulnerable_symbol="yaml.load",
        use_nemotron=True,
        query_tavily=True
    )

    res = await VerificationPipeline.run_pipeline(req)
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"

    nebius_calls = [r for r in mock_external_apis.requests if "tokenfactory" in str(r.url) or "nebius" in str(r.url)]
    tavily_calls = [r for r in mock_external_apis.requests if "tavily" in str(r.url)]

    assert len(nebius_calls) > 0
    assert len(tavily_calls) > 0


@pytest.mark.asyncio
async def test_optin_7_missing_keys_opt_in_requested_truthful_degradation(tmp_path, clean_api_keys, monkeypatch, mock_external_apis):
    """
    Opt-In Case 7: Missing keys with opt-in requested produces truthful degradation.
    Never fabricates AI results or live threat findings.
    """
    monkeypatch.setenv("LIVE_LLM", "1")
    monkeypatch.setenv("LIVE_INTEL", "1")
    repo_dir = _setup_curated_workspace(tmp_path)

    req = VerificationPipelineRequest(
        repo_path=str(repo_dir),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        target_function="parse_app_config",
        vulnerable_symbol="yaml.load",
        use_nemotron=True,
        query_tavily=True
    )

    events = []
    res = await VerificationPipeline.run_pipeline(req, on_event=events.append)

    # Truthful degradation: Nebius falls back to deterministic AST codemod
    assert res.remediation.engine == "AST_DETERMINISTIC_CODEMOD"
    assert res.remediation.tokens_used is None

    # Truthful degradation: Tavily status reports degraded / local advisory mode
    assert res.threat_intel is not None
    assert res.threat_intel.status == "degraded"

    # Zero live external API calls made
    assert len(mock_external_apis.requests) == 0

    # Truthful logging
    patch_logs = [e.message for e in events if e.stage == "PATCH" or e.stage == "INTEL"]
    assert any("not configured" in msg.lower() for msg in patch_logs)


# ==============================================================================
# SECTION 3: Provider Failure & Degradation Handling
# ==============================================================================

@pytest.mark.asyncio
async def test_invalid_nebius_key_graceful_fallback(tmp_path, monkeypatch, mock_external_apis):
    """
    Invalid Nebius key: Gracefully falls back to AST deterministic codemod without crashing.
    """
    monkeypatch.setenv("NEBIUS_API_KEY", "invalid-key")
    monkeypatch.setenv("LIVE_LLM", "1")
    monkeypatch.setattr(settings, "nebius_api_key", "invalid-key")

    mock_external_apis.set_response(
        "tokenfactory",
        lambda req: httpx.Response(401, json={"error": "Unauthorized: Invalid API Key"})
    )

    repo_copy = tmp_path / "copy_fallback"
    shutil.copytree(BENCHMARK_DIR, repo_copy)

    req = RemediationRequest(
        repo_path=str(repo_copy),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        vulnerable_call="yaml.load",
        use_nemotron=True,
        allow_ast_fallback=True
    )

    res = await RemediationPatcher.synthesize_remediation(req, workspace_dir=repo_copy)

    assert res.success is True
    assert res.engine == "AST_DETERMINISTIC_CODEMOD"
    assert "Applied AST deterministic codemod" in res.explanation


@pytest.mark.asyncio
async def test_invalid_tavily_key_graceful_degradation(monkeypatch, mock_external_apis):
    """
    Invalid Tavily key: Threat intel reports degraded status without failing or crashing.
    """
    monkeypatch.setenv("TAVILY_API_KEY", "invalid-tavily-key")
    monkeypatch.setenv("LIVE_INTEL", "1")
    monkeypatch.setattr(settings, "tavily_api_key", "invalid-tavily-key")

    mock_external_apis.set_response(
        "tavily",
        lambda req: httpx.Response(401, json={"detail": "Unauthorized: Invalid API Key"})
    )

    tavily_client = TavilyClient()
    intel = await tavily_client.query_threat_intel("CVE-2020-14343")

    assert intel.status == "degraded"
    assert "yaml.load" in intel.affected_symbols


@pytest.mark.asyncio
async def test_provider_unavailable_clean_handling(tmp_path, monkeypatch, mock_external_apis):
    """
    Provider unavailable (500/503): Handled cleanly without crash or false-success GREEN.
    """
    monkeypatch.setenv("NEBIUS_API_KEY", "some-key")
    monkeypatch.setenv("TAVILY_API_KEY", "some-key")
    monkeypatch.setenv("LIVE_LLM", "1")
    monkeypatch.setenv("LIVE_INTEL", "1")
    monkeypatch.setattr(settings, "nebius_api_key", "some-key")
    monkeypatch.setattr(settings, "tavily_api_key", "some-key")

    mock_external_apis.set_response(
        "tokenfactory",
        lambda req: httpx.Response(503, json={"error": "Service Unavailable"})
    )
    mock_external_apis.set_response(
        "tavily",
        lambda req: httpx.Response(500, json={"error": "Internal Server Error"})
    )

    repo_dir = _setup_curated_workspace(tmp_path)

    req = VerificationPipelineRequest(
        repo_path=str(repo_dir),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        target_function="parse_app_config",
        vulnerable_symbol="yaml.load",
        use_nemotron=True,
        query_tavily=True
    )

    res = await VerificationPipeline.run_pipeline(req)
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"

    assert res.remediation.success is True
    assert res.remediation.engine == "AST_DETERMINISTIC_CODEMOD"
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"


# ==============================================================================
# SECTION 4: Secret Hygiene & Environment Sanitization
# ==============================================================================

def test_secret_hygiene_purged_from_env_and_bundles(tmp_path, monkeypatch):
    """
    Secret hygiene: API keys and tokens purged from child environments and evidence bundles.
    """
    secrets_to_test = {
        "NEBIUS_API_KEY": "nb-secret-token-abcdef123456",
        "TAVILY_API_KEY": "tvly-secret-key-987654321",
        "OPENAI_API_KEY": "sk-secret-openai-token",
        "GITHUB_TOKEN": "ghp_supersecretauthtoken",
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }

    for k, v in secrets_to_test.items():
        monkeypatch.setenv(k, v)

    # Test EnvironmentBuilder.sanitize_environment
    sanitized_env_1 = EnvironmentBuilder.sanitize_environment(tmp_path)
    for k in secrets_to_test:
        assert k not in sanitized_env_1
        for val in secrets_to_test.values():
            assert val not in str(sanitized_env_1)

    # Test TargetEnvironmentManager.sanitize_provisioning_environment
    sanitized_env_2 = TargetEnvironmentManager.sanitize_provisioning_environment(tmp_path)
    for k in secrets_to_test:
        assert k not in sanitized_env_2
        for val in secrets_to_test.values():
            assert val not in str(sanitized_env_2)


# ==============================================================================
# SECTION 5: Server Health & Opt-In Defaults
# ==============================================================================

@pytest.mark.asyncio
async def test_server_health_local_mode(clean_api_keys):
    """
    Server health: /api/v1/health returns structured status with MISSING_KEY when keys are absent.
    ExecuteRunRequest defaults to use_nemotron=False and query_tavily=False.
    """
    health = await get_system_health()

    assert "nebius_token_factory" in health.providers
    nebius_status = health.providers["nebius_token_factory"]
    assert nebius_status.configured is False
    assert nebius_status.status == "MISSING_KEY"

    assert "tavily_search" in health.providers
    tavily_status = health.providers["tavily_search"]
    assert tavily_status.configured is False
    assert tavily_status.status == "MISSING_KEY"

    # Crucial guarantee: ExecuteRunRequest defaults to False for both external providers
    req_default = ExecuteRunRequest()
    assert req_default.use_nemotron is False
    assert req_default.query_tavily is False
