"""
Unit tests for VulnTrace Benchmark Protocol, 3-Repeat Evaluation Gate,
Curated Registry Enforcement for bench/, and CI Drift Detection (Technical Spec §3.2, §4.6, §5.1, §5.2).
"""

from vulntrace.core.backend import (
    TrustedFixtureRegistry,
    is_curated_fixture,
    PROJECT_ROOT,
)


# ---------------------------------------------------------------------------
# Section 1: Three-Repeat Protocol & Aggregation Gate Tests
# ---------------------------------------------------------------------------

def test_evaluate_three_repeat_empty():
    """Zero observed repeats must fail the 3-repeat gate, emit UNVERIFIABLE, and never produce GREEN_STATE_VERIFIED."""
    from bench.run import evaluate_three_repeat_verdict

    verdict, meta = evaluate_three_repeat_verdict([])
    assert verdict == "UNVERIFIABLE"
    assert meta["repeat_status"] == "INCOMPLETE"
    assert meta["repeat_count"] == 0
    assert "0 of 3" in meta["notes"] or "Incomplete" in meta["notes"]
    assert verdict != "GREEN_STATE_VERIFIED"


def test_evaluate_three_repeat_one_repeat():
    """A single repeat (legacy single-pass) cannot satisfy the three-repeat gate and emits UNVERIFIABLE."""
    from bench.run import evaluate_three_repeat_verdict

    single_run = [
        {
            "repeat_index": 1,
            "pre_patch_reproduced": True,
            "post_patch_blocked": True,
            "positive_control_passed": True,
            "regression_passed": True,
            "reproduction_state": "GREEN_STATE_BLOCKED",
            "exit_code": 42,
        }
    ]
    verdict, meta = evaluate_three_repeat_verdict(single_run)
    assert verdict == "UNVERIFIABLE"
    assert meta["repeat_status"] == "INCOMPLETE"
    assert meta["repeat_count"] == 1
    assert "1 of 3" in meta["notes"]
    assert verdict != "GREEN_STATE_VERIFIED"


def test_evaluate_three_repeat_two_repeats():
    """Two repeats (incomplete execution) cannot satisfy the three-repeat gate and emit UNVERIFIABLE."""
    from bench.run import evaluate_three_repeat_verdict

    two_runs = [
        {
            "repeat_index": 1,
            "pre_patch_reproduced": True,
            "post_patch_blocked": True,
            "positive_control_passed": True,
            "regression_passed": True,
            "reproduction_state": "GREEN_STATE_BLOCKED",
            "exit_code": 42,
        },
        {
            "repeat_index": 2,
            "pre_patch_reproduced": True,
            "post_patch_blocked": True,
            "positive_control_passed": True,
            "regression_passed": True,
            "reproduction_state": "GREEN_STATE_BLOCKED",
            "exit_code": 42,
        },
    ]
    verdict, meta = evaluate_three_repeat_verdict(two_runs)
    assert verdict == "UNVERIFIABLE"
    assert meta["repeat_status"] == "INCOMPLETE"
    assert meta["repeat_count"] == 2
    assert "2 of 3" in meta["notes"]
    assert verdict != "GREEN_STATE_VERIFIED"


def test_evaluate_three_repeat_unanimous_green():
    """Three unanimous successful runs produce GREEN_STATE_VERIFIED with UNANIMOUS_PASS status."""
    from bench.run import evaluate_three_repeat_verdict

    unanimous_runs = [
        {
            "repeat_index": i,
            "pre_patch_reproduced": True,
            "post_patch_blocked": True,
            "positive_control_passed": True,
            "regression_passed": True,
            "reproduction_state": "GREEN_STATE_BLOCKED",
            "exit_code": 42,
        }
        for i in (1, 2, 3)
    ]
    verdict, meta = evaluate_three_repeat_verdict(unanimous_runs)
    assert verdict == "GREEN_STATE_VERIFIED"
    assert meta["repeat_status"] == "UNANIMOUS_PASS"
    assert meta["is_unanimous"] is True
    assert "3/3" in meta["notes"]


# ---------------------------------------------------------------------------
# Section 1.1: Four Pre-Patch Reproduction Scenarios (0/3, 1/3, 2/3, 3/3)
# ---------------------------------------------------------------------------

def test_pre_patch_scenario_0_of_3_observations():
    """Scenario 1: 0/3 observations (unanimous non-reproduction) emits canonical RED_NOT_REPRODUCED with UNANIMOUS_FAIL."""
    from bench.run import evaluate_three_repeat_verdict

    zero_of_three_runs = [
        {
            "repeat_index": i,
            "pre_patch_reproduced": False,
            "post_patch_blocked": False,
            "positive_control_passed": False,
            "regression_passed": True,
            "reproduction_state": "RED_NOT_REPRODUCED",
            "exit_code": 10,
        }
        for i in (1, 2, 3)
    ]
    verdict, meta = evaluate_three_repeat_verdict(zero_of_three_runs)
    assert verdict == "RED_NOT_REPRODUCED"
    assert meta["repeat_status"] == "UNANIMOUS_FAIL"
    assert meta["failure_mode"] == "PRE_PATCH_NOT_REPRODUCED"
    assert meta["is_unanimous"] is True
    assert meta["repeat_count"] == 3
    assert meta["green_count"] == 0
    assert "unanimous non-reproduction" in meta["notes"]
    assert verdict != "GREEN_STATE_VERIFIED"


def test_pre_patch_scenario_1_of_3_observations():
    """Scenario 2: 1/3 observations (divergent / flaky) emits UNVERIFIABLE with DIVERGENT status."""
    from bench.run import evaluate_three_repeat_verdict

    one_of_three_runs = [
        {
            "repeat_index": 1,
            "pre_patch_reproduced": True,
            "post_patch_blocked": True,
            "positive_control_passed": True,
            "regression_passed": True,
            "reproduction_state": "GREEN_STATE_BLOCKED",
            "exit_code": 42,
        },
        {
            "repeat_index": 2,
            "pre_patch_reproduced": False,
            "post_patch_blocked": False,
            "positive_control_passed": False,
            "regression_passed": True,
            "reproduction_state": "RED_NOT_REPRODUCED",
            "exit_code": 10,
        },
        {
            "repeat_index": 3,
            "pre_patch_reproduced": False,
            "post_patch_blocked": False,
            "positive_control_passed": False,
            "regression_passed": True,
            "reproduction_state": "RED_NOT_REPRODUCED",
            "exit_code": 10,
        },
    ]
    verdict, meta = evaluate_three_repeat_verdict(one_of_three_runs)
    assert verdict == "UNVERIFIABLE"
    assert meta["repeat_status"] == "DIVERGENT"
    assert meta["failure_mode"] == "FLAKY_PRE_PATCH"
    assert meta["is_unanimous"] is False
    assert meta["repeat_count"] == 3
    assert "Flakiness/divergence detected" in meta["notes"]
    assert "1/3" in meta["notes"]
    assert verdict != "RED_NOT_REPRODUCED"
    assert verdict != "GREEN_STATE_VERIFIED"


def test_pre_patch_scenario_2_of_3_observations():
    """Scenario 3: 2/3 observations (divergent / flaky) emits UNVERIFIABLE with DIVERGENT status."""
    from bench.run import evaluate_three_repeat_verdict

    two_of_three_runs = [
        {
            "repeat_index": 1,
            "pre_patch_reproduced": True,
            "post_patch_blocked": True,
            "positive_control_passed": True,
            "regression_passed": True,
            "reproduction_state": "GREEN_STATE_BLOCKED",
            "exit_code": 42,
        },
        {
            "repeat_index": 2,
            "pre_patch_reproduced": False,
            "post_patch_blocked": False,
            "positive_control_passed": False,
            "regression_passed": True,
            "reproduction_state": "RED_NOT_REPRODUCED",
            "exit_code": 10,
        },
        {
            "repeat_index": 3,
            "pre_patch_reproduced": True,
            "post_patch_blocked": True,
            "positive_control_passed": True,
            "regression_passed": True,
            "reproduction_state": "GREEN_STATE_BLOCKED",
            "exit_code": 42,
        },
    ]
    verdict, meta = evaluate_three_repeat_verdict(two_of_three_runs)
    assert verdict == "UNVERIFIABLE"
    assert meta["repeat_status"] == "DIVERGENT"
    assert meta["failure_mode"] == "FLAKY_PRE_PATCH"
    assert meta["is_unanimous"] is False
    assert meta["repeat_count"] == 3
    assert "Flakiness/divergence detected" in meta["notes"]
    assert "2/3" in meta["notes"]
    assert verdict != "RED_NOT_REPRODUCED"
    assert verdict != "GREEN_STATE_VERIFIED"


def test_pre_patch_scenario_3_of_3_observations():
    """Scenario 4: 3/3 observations (unanimous pass) emits GREEN_STATE_VERIFIED with UNANIMOUS_PASS status."""
    from bench.run import evaluate_three_repeat_verdict

    three_of_three_runs = [
        {
            "repeat_index": i,
            "pre_patch_reproduced": True,
            "post_patch_blocked": True,
            "positive_control_passed": True,
            "regression_passed": True,
            "reproduction_state": "GREEN_STATE_BLOCKED",
            "exit_code": 42,
        }
        for i in (1, 2, 3)
    ]
    verdict, meta = evaluate_three_repeat_verdict(three_of_three_runs)
    assert verdict == "GREEN_STATE_VERIFIED"
    assert meta["repeat_status"] == "UNANIMOUS_PASS"
    assert meta["failure_mode"] is None
    assert meta["is_unanimous"] is True
    assert meta["repeat_count"] == 3
    assert meta["green_count"] == 3
    assert "3/3" in meta["notes"]


def test_evaluate_three_repeat_timeout_failure():
    """A run with a timeout in one repeat is classified as UNEXPECTED_FAILURE with TIMED_OUT status."""
    from bench.run import evaluate_three_repeat_verdict

    timed_out_runs = [
        {
            "repeat_index": 1,
            "pre_patch_reproduced": True,
            "post_patch_blocked": True,
            "positive_control_passed": True,
            "regression_passed": True,
            "reproduction_state": "GREEN_STATE_BLOCKED",
            "exit_code": 42,
        },
        {
            "repeat_index": 2,
            "pre_patch_reproduced": True,
            "post_patch_blocked": False,
            "positive_control_passed": False,
            "regression_passed": False,
            "reproduction_state": "TIMEOUT",
            "exit_code": -9,
            "error": "Command exceeded wall-clock timeout watchdog (30s)",
        },
        {
            "repeat_index": 3,
            "pre_patch_reproduced": True,
            "post_patch_blocked": True,
            "positive_control_passed": True,
            "regression_passed": True,
            "reproduction_state": "GREEN_STATE_BLOCKED",
            "exit_code": 42,
        },
    ]
    verdict, meta = evaluate_three_repeat_verdict(timed_out_runs)
    assert verdict == "UNEXPECTED_FAILURE"
    assert meta["repeat_status"] == "TIMED_OUT"
    assert "timeout" in meta["notes"].lower()
    assert verdict != "GREEN_STATE_VERIFIED"


def test_evaluate_three_repeat_regression_failure():
    """A run where candidate patch breaks regression tests across all 3 repeats emits REGRESSION_FAILURE with UNANIMOUS_FAIL status."""
    from bench.run import evaluate_three_repeat_verdict

    regression_failed_runs = [
        {
            "repeat_index": i,
            "pre_patch_reproduced": True,
            "post_patch_blocked": True,
            "positive_control_passed": True,
            "regression_passed": False,
            "reproduction_state": "REGRESSION_FAILURE",
            "exit_code": 42,
        }
        for i in (1, 2, 3)
    ]
    verdict, meta = evaluate_three_repeat_verdict(regression_failed_runs)
    assert verdict == "REGRESSION_FAILURE"
    assert meta["repeat_status"] == "UNANIMOUS_FAIL"
    assert meta["failure_mode"] == "REGRESSION_FAILURE"
    assert meta["is_unanimous"] is True
    assert verdict != "GREEN_STATE_VERIFIED"


def test_evaluate_three_repeat_unanimous_non_reproduction():
    """A run where all 3 repeats fail to observe pre-patch vulnerability emits RED_NOT_REPRODUCED with UNANIMOUS_FAIL status."""
    from bench.run import evaluate_three_repeat_verdict

    unobserved_runs = [
        {
            "repeat_index": i,
            "pre_patch_reproduced": False,
            "post_patch_blocked": False,
            "positive_control_passed": False,
            "regression_passed": True,
            "reproduction_state": "RED_NOT_REPRODUCED",
            "exit_code": 10,
        }
        for i in (1, 2, 3)
    ]
    verdict, meta = evaluate_three_repeat_verdict(unobserved_runs)
    assert verdict == "RED_NOT_REPRODUCED"
    assert meta["repeat_status"] == "UNANIMOUS_FAIL"
    assert meta["failure_mode"] == "PRE_PATCH_NOT_REPRODUCED"
    assert meta["is_unanimous"] is True
    assert "unanimous non-reproduction" in meta["notes"]
    assert verdict != "GREEN_STATE_VERIFIED"


def test_evaluate_three_repeat_patch_persists_unanimous_and_divergent():
    """Vulnerability persisting post-patch emits RED_STATE_PERSISTS with UNANIMOUS_FAIL or DIVERGENT status."""
    from bench.run import evaluate_three_repeat_verdict

    # Unanimous persistence
    persisted_unanimous = [
        {
            "repeat_index": i,
            "pre_patch_reproduced": True,
            "post_patch_blocked": False,
            "positive_control_passed": True,
            "regression_passed": True,
            "reproduction_state": "RED_STATE_PERSISTS",
            "exit_code": 0,
        }
        for i in (1, 2, 3)
    ]
    verdict, meta = evaluate_three_repeat_verdict(persisted_unanimous)
    assert verdict == "RED_STATE_PERSISTS"
    assert meta["repeat_status"] == "UNANIMOUS_FAIL"
    assert meta["failure_mode"] == "RED_STATE_PERSISTS"
    assert meta["is_unanimous"] is True

    # Divergent persistence (1 failed, 2 passed)
    persisted_divergent = [
        {
            "repeat_index": 1,
            "pre_patch_reproduced": True,
            "post_patch_blocked": False,
            "positive_control_passed": True,
            "regression_passed": True,
            "reproduction_state": "RED_STATE_PERSISTS",
            "exit_code": 0,
        },
        {
            "repeat_index": 2,
            "pre_patch_reproduced": True,
            "post_patch_blocked": True,
            "positive_control_passed": True,
            "regression_passed": True,
            "reproduction_state": "GREEN_STATE_BLOCKED",
            "exit_code": 42,
        },
        {
            "repeat_index": 3,
            "pre_patch_reproduced": True,
            "post_patch_blocked": True,
            "positive_control_passed": True,
            "regression_passed": True,
            "reproduction_state": "GREEN_STATE_BLOCKED",
            "exit_code": 42,
        },
    ]
    verdict, meta = evaluate_three_repeat_verdict(persisted_divergent)
    assert verdict == "RED_STATE_PERSISTS"
    assert meta["repeat_status"] == "DIVERGENT"
    assert meta["failure_mode"] == "RED_STATE_PERSISTS"
    assert meta["is_unanimous"] is False


def test_evaluate_three_repeat_verification_rejected():
    """Evidence tampering or canary mismatch emits VERIFICATION_REJECTED with UNANIMOUS_FAIL or DIVERGENT status."""
    from bench.run import evaluate_three_repeat_verdict

    tampered_runs = [
        {
            "repeat_index": i,
            "pre_patch_reproduced": True,
            "post_patch_blocked": True,
            "positive_control_passed": True,
            "regression_passed": True,
            "reproduction_state": "VERIFICATION_REJECTED",
            "exit_code": 42,
        }
        for i in (1, 2, 3)
    ]
    verdict, meta = evaluate_three_repeat_verdict(tampered_runs)
    assert verdict == "VERIFICATION_REJECTED"
    assert meta["repeat_status"] == "UNANIMOUS_FAIL"
    assert meta["failure_mode"] == "VERIFICATION_REJECTED"
    assert meta["is_unanimous"] is True


def test_protocol_contract_validation_and_invariants():
    """Validates the contract rules: canonical verdicts, supported repeat statuses, and rejection of invalid combinations."""
    import pytest
    from bench.run import (
        CANONICAL_VERDICTS,
        SUPPORTED_REPEAT_STATUSES,
        validate_verdict_and_repeat_status,
    )

    # Exactly 11 canonical verdicts
    assert len(CANONICAL_VERDICTS) == 11
    # Exactly 5 supported repeat statuses
    assert len(SUPPORTED_REPEAT_STATUSES) == 5
    assert SUPPORTED_REPEAT_STATUSES == {"INCOMPLETE", "TIMED_OUT", "UNANIMOUS_PASS", "UNANIMOUS_FAIL", "DIVERGENT"}

    # Valid combinations must not raise
    validate_verdict_and_repeat_status("GREEN_STATE_VERIFIED", "UNANIMOUS_PASS")
    validate_verdict_and_repeat_status("UNVERIFIABLE", "INCOMPLETE")
    validate_verdict_and_repeat_status("UNVERIFIABLE", "DIVERGENT")
    validate_verdict_and_repeat_status("UNEXPECTED_FAILURE", "TIMED_OUT")
    validate_verdict_and_repeat_status("RED_NOT_REPRODUCED", "UNANIMOUS_FAIL")
    validate_verdict_and_repeat_status("RED_STATE_PERSISTS", "UNANIMOUS_FAIL")
    validate_verdict_and_repeat_status("RED_STATE_PERSISTS", "DIVERGENT")
    validate_verdict_and_repeat_status("REGRESSION_FAILURE", "UNANIMOUS_FAIL")
    validate_verdict_and_repeat_status("REGRESSION_FAILURE", "DIVERGENT")
    validate_verdict_and_repeat_status("VERIFICATION_REJECTED", "UNANIMOUS_FAIL")
    validate_verdict_and_repeat_status("VERIFICATION_REJECTED", "DIVERGENT")

    # Invalid verdict rejected
    with pytest.raises(ValueError, match="not in CANONICAL_VERDICTS"):
        validate_verdict_and_repeat_status("INCONCLUSIVE", "DIVERGENT")

    with pytest.raises(ValueError, match="not in CANONICAL_VERDICTS"):
        validate_verdict_and_repeat_status("UNKNOWN_VERDICT", "UNANIMOUS_PASS")

    # Invalid repeat status rejected (e.g. using a canonical verdict as repeat_status)
    with pytest.raises(ValueError, match="not in SUPPORTED_REPEAT_STATUSES"):
        validate_verdict_and_repeat_status("VERIFICATION_REJECTED", "VERIFICATION_REJECTED")

    with pytest.raises(ValueError, match="not in SUPPORTED_REPEAT_STATUSES"):
        validate_verdict_and_repeat_status("RED_STATE_PERSISTS", "RED_STATE_PERSISTS")

    with pytest.raises(ValueError, match="not in SUPPORTED_REPEAT_STATUSES"):
        validate_verdict_and_repeat_status("REGRESSION_FAILURE", "REGRESSION_FAILED")

    # Invalid combinations rejected by invariant rules
    with pytest.raises(ValueError, match="GREEN_STATE_VERIFIED cannot have repeat_status 'DIVERGENT'"):
        validate_verdict_and_repeat_status("GREEN_STATE_VERIFIED", "DIVERGENT")

    with pytest.raises(ValueError, match="UNANIMOUS_PASS cannot produce verdict 'RED_NOT_REPRODUCED'"):
        validate_verdict_and_repeat_status("RED_NOT_REPRODUCED", "UNANIMOUS_PASS")

    with pytest.raises(ValueError, match="INCOMPLETE repeat_status must yield UNVERIFIABLE"):
        validate_verdict_and_repeat_status("GREEN_STATE_VERIFIED", "INCOMPLETE")

    with pytest.raises(ValueError, match="TIMED_OUT repeat_status must yield UNEXPECTED_FAILURE"):
        validate_verdict_and_repeat_status("RED_NOT_REPRODUCED", "TIMED_OUT")

    with pytest.raises(ValueError, match="RED_NOT_REPRODUCED requires behavior not observed"):
        validate_verdict_and_repeat_status("RED_NOT_REPRODUCED", "DIVERGENT")


# ---------------------------------------------------------------------------
# Section 2: Legacy Single-Pass Migration & Gate Ineligibility
# ---------------------------------------------------------------------------

def test_legacy_single_pass_record_gate_ineligibility():
    """Legacy single-pass records must have three_repeat_verified=False and cannot satisfy the 3-repeat gate."""
    from bench.run import validate_record_protocol_conformance

    legacy_record = {
        "id": "deep_callchain",
        "name": "Deep Call Chain",
        "behavioral_verdict": "GREEN_STATE_VERIFIED",
        "repeat_count": 1,
        "protocol_conformance": "LEGACY_SINGLE_PASS",
        "three_repeat_verified": False,
        "observed_repeat_results": [
            {
                "repeat_index": 1,
                "reproduction_state": "GREEN_STATE_BLOCKED",
                "exit_code": 42,
            }
        ],
    }
    is_valid_3x, reason = validate_record_protocol_conformance(legacy_record)
    assert is_valid_3x is False
    assert "LEGACY_SINGLE_PASS" in reason


# ---------------------------------------------------------------------------
# Section 3: Curated Registry & bench/ Path Refusal Tests
# ---------------------------------------------------------------------------

def test_canonical_fixtures_remain_exact_twelve():
    """TrustedFixtureRegistry retains exactly the 12 authorized canonical fixtures."""
    canonical = TrustedFixtureRegistry.get_canonical_fixtures()
    assert len(canonical) == 12
    for p in canonical:
        assert p.exists()
        assert is_curated_fixture(p) is True


def test_bench_directory_cannot_obtain_tier0():
    """The bench/ directory itself must be refused by is_curated_fixture()."""
    bench_dir = PROJECT_ROOT / "bench"
    assert is_curated_fixture(bench_dir) is False


def test_bench_subpaths_cannot_obtain_tier0(tmp_path):
    """Files or subdirectories within bench/ cannot obtain Tier 0 trust."""
    bench_dir = PROJECT_ROOT / "bench"
    subpath = bench_dir / "scenarios" / "test_case"
    assert is_curated_fixture(subpath) is False

    run_py = bench_dir / "run.py"
    assert is_curated_fixture(run_py) is False


def test_bench_path_normalization_refusal():
    """Path normalization variants (slashes, relative, dot-slash) cannot bypass bench/ refusal."""
    bench_variants = [
        str(PROJECT_ROOT / "bench"),
        str(PROJECT_ROOT / "bench") + "/",
        str(PROJECT_ROOT / "bench") + "\\",
        str(PROJECT_ROOT / "bench" / "." / "scenarios"),
        "bench",
        "bench/",
        "./bench",
    ]
    for variant in bench_variants:
        assert is_curated_fixture(variant) is False


def test_dynamic_registration_rejects_bench_directory():
    """Dynamic registration must refuse bench/ as a broad in-project directory."""
    bench_dir = PROJECT_ROOT / "bench"
    if bench_dir.exists():
        TrustedFixtureRegistry.register_trusted_fixture(bench_dir)
        try:
            assert bench_dir.resolve() not in TrustedFixtureRegistry.get_all_approved_roots()
            assert is_curated_fixture(bench_dir) is False
        finally:
            TrustedFixtureRegistry.unregister_trusted_fixture(bench_dir)


# ---------------------------------------------------------------------------
# Section 4: bench/HELDOUT.md Verification
# ---------------------------------------------------------------------------

def test_heldout_file_metadata_and_oracles():
    """Verifies that bench/HELDOUT.md documents all 3 verified candidates with exact oracle specifications."""
    heldout_file = PROJECT_ROOT / "bench" / "HELDOUT.md"
    assert heldout_file.exists(), "bench/HELDOUT.md must exist"
    content = heldout_file.read_text(encoding="utf-8")

    # Candidate 1: aiohttp
    assert "aio-libs/aiohttp" in content
    assert "CVE-2024-23334" in content
    assert "33ccdfb0a12690af5bb49bda2319ec0907fa7827" in content
    assert "1c335944d6a8b1298baf179b7c0b3069f10c514b" in content
    assert "raw-socket" in content or "raw socket" in content or "open_connection" in content

    # Candidate 2: PyYAML
    assert "yaml/pyyaml" in content
    assert "CVE-2020-1747" in content
    assert "2f463cf5b0e98a52bc20e348d1e69761bf263b86" in content
    assert "6f675f711a807af61233355c6d127a3a2e412dbe" in content
    assert "python/object/new" in content

    # Candidate 3: Tornado
    assert "tornadoweb/tornado" in content
    assert "CVE-2026-103263" in content
    assert "03945136ea9746eccf61caf88edae39642e59c93" in content
    assert "437ab5f76565403b3403438d2e555d11f8128d32" in content
    assert "symlink" in content.lower()

    # Segregation declaration
    assert "segregated" in content.lower()
