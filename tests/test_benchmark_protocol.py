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


# ---------------------------------------------------------------------------
# Section 5: Benchmark Generation, Drift Detection & Fallback Insertion Tests
# ---------------------------------------------------------------------------

def test_generate_markdown_table_summary_and_labels():
    """Validates that generate_markdown_table produces the accurate summary and historical label notes."""
    from bench.run import (
        load_raw_observations,
        derive_benchmark_results,
        generate_markdown_table,
    )

    raw = load_raw_observations()
    assert len(raw) == 10
    results = derive_benchmark_results(raw)
    assert len(results) == 10

    table_md1 = generate_markdown_table(results)
    table_md2 = generate_markdown_table(results)

    # 1. Deterministic generation
    assert table_md1 == table_md2

    # 2. Summary string reports 4 real-world revision evaluations across 3 distinct repositories
    assert "4 Real-World Revision Evaluations across 3 Distinct Repositories, 6 Curated Synthetic Fixtures" in table_md1

    # 3. Discloses 0 of 10 three-repeat verified
    assert "- **Three-Repeat Protocol Verified Status:** `0 of 10 cases`" in table_md1

    # 4. Historical label note present and explains non-universal mappings
    assert "Historical Observation Labels & Protocol Conformance:" in table_md1
    assert "UNREACHABLE_FALSE_POSITIVE" in table_md1
    assert "NO_STATIC_PATH_FOUND" in table_md1
    assert "NO_VULNERABILITIES_FOUND" in table_md1
    assert "NOT_VULNERABLE_ALREADY_SAFE" in table_md1
    assert "INCONCLUSIVE" in table_md1
    assert "RED_NOT_REPRODUCED" in table_md1
    assert "VERIFICATION_REJECTED" in table_md1
    assert "LOCAL_SUBPROCESS_FALLBACK" in table_md1
    assert "unreachable_dead_code" in table_md1
    assert "Cookiecutter" in table_md1
    assert "environment-policy violation" in table_md1
    assert "contradictory regression telemetry" in table_md1
    assert "exactly 5 of 10 historical records carry the legacy single-pass `GREEN_STATE_VERIFIED` label" in table_md1
    assert "--unsafe-local" in table_md1
    assert "unverified from raw logs" in table_md1


def test_ci_drift_zero_on_current_readme():
    """Validates that check_ci_drift returns 0 drift on the repository's README.md."""
    from bench.run import check_ci_drift, README_PATH

    is_clean, msg = check_ci_drift(README_PATH)
    assert is_clean is True, f"Expected 0 drift, got error: {msg}"
    assert "0 drift" in msg


def test_update_readme_fallback_insertion_and_idempotence(tmp_path):
    """
    Validates fallback insertion before Section 11 when markers are absent,
    and ensures repeated generation is idempotent with zero duplicate sections.
    """
    from bench.run import update_readme_table, TABLE_START_MARKER, TABLE_END_MARKER

    fake_readme = tmp_path / "README.md"
    initial_content = (
        "# VulnTrace\n\n"
        "## 9. Clean-Room Setup Instructions\n\n"
        "Setup details...\n\n"
        "---\n\n"
        "## 11. Disclosures & Formal Limitations\n\n"
        "1. Isolation Tiers...\n\n"
        "---\n\n"
        "## 12. Open-Source License\n"
    )
    fake_readme.write_text(initial_content, encoding="utf-8")

    # 1. First run: markers absent -> inserts Section 10 before Section 11
    success = update_readme_table(fake_readme)
    assert success is True

    content_after_first = fake_readme.read_text(encoding="utf-8")
    assert TABLE_START_MARKER in content_after_first
    assert TABLE_END_MARKER in content_after_first
    assert "## 10. VulnTrace-Bench Evaluation Results" in content_after_first

    # Ensure Section 10 is placed before Section 11
    idx_s10 = content_after_first.find("## 10. VulnTrace-Bench Evaluation Results")
    idx_s11 = content_after_first.find("## 11. Disclosures & Formal Limitations")
    assert idx_s10 != -1 and idx_s11 != -1
    assert idx_s10 < idx_s11

    # 2. Second run: markers present -> replaces in-place without duplicating
    success_second = update_readme_table(fake_readme)
    assert success_second is True

    content_after_second = fake_readme.read_text(encoding="utf-8")
    assert content_after_second.count("## 10. VulnTrace-Bench Evaluation Results") == 1
    assert content_after_second.count(TABLE_START_MARKER) == 1
    assert content_after_second.count(TABLE_END_MARKER) == 1
    assert content_after_second.count("## 11. Disclosures & Formal Limitations") == 1


def test_legacy_single_pass_verdict_labels_not_conforming():
    """
    Validates that derived benchmark records with historical GREEN labels in single-pass runs
    are strictly ineligible for 3-repeat claims and are formatted as 'Legacy Single-Pass (3x Pending)'.
    Programmatically derives the exact counts from raw observations.
    """
    from bench.run import (
        load_raw_observations,
        derive_benchmark_results,
        generate_markdown_table,
    )

    raw = load_raw_observations()
    results = derive_benchmark_results(raw)

    # In raw empirical observations, exactly 5 are GREEN_STATE_VERIFIED
    green_count = sum(1 for r in raw if r.get("behavioral_verdict") == "GREEN_STATE_VERIFIED")
    assert green_count == 5

    # All 10 are LEGACY_SINGLE_PASS
    single_pass_count = sum(1 for r in raw if r.get("protocol_conformance") == "LEGACY_SINGLE_PASS")
    assert single_pass_count == 10

    # 0 are three-repeat verified
    three_repeat_count = sum(1 for r in raw if r.get("three_repeat_verified"))
    assert three_repeat_count == 0

    for r in results:
        assert r["three_repeat_verified"] is False
        assert r["protocol_conformance"] == "LEGACY_SINGLE_PASS"

    table_md = generate_markdown_table(results)
    assert "3/3 Verified" not in table_md
    assert table_md.count("Legacy Single-Pass (3x Pending)") == 10


def test_budget_accounting_and_case_rw01_adjudication_semantics():
    """
    Validates CASE-RW-01 contradictory telemetry in raw observation,
    ensures its canonical adjudication is VERIFICATION_REJECTED while preserving
    INCONCLUSIVE as its raw behavioral observation, and tests count separation.
    """
    from bench.run import load_raw_observations, derive_benchmark_results, generate_markdown_table

    raw = load_raw_observations()
    case_rw01 = next((r for r in raw if r.get("id") == "CASE-RW-01"), None)
    assert case_rw01 is not None

    # Verify raw fields for CASE-RW-01
    assert case_rw01["behavioral_verdict"] == "INCONCLUSIVE"
    assert case_rw01["isolation_tier"] == "LOCAL_SUBPROCESS_FALLBACK"
    assert case_rw01["repeat_count"] == 1
    assert case_rw01["three_repeat_verified"] is False
    assert case_rw01["observed_repeat_results"][0]["positive_control_passed"] is False

    # Verify contradictory regression telemetry in raw observation:
    # top-level claims True, but observed repeat claims False (with test_count == 0)
    assert case_rw01["regression_passed"] is True
    assert case_rw01["regression_test_count"] == 0
    repeat_obs = case_rw01["observed_repeat_results"][0]
    assert repeat_obs["regression_passed"] is False
    assert repeat_obs["exit_code"] == 10

    results = derive_benchmark_results(raw)
    table_md = generate_markdown_table(results)

    # In the table itself, the raw behavioral verdict remains INCONCLUSIVE
    assert "| **`CASE-RW-01`** | Flasgger Vulnerable Commit (163a753) | Unsafe Deserialization | Real World Repository | `REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED` | `INCONCLUSIVE` | `LOCAL_SUBPROCESS_FALLBACK` | Legacy Single-Pass (3x Pending) |" in table_md

    # In the note, canonical terminal adjudication is VERIFICATION_REJECTED
    assert "canonical terminal adjudication under Spec §3.2 is `VERIFICATION_REJECTED`" in table_md
    assert "untrusted repository executed on host Tier 0 `LOCAL_SUBPROCESS_FALLBACK`" in table_md
    assert "contradictory regression telemetry" in table_md


def test_control_flow_and_api_accounting_semantics():
    """
    Validates that generated benchmark notes and static code structures accurately reflect:
    1. Multi-tier LLM control flow (Triage, Planning, Synthesis, AST fallback, 3-7 call range).
    2. 7/10 Tavily dispatch path vs 3/10 static reachability bypass.
    3. Offline client cache-miss fall-through risk to live HTTP requests.
    4. Formal metric disentanglement (client invocations, HTTP attempts, responses, replays, synthetic errors, degraded).
    """
    import inspect
    from bench.run import load_raw_observations, derive_benchmark_results, generate_markdown_table
    import vulntrace.llm.client as llm_client_mod
    import vulntrace.intel.tavily_client as tavily_client_mod
    import real_world_eval.run_eval as run_eval_mod

    # 1. Verify Markdown Table Notes
    raw = load_raw_observations()
    results = derive_benchmark_results(raw)
    table_md = generate_markdown_table(results)

    assert "API Interaction, Control Flow & Telemetry Accounting:" in table_md
    assert "Multi-Tier LLM Orchestration" in table_md
    assert "Triage (Small: `NVIDIA-Nemotron-3-Nano-30B-A3B`)" in table_md
    assert "Planning (Mid: `llama-3.3-70b-instruct`)" in table_md
    assert "Patch Synthesis (Ultra: `Nemotron-3-Ultra-550b-a55b`)" in table_md
    assert "Triage: N/A" in table_md
    assert "max_retries=2" in table_md
    assert "3 (baseline) to 7 (with schema validation retries)" in table_md
    assert "AST fallback is a defensive repair fallback, not an inference bypass" in table_md

    assert "Threat Intelligence Dispatch (7 of 10 Cases)" in table_md
    assert "7 of 10 benchmark cases invoke `VerificationPipeline.run_pipeline()`" in table_md
    assert "unreachable_dead_code" in table_md and "CASE-RW-02" in table_md and "CASE-RW-03" in table_md
    assert "standalone static AST reachability analysis without pipeline dispatch (0 Tavily invocations)" in table_md

    assert "Offline Cache-Miss Behavior (Static Verification)" in table_md
    assert "falls through to live outbound HTTP requests" in table_md

    assert "Telemetry Metric Disentanglement:" in table_md
    assert "(1) Client Invocations" in table_md
    assert "(2) Outbound HTTP Request Attempts" in table_md
    assert "(3) HTTP Responses Received" in table_md
    assert "(4) Successful HTTP 200 Responses with Valid JSON" in table_md
    assert "(5) Cassette Replays" in table_md
    assert "takes no outbound request on that code path" in table_md
    assert "(6) Synthetic Error Reports" in table_md
    assert "created without a received HTTP response" in table_md
    assert "internal 401 and exception-generated 500 objects are not counted as received HTTP responses" in table_md
    assert "(7) Degraded Pipeline Outcomes" in table_md
    assert "(8) Historical Telemetry Limitations" in table_md

    # 2. Static Code Verification: TokenFactoryClient Cache-Miss Fall-Through
    tf_source = inspect.getsource(llm_client_mod.TokenFactoryClient.generate_chat)
    assert "if not LLMCassetteManager.is_live_enabled() or not self.api_key:" in tf_source
    assert "if not self.api_key:" in tf_source
    assert "# 2. Live HTTP Call" in tf_source

    # 3. Static Code Verification: TavilyClient Cache-Miss Fall-Through
    tavily_source = inspect.getsource(tavily_client_mod.TavilyClient.search_with_relevance)
    assert "if not IntelCassetteManager.is_live_enabled() or not self.api_key:" in tavily_source
    assert "status_code=401" in tavily_source
    assert "await client.post(self.ENDPOINT, json=payload)" in tavily_source

    # 4. Static Code Verification: Benchmark Runner Case-Dispatch Paths
    eval_source = inspect.getsource(run_eval_mod)
    # CASE-RW-01 calls pipeline
    assert "evaluate_flasgger_vulnerable" in eval_source
    assert "VerificationPipeline.run_pipeline(pipeline_req)" in eval_source
    # CASE-RW-02 calls only AST analyzer
    rw02_source = inspect.getsource(run_eval_mod.evaluate_flasgger_patched)
    assert "AstReachabilityAnalyzer.analyze_repository" in rw02_source
    assert "VerificationPipeline.run_pipeline" not in rw02_source
    # CASE-RW-03 calls only AST analyzer
    rw03_source = inspect.getsource(run_eval_mod.evaluate_cookiecutter_false_positive)
    assert "AstReachabilityAnalyzer.analyze_repository" in rw03_source
    assert "VerificationPipeline.run_pipeline" not in rw03_source
