"""
VulnTrace Deserialization Sink-Class Oracle Unit Tests (Spec §4.3)
"""

from vulntrace.sinks import (
    SinkOracleRegistry,
    YamlDeserializationOracle,
    PickleDeserializationOracle,
    DeserializationSinkOracle,
    SinkClass,
)


def test_registry_registration_and_lookup():
    """Proves that SinkOracleRegistry discovers reviewed oracles by symbol."""
    yaml_oracle = SinkOracleRegistry.get_oracle_for_symbol("yaml.load")
    assert yaml_oracle is not None
    assert isinstance(yaml_oracle, YamlDeserializationOracle)
    assert yaml_oracle.sink_class == SinkClass.DESERIALIZATION

    pickle_oracle = SinkOracleRegistry.get_oracle_for_symbol("pickle.loads")
    assert pickle_oracle is not None
    assert isinstance(pickle_oracle, PickleDeserializationOracle)
    assert pickle_oracle.sink_class == SinkClass.DESERIALIZATION

    unknown_oracle = SinkOracleRegistry.get_oracle_for_symbol("unregistered.custom_sink")
    assert unknown_oracle is None


def test_yaml_oracle_probe_safety():
    """Proves that YAML probe is behavioral only (no shells, no network, non-destructive)."""
    oracle = YamlDeserializationOracle()
    probe = oracle.get_probe("test_canary.marker")
    assert probe.is_destructive is False
    assert probe.requires_network is False
    assert probe.requires_shell is False
    assert "test_canary.marker" in probe.payload_expr
    assert "builtins.eval" in probe.payload_expr


def test_pickle_oracle_probe_safety():
    """Proves that Pickle probe is behavioral only (no shells, no network, non-destructive)."""
    oracle = PickleDeserializationOracle()
    probe = oracle.get_probe("test_canary.marker")
    assert probe.is_destructive is False
    assert probe.requires_network is False
    assert probe.requires_shell is False
    assert "test_canary.marker" in probe.payload_expr
    assert "__reduce__" in probe.payload_expr


def test_expected_block_signature_matching():
    """Proves that ExpectedBlockSignature distinguishes authentic blocks from generic crashes."""
    oracle = YamlDeserializationOracle()
    sig = oracle.get_expected_block_signature()

    # Valid security blocks
    assert sig.matches("ConstructorError") is True
    assert sig.matches("yaml.constructor.ConstructorError") is True
    assert sig.matches("ParserError") is True
    assert sig.matches("YAMLError") is True

    # Generic crashes must NOT match
    assert sig.matches("Exception") is False
    assert sig.matches("RuntimeError") is False
    assert sig.matches("ZeroDivisionError") is False
    assert sig.matches("TypeError") is False
    assert sig.matches("") is False


def test_pickle_block_signature_matching():
    """Proves Pickle block signatures match unpickling errors."""
    oracle = PickleDeserializationOracle()
    sig = oracle.get_expected_block_signature()

    assert sig.matches("UnpicklingError") is True
    assert sig.matches("_pickle.UnpicklingError") is True
    assert sig.matches("SecurityError") is True
    assert sig.matches("AttributeError") is True

    assert sig.matches("IndexError") is False
    assert sig.matches("RuntimeError") is False


def test_safe_pattern_definitions():
    """Proves that oracles export documented safe pattern definitions."""
    yaml_oracle = YamlDeserializationOracle()
    patterns = yaml_oracle.get_safe_patterns()
    assert len(patterns) >= 2
    pattern_ids = [p.pattern_id for p in patterns]
    assert "yaml_safe_load" in pattern_ids
    assert any("safe_load" in p.example_snippet for p in patterns)

    pickle_oracle = PickleDeserializationOracle()
    pickle_patterns = pickle_oracle.get_safe_patterns()
    assert len(pickle_patterns) >= 2
    pickle_ids = [p.pattern_id for p in pickle_patterns]
    assert "restricted_unpickler" in pickle_ids


def test_benign_contracts_multi_input_evaluation():
    """Proves that positive controls evaluate valid outputs and reject stubs/empty containers."""
    oracle = YamlDeserializationOracle()
    contracts = oracle.get_benign_contracts()
    assert len(contracts) >= 3

    flat_contract = next(c for c in contracts if c.case_id == "flat_service_mapping")

    # Valid output passes
    valid_out = {"service": "auth", "port": 9000}
    ok, msg = oracle.evaluate_benign_output(flat_contract, valid_out)
    assert ok is True

    # None fails
    ok, msg = oracle.evaluate_benign_output(flat_contract, None)
    assert ok is False
    assert "cannot be None" in msg

    # Empty dict fails
    ok, msg = oracle.evaluate_benign_output(flat_contract, {})
    assert ok is False
    assert "empty dummy container" in msg

    # Missing key fails
    ok, msg = oracle.evaluate_benign_output(flat_contract, {"service": "auth"})
    assert ok is False
    assert "Missing required top-level key" in msg

    # Null value for required key fails
    ok, msg = oracle.evaluate_benign_output(flat_contract, {"service": "auth", "port": None})
    assert ok is False
    assert "has None value" in msg

    # Nested hierarchy contract
    nested_contract = next(c for c in contracts if c.case_id == "nested_hierarchy_mapping")
    valid_nested = {"service": "core-api", "nested": {"workers": 4, "enabled": True}}
    ok, msg = oracle.evaluate_benign_output(nested_contract, valid_nested)
    assert ok is True

    # Invariant value mismatch fails
    wrong_nested = {"service": "core-api", "nested": {"workers": 99, "enabled": True}}
    ok, msg = oracle.evaluate_benign_output(nested_contract, wrong_nested)
    assert ok is False
    assert "Invariant" in msg and "mismatch" in msg


def test_composite_deserialization_oracle():
    """Proves that Composite DeserializationSinkOracle routes correctly."""
    composite = DeserializationSinkOracle()
    assert composite.matches("yaml.load") is True
    assert composite.matches("pickle.loads") is True

    probe_yaml = composite.get_probe("canary.marker", symbol_or_call="yaml.load")
    assert "eval" in probe_yaml.payload_expr

    probe_pickle = composite.get_probe("canary.marker", symbol_or_call="pickle.loads")
    assert "__reduce__" in probe_pickle.payload_expr
