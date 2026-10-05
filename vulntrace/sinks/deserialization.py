"""
VulnTrace Reviewed Deserialization Sink-Class Oracle (Spec §4.3)

Provides reviewed, deterministic behavioral oracles for unsafe deserialization:
1. YAML: unsafe yaml.load, yaml.full_load, yaml.unsafe_load, unsafe Loader classes
2. Pickle: unsafe pickle.loads, pickle.load, _pickle.loads

Policy:
- Behavioral probes only.
- Canary file in workspace temp/working directory.
- Specific constructor/unpickler exception classes required for GREEN.
- Multi-input positive controls verify legitimate parsing survives remediation.
"""

from typing import List
from vulntrace.sinks.base import (
    BaseSinkOracle,
    SinkClass,
    BenignProbe,
    ExpectedBlockSignature,
    SafePattern,
    BenignContract,
)


class YamlDeserializationOracle(BaseSinkOracle):
    """Reviewed sink oracle for unsafe PyYAML deserialization (e.g. CVE-2020-14343)."""

    YAML_SINK_PATTERNS = (
        "yaml.load",
        "yaml.full_load",
        "yaml.unsafe_load",
        "yaml.Loader",
        "yaml.UnsafeLoader",
        "yaml.CLoader",
        "yaml.FullLoader",
    )

    @property
    def sink_class(self) -> SinkClass:
        return SinkClass.DESERIALIZATION

    @property
    def name(self) -> str:
        return "PyYAML Unsafe Deserialization Oracle"

    def matches(self, symbol_or_call: str) -> bool:
        sym = (symbol_or_call or "").lower()
        return any(p.lower() in sym for p in self.YAML_SINK_PATTERNS) or "yaml" in sym

    def get_probe(self, canary_filename: str) -> BenignProbe:
        payload = (
            f'"""\nexploit: !!python/object/apply:builtins.eval ["open(\'{canary_filename}\', \'w\').close()"]\n"""'
        )
        return BenignProbe(
            payload_expr=payload,
            canary_filename=canary_filename,
            description="Benign YAML eval probe creating canary marker inside workspace.",
            is_destructive=False,
            requires_network=False,
            requires_shell=False,
        )

    def get_expected_block_signature(self) -> ExpectedBlockSignature:
        return ExpectedBlockSignature(
            exception_class_names=(
                "ConstructorError",
                "ParserError",
                "YAMLError",
                "SecurityError",
            ),
            exception_module_names=("yaml.constructor", "yaml.parser", "yaml.error", "yaml"),
        )

    def get_safe_patterns(self) -> List[SafePattern]:
        return [
            SafePattern(
                pattern_id="yaml_safe_load",
                description="Replace unsafe yaml.load with yaml.safe_load",
                example_snippet="yaml.safe_load(raw_yaml)",
            ),
            SafePattern(
                pattern_id="yaml_safe_loader_param",
                description="Pass yaml.SafeLoader explicitly to yaml.load",
                example_snippet="yaml.load(raw_yaml, Loader=yaml.SafeLoader)",
            ),
            SafePattern(
                pattern_id="custom_safe_loader_subclass",
                description="Subclass yaml.SafeLoader to support domain tags without arbitrary object instantiation",
                example_snippet="class AppSafeLoader(yaml.SafeLoader): pass\nyaml.load(raw_yaml, Loader=AppSafeLoader)",
            ),
        ]

    def get_benign_contracts(self) -> List[BenignContract]:
        return [
            BenignContract(
                case_id="flat_service_mapping",
                description="Flat mapping with scalar configuration",
                raw_input="service: auth\nport: 9000",
                required_type_name="dict",
                required_keys=["service", "port"],
                nested_invariants={"service": "auth", "port": 9000},
            ),
            BenignContract(
                case_id="nested_hierarchy_mapping",
                description="Hierarchical mapping with nested dictionary, integer, and boolean",
                raw_input="service: core-api\nnested:\n  workers: 4\n  enabled: true",
                required_type_name="dict",
                required_keys=["service", "nested"],
                nested_invariants={"nested.workers": 4, "nested.enabled": True},
            ),
            BenignContract(
                case_id="collection_and_types_mapping",
                description="Complex mapping containing collections and endpoint lists",
                raw_input="database:\n  host: localhost\n  port: 5432\n  endpoints:\n    - primary\n    - replica",
                required_type_name="dict",
                required_keys=["database"],
                nested_invariants={"database.port": 5432, "database.endpoints": ["primary", "replica"]},
            ),
        ]

    def get_harness_import_block(self) -> str:
        return """try:
    import yaml
    sec_block_types = (yaml.constructor.ConstructorError, yaml.parser.ParserError, yaml.YAMLError)
except Exception:
    class _EmptySecBlock(Exception): pass
    sec_block_types = (_EmptySecBlock,)"""


class PickleDeserializationOracle(BaseSinkOracle):
    """Reviewed sink oracle for unsafe Pickle deserialization."""

    PICKLE_SINK_PATTERNS = (
        "pickle.loads",
        "pickle.load",
        "_pickle.loads",
        "_pickle.load",
    )

    @property
    def sink_class(self) -> SinkClass:
        return SinkClass.DESERIALIZATION

    @property
    def name(self) -> str:
        return "Pickle Unsafe Deserialization Oracle"

    def matches(self, symbol_or_call: str) -> bool:
        sym = (symbol_or_call or "").lower()
        return any(p.lower() in sym for p in self.PICKLE_SINK_PATTERNS) or "pickle" in sym

    def get_probe(self, canary_filename: str) -> BenignProbe:
        payload = (
            f'__import__("pickle").dumps(type("Exploit", (), {{"__reduce__": lambda self: (open, ("{canary_filename}", "w"))}})())'
        )
        return BenignProbe(
            payload_expr=payload,
            canary_filename=canary_filename,
            description="Benign Pickle __reduce__ probe creating canary marker inside workspace.",
            is_destructive=False,
            requires_network=False,
            requires_shell=False,
        )

    def get_expected_block_signature(self) -> ExpectedBlockSignature:
        return ExpectedBlockSignature(
            exception_class_names=(
                "UnpicklingError",
                "_UnpicklingError",
                "SecurityError",
                "AttributeError",
                "ValueError",
                "PermissionError",
            ),
            exception_module_names=("pickle", "_pickle"),
        )

    def get_safe_patterns(self) -> List[SafePattern]:
        return [
            SafePattern(
                pattern_id="restricted_unpickler",
                description="Custom unpickler overriding find_class to whitelist safe classes",
                example_snippet=(
                    "class RestrictedUnpickler(pickle.Unpickler):\n"
                    "    def find_class(self, module, name):\n"
                    "        if module in SAFE_MODULES: return super().find_class(module, name)\n"
                    "        raise pickle.UnpicklingError(f'Global {module}.{name} blocked')"
                ),
            ),
            SafePattern(
                pattern_id="json_replacement",
                description="Replaces raw pickle deserialization with safe json deserialization",
                example_snippet="json.loads(data.decode('utf-8'))",
            ),
        ]

    def get_benign_contracts(self) -> List[BenignContract]:
        return [
            BenignContract(
                case_id="pickle_flat_dict",
                description="Pickled basic configuration dictionary",
                raw_input='__import__("pickle").dumps({"service": "auth", "port": 9000})',
                required_type_name="dict",
                required_keys=["service", "port"],
                nested_invariants={"service": "auth", "port": 9000},
            ),
            BenignContract(
                case_id="pickle_nested_structure",
                description="Pickled nested structure with collections",
                raw_input='__import__("pickle").dumps({"service": "core", "nested": {"workers": 4}})',
                required_type_name="dict",
                required_keys=["service", "nested"],
                nested_invariants={"nested.workers": 4},
            ),
        ]

    def get_harness_import_block(self) -> str:
        return """try:
    import pickle
    import _pickle
    sec_block_types = (pickle.UnpicklingError, _pickle.UnpicklingError, AttributeError, ValueError, PermissionError)
except Exception:
    class _EmptySecBlock(Exception): pass
    sec_block_types = (_EmptySecBlock,)"""


class DeserializationSinkOracle(BaseSinkOracle):
    """
    Unified Deserialization Sink-Class Oracle.
    Dispatches between PyYAML and Pickle reviewed oracles based on the target symbol.
    """

    def __init__(self):
        self._yaml_oracle = YamlDeserializationOracle()
        self._pickle_oracle = PickleDeserializationOracle()

    @property
    def sink_class(self) -> SinkClass:
        return SinkClass.DESERIALIZATION

    @property
    def name(self) -> str:
        return "Composite Deserialization Sink-Class Oracle"

    def _resolve_sub_oracle(self, symbol_or_call: str) -> BaseSinkOracle:
        if self._pickle_oracle.matches(symbol_or_call):
            return self._pickle_oracle
        return self._yaml_oracle

    def matches(self, symbol_or_call: str) -> bool:
        return self._yaml_oracle.matches(symbol_or_call) or self._pickle_oracle.matches(symbol_or_call)

    def get_probe(self, canary_filename: str, symbol_or_call: str = "yaml.load") -> BenignProbe:
        return self._resolve_sub_oracle(symbol_or_call).get_probe(canary_filename)

    def get_expected_block_signature(self, symbol_or_call: str = "yaml.load") -> ExpectedBlockSignature:
        return self._resolve_sub_oracle(symbol_or_call).get_expected_block_signature()

    def get_safe_patterns(self, symbol_or_call: str = "yaml.load") -> List[SafePattern]:
        return self._resolve_sub_oracle(symbol_or_call).get_safe_patterns()

    def get_benign_contracts(self, symbol_or_call: str = "yaml.load") -> List[BenignContract]:
        return self._resolve_sub_oracle(symbol_or_call).get_benign_contracts()

    def get_harness_import_block(self, symbol_or_call: str = "yaml.load") -> str:
        return self._resolve_sub_oracle(symbol_or_call).get_harness_import_block()
