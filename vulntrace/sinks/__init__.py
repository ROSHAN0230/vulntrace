"""
VulnTrace Sink-Class Oracle Library (Spec §4.3)
"""

from typing import List, Optional, Any
from vulntrace.sinks.base import (
    BaseSinkOracle,
    SinkClass,
    BenignProbe,
    ExpectedBlockSignature,
    SafePattern,
    BenignContract,
)
from vulntrace.sinks.deserialization import (
    YamlDeserializationOracle,
    PickleDeserializationOracle,
    DeserializationSinkOracle,
)


class SinkOracleRegistry:
    """Registry for reviewed sink-class oracles."""

    _oracles: List[BaseSinkOracle] = [
        YamlDeserializationOracle(),
        PickleDeserializationOracle(),
    ]

    @classmethod
    def register(cls, oracle: BaseSinkOracle) -> None:
        cls._oracles.append(oracle)

    @classmethod
    def get_oracle_for_symbol(cls, symbol_or_call: str) -> Optional[BaseSinkOracle]:
        for oracle in cls._oracles:
            if oracle.matches(symbol_or_call):
                return oracle
        return None

    @classmethod
    def get_oracle_for_intel(cls, intel: Optional[Any]) -> Optional[BaseSinkOracle]:
        """Resolves reviewed sink oracle using ThreatIntel affected symbols or sink classes."""
        if not intel:
            return None
        symbols = getattr(intel, "affected_symbols", [])
        for sym in symbols:
            oracle = cls.get_oracle_for_symbol(sym)
            if oracle:
                return oracle
        sink_classes = getattr(intel, "sink_classes", [])
        for sc in sink_classes:
            for oracle in cls._oracles:
                if oracle.sink_class.value == sc or oracle.sink_class == sc:
                    return oracle
        return None

    @classmethod
    def get_candidate_symbols_for_intel(cls, intel: Optional[Any]) -> List[str]:
        """
        Returns candidate symbols selected by ThreatIntel.
        Materially changes AST search targets based on runtime threat intelligence.
        """
        if not intel or getattr(intel, "status", "") == "degraded":
            return [
                "yaml.load", "yaml.full_load", "os.system", "subprocess.Popen",
                "subprocess.call", "pickle.loads", "pickle.load", "eval", "exec"
            ]
        symbols = list(getattr(intel, "affected_symbols", []))
        oracle = cls.get_oracle_for_intel(intel)
        if oracle and hasattr(oracle, "SINK_CALLS"):
            for s in getattr(oracle, "SINK_CALLS"):
                if s not in symbols:
                    symbols.append(s)
        return symbols if symbols else [
            "yaml.load", "yaml.full_load", "os.system", "subprocess.Popen",
            "subprocess.call", "pickle.loads", "pickle.load", "eval", "exec"
        ]

    @classmethod
    def list_oracles(cls) -> List[BaseSinkOracle]:
        return list(cls._oracles)


__all__ = [
    "BaseSinkOracle",
    "SinkClass",
    "BenignProbe",
    "ExpectedBlockSignature",
    "SafePattern",
    "BenignContract",
    "YamlDeserializationOracle",
    "PickleDeserializationOracle",
    "DeserializationSinkOracle",
    "SinkOracleRegistry",
]
