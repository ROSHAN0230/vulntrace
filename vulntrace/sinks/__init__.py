"""
VulnTrace Sink-Class Oracle Library (Spec §4.3)
"""

from typing import List, Optional
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
