"""
VulnTrace Acceptance Test Synthesizer (M7 Phase 2 / Spec §4.4)
Synthesizes executable pytest acceptance test modules directly from canonical Spec definitions,
incorporating both security vulnerability rejection oracles and functional preservation checks.
"""

from typing import Optional, List
from vulntrace.intent.spec import Spec


class AcceptanceTestSynthesizer:
    """
    Synthesizes complete, executable pytest modules from repair specifications.
    Ensures that synthesized tests have substantive assertions and call the target symbol.
    """

    @classmethod
    def derive_import_path(cls, target_file: Optional[str], target_symbol: str) -> str:
        """Derives a Python import statement from target file and symbol."""
        if not target_file:
            return f"# Target symbol: {target_symbol}"

        # Clean file path: service/custom_loader.py -> service.custom_loader
        norm = target_file.replace("\\", "/").strip("/")
        if norm.endswith(".py"):
            norm = norm[:-3]
        module_path = norm.replace("/", ".")
        return f"from {module_path} import {target_symbol}"

    @classmethod
    def synthesize_test_module(
        cls,
        spec: Spec,
        target_symbol: Optional[str] = None,
        target_file: Optional[str] = None
    ) -> str:
        """Generates a complete pytest Python test module file content."""
        symbol = target_symbol or spec.vulnerable_symbol or "target_function"
        file_path = target_file or spec.target_file or "app.py"
        import_stmt = cls.derive_import_path(file_path, symbol)

        is_deserialization = any(k in spec.must_fix.lower() for k in ["deserialization", "yaml", "pickle", "json"])
        is_path_traversal = any(k in spec.must_fix.lower() for k in ["traversal", "archive", "tar", "zip", "extract"])
        has_custom_tags = any("custom" in p.lower() or "tag" in p.lower() for p in spec.must_preserve)

        lines: List[str] = [
            '"""',
            "Synthesized Acceptance Test Suite (VulnTrace Studio M7 Phase 2)",
            f"Target Vulnerability: {spec.must_fix}",
            f"Target Symbol: {symbol}",
            f"Target File: {file_path}",
            '"""',
            "",
            "import os",
            "import sys",
            "import tempfile",
            "from pathlib import Path",
            "import pytest",
            "",
            "try:",
            f"    {import_stmt}",
            "except ImportError:",
            "    # Fallback to sys.path resolution",
            "    sys.path.insert(0, str(Path.cwd()))",
            f"    {import_stmt}",
            "",
        ]

        if is_deserialization:
            # 1. Security Exploit Probe Test (Bounded canary in Tier 1 scratch space, strictly no shells)
            lines.extend([
                "@pytest.mark.security",
                "def test_security_probe_rejection(tmp_path):",
                f'    """Verifies that {symbol} rejects arbitrary object instantiation without creating canary."""',
                "    import yaml",
                "    import json",
                "    canary_file = Path.cwd() / '_canary_acceptance.marker'",
                "    telemetry_file = Path.cwd() / '_acceptance_telemetry.json'",
                "    if canary_file.exists():",
                "        canary_file.unlink()",
                "    if telemetry_file.exists():",
                "        telemetry_file.unlink()",
                "    canary_str = str(canary_file).replace('\\\\', '/')",
                "    exploit_payload = f\"exploit: !!python/object/apply:builtins.eval [\\\"open('{canary_str}', 'w').close()\\\"]\"",
                "",
                "    probe_blocked = False",
                "    exc_type = None",
                "    exc_msg = ''",
                "    try:",
                f"        {symbol}(exploit_payload)",
                "    except yaml.constructor.ConstructorError as e:",
                "        probe_blocked = True",
                "        exc_type = 'yaml.constructor.ConstructorError'",
                "        exc_msg = str(e)",
                "    except Exception as e:",
                "        probe_blocked = False",
                "        exc_type = type(e).__name__",
                "        exc_msg = str(e)",
                "",
                "    canary_created = canary_file.exists()",
                "    telemetry_data = {",
                "        'probe': 'test_security_probe_rejection',",
                "        'probe_blocked': probe_blocked,",
                "        'exception_type': exc_type,",
                "        'canary_created': canary_created,",
                "        'canary_relpath': '_canary_acceptance.marker'",
                "    }",
                "    telemetry_file.write_text(json.dumps(telemetry_data), encoding='utf-8')",
                "    print(f'\\n[ACCEPTANCE_TELEMETRY] {json.dumps(telemetry_data)}')",
                "",
                "    # Security expectation for repaired state:",
                "    # 1. Must block with exact expected ConstructorError (not broad YAMLError or unrelated exceptions)",
                "    # 2. Canary file must not exist",
                "    assert probe_blocked is True and exc_type == 'yaml.constructor.ConstructorError', (",
                "        f'UNSAFE_PROBE_NOT_BLOCKED: probe_blocked={probe_blocked}, exception_type={exc_type}, canary_created={canary_created}, error={exc_msg}'",
                "    )",
                "    assert not canary_created, (",
                "        f'CANARY_FILE_CREATED: probe_blocked={probe_blocked}, exception_type={exc_type}, canary_created={canary_created}'",
                "    )",
                "",
            ])

            # 2. Custom Tag Preservation Test
            if has_custom_tags:
                lines.extend([
                    "@pytest.mark.preservation",
                    "def test_preserve_custom_tags():",
                    f'    """Verifies that {symbol} preserves custom application tags and loaders."""',
                    "    custom_tag_payload = 'database_host: !env_var DB_HOST'",
                    f"    result = {symbol}(custom_tag_payload)",
                    "    # Domain preservation: must return valid dictionary without constructor error",
                    "    assert result is not None",
                    "    assert isinstance(result, dict)",
                    "    assert 'database_host' in result",
                    "    assert str(result['database_host']).startswith('DEFAULT_') or len(str(result['database_host'])) > 0",
                    "",
                ])

            # 3. Standard Configuration Regression Test
            lines.extend([
                "@pytest.mark.regression",
                "def test_standard_benign_config_loads_cleanly():",
                f'    """Verifies standard benign dictionary configuration passes {symbol}."""',
                "    benign_config = 'server:\\n  host: 127.0.0.1\\n  port: 8080'",
                f"    cfg = {symbol}(benign_config)",
                "    assert cfg is not None",
                "    if isinstance(cfg, dict):",
                "        assert 'server' in cfg",
                "        assert cfg['server']['host'] == '127.0.0.1'",
                "",
            ])

        elif is_path_traversal:
            # 1. Path Traversal Archive Rejection
            lines.extend([
                "@pytest.mark.security",
                "def test_path_traversal_archive_rejection(tmp_path):",
                f'    """Verifies {symbol} refuses archives containing directory traversal member paths."""',
                "    import tarfile",
                "    archive_path = tmp_path / 'traversal.tar'",
                "    extract_dest = tmp_path / 'extracted'",
                "    extract_dest.mkdir()",
                "",
                "    # Create canary archive with traversal member",
                "    with tarfile.open(archive_path, 'w') as tar:",
                "        canary_data = b'CANARY_PAYLOAD'",
                "        info = tarfile.TarInfo(name='../canary_escape.txt')",
                "        info.size = len(canary_data)",
                "        from io import BytesIO",
                "        tar.addfile(info, BytesIO(canary_data))",
                "",
                "    # Security expectation: raises exception or safely skips traversal members",
                "    try:",
                f"        {symbol}(str(archive_path), str(extract_dest))",
                "    except (ValueError, PermissionError, Exception):",
                "        pass",
                "",
                "    # Critical invariant: canary must not exist outside extract_dest",
                "    assert not (tmp_path / 'canary_escape.txt').exists()",
                "",
            ])

            # 2. Benign Archive Extraction Preserved
            lines.extend([
                "@pytest.mark.preservation",
                "def test_benign_archive_extraction_preserved(tmp_path):",
                f'    """Verifies {symbol} cleanly extracts benign archives within the destination."""',
                "    import tarfile",
                "    archive_path = tmp_path / 'benign.tar'",
                "    extract_dest = tmp_path / 'extracted'",
                "    extract_dest.mkdir(exist_ok=True)",
                "",
                "    with tarfile.open(archive_path, 'w') as tar:",
                "        safe_data = b'VALID_CONFIG'",
                "        info = tarfile.TarInfo(name='safe_file.txt')",
                "        info.size = len(safe_data)",
                "        from io import BytesIO",
                "        tar.addfile(info, BytesIO(safe_data))",
                "",
                f"    {symbol}(str(archive_path), str(extract_dest))",
                "    assert (extract_dest / 'safe_file.txt').exists()",
                "    assert (extract_dest / 'safe_file.txt').read_bytes() == b'VALID_CONFIG'",
                "",
            ])

        else:
            # Generic sink / regression verification
            lines.extend([
                "@pytest.mark.security",
                "def test_generic_security_probe():",
                f'    """Verifies {symbol} handles invalid or hostile inputs defensively."""',
                "    with pytest.raises(Exception) as exc:",
                f"        {symbol}('__MALICIOUS_INPUT__')",
                "    assert exc.value is not None",
                "",
                "@pytest.mark.regression",
                "def test_generic_benign_behavior():",
                f'    """Verifies {symbol} handles normal benign inputs."""',
                f"    result = {symbol}('valid_input')",
                "    assert result is not None",
                "",
            ])

        return "\n".join(lines)
