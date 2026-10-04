"""
VulnTrace Generalized Automated Verification Harness Synthesizer
Dynamically inspects discovered AST vulnerable call sites across arbitrary repository layouts.
Generates controlled, deterministic verification harnesses with explicit behavioral assertions:
- Exit 0: RED_PASSED (Risky behavior executed, sentinel created)
- Exit 42: GREEN_SECURITY_BLOCK_VERIFIED (Expected security block verified, sentinel blocked)
- Exit 10: INCONCLUSIVE (Pre-validation guard blocked input or condition could not be reproduced)
- Exit 1: UNEXPECTED_FAILURE (Process crash or uncaught unexpected error - NEVER treated as green!)
"""

import time
from pathlib import Path
from vulntrace.models import HarnessGenerateRequest, HarnessGenerateResponse

class HarnessSynthesizer:
    DEFAULT_SENTINEL = "sentinel_pwned.marker"

    @classmethod
    def _resolve_module_import_path(cls, rel_file_path: str) -> str:
        """Converts repository relative file path (e.g. 'services/yaml_parser.py') to Python import notation ('services.yaml_parser')."""
        p = Path(rel_file_path).as_posix()
        if p.endswith(".py"):
            p = p[:-3]
        return p.replace("/", ".").replace("\\", ".")

    @classmethod
    def synthesize_harness(cls, req: HarnessGenerateRequest) -> HarnessGenerateResponse:
        t0 = time.perf_counter()
        module_import = cls._resolve_module_import_path(req.target_file)
        func_name = req.function_name
        vuln_sym = req.vulnerable_call.lower()

        sentinel_name = req.sentinel_filename or cls.DEFAULT_SENTINEL

        # Classify vulnerability type from AST call name
        is_yaml_deserialization = any(k in vuln_sym for k in ["yaml.load", "yaml.full_load", "yaml.unsafe_load"])
        is_pickle_deserialization = any(k in vuln_sym for k in ["pickle.loads", "pickle.load", "_pickle.loads"])
        is_command_exec = any(k in vuln_sym for k in ["os.system", "subprocess.popen", "subprocess.call", "subprocess.run"])
        is_code_eval = any(k in vuln_sym for k in ["eval", "exec"])

        if is_yaml_deserialization:
            payload_expr = f'"""\nexploit: !!python/object/apply:builtins.eval ["open(\'{sentinel_name}\', \'w\').close()"]\n"""'
            import_block = """try:
    import yaml
    sec_block_types = (yaml.constructor.ConstructorError, yaml.parser.ParserError, yaml.YAMLError)
except Exception:
    class _EmptySecBlock(Exception): pass
    sec_block_types = (_EmptySecBlock,)"""
            benign_suite_code = """[
    {
        "id": "flat_service_mapping",
        "input": \"\"\"service: auth\\nport: 9000\"\"\",
        "req_type": dict,
        "req_keys": ["service", "port"],
        "check": lambda r: r.get("service") == "auth" and r.get("port") == 9000
    },
    {
        "id": "nested_hierarchy_mapping",
        "input": \"\"\"service: core-api\\nnested:\\n  workers: 4\\n  enabled: true\"\"\",
        "req_type": dict,
        "req_keys": ["service", "nested"],
        "check": lambda r: isinstance(r.get("nested"), dict) and r["nested"].get("workers") == 4 and r["nested"].get("enabled") is True
    },
    {
        "id": "multi_type_mapping",
        "input": \"\"\"database:\\n  host: localhost\\n  port: 5432\\n  endpoints:\\n    - primary\\n    - replica\"\"\",
        "req_type": dict,
        "req_keys": ["database"],
        "check": lambda r: isinstance(r.get("database"), dict) and r["database"].get("port") == 5432 and isinstance(r["database"].get("endpoints"), list) and len(r["database"]["endpoints"]) == 2
    }
]"""
        elif is_pickle_deserialization:
            payload_expr = f'__import__("pickle").dumps(type("Exploit", (), {{"__reduce__": lambda self: (open, ("{sentinel_name}", "w"))}})())'
            import_block = """try:
    import pickle
    import _pickle
    sec_block_types = (pickle.UnpicklingError, _pickle.UnpicklingError, AttributeError, ValueError)
except Exception:
    class _EmptySecBlock(Exception): pass
    sec_block_types = (_EmptySecBlock,)"""
            benign_suite_code = """[
    {
        "id": "pickle_flat_dict",
        "input": __import__("pickle").dumps({"service": "auth", "port": 9000}),
        "req_type": dict,
        "req_keys": ["service", "port"],
        "check": lambda r: r.get("service") == "auth" and r.get("port") == 9000
    },
    {
        "id": "pickle_nested_structure",
        "input": __import__("pickle").dumps({"service": "core", "nested": {"workers": 4}}),
        "req_type": dict,
        "req_keys": ["service", "nested"],
        "check": lambda r: isinstance(r.get("nested"), dict) and r["nested"].get("workers") == 4
    }
]"""
        elif is_command_exec or is_code_eval:
            payload_expr = f'"__import__(\'pathlib\').Path(\'{sentinel_name}\').touch()"'
            import_block = """sec_block_types = (ValueError, PermissionError, TypeError)"""
            benign_suite_code = """[
    {
        "id": "arithmetic_eval_alpha",
        "input": "1 + 1",
        "req_type": (int, str),
        "req_keys": [],
        "check": lambda r: r == 2 or str(r) == "2"
    },
    {
        "id": "arithmetic_eval_beta",
        "input": "10 * 5",
        "req_type": (int, str),
        "req_keys": [],
        "check": lambda r: r == 50 or str(r) == "50"
    }
]"""
        else:
            payload_expr = f'"""\nexploit: !!python/object/apply:builtins.eval ["open(\'{sentinel_name}\', \'w\').close()"]\n"""'
            import_block = """class _EmptySecBlock(Exception): pass
sec_block_types = (_EmptySecBlock,)"""
            benign_suite_code = """[
    {
        "id": "generic_benign_alpha",
        "input": "test_benign_input_alpha",
        "req_type": str,
        "req_keys": [],
        "check": lambda r: len(str(r)) > 0
    },
    {
        "id": "generic_benign_beta",
        "input": "test_benign_input_beta",
        "req_type": str,
        "req_keys": [],
        "check": lambda r: len(str(r)) > 0
    }
]"""

        harness_code = f'''"""
Automated Behavioral Verification Harness for {req.cve_id}
Generated dynamically by VulnTrace Verification Engine.
Target: {module_import}.{func_name}()
Vulnerable Symbol: {req.vulnerable_call}
"""
import sys
import os
import json
from pathlib import Path

# Anti-evasion normalization (P0.5.5)
# Normalize sys.argv to prevent trivial environment detection by candidate code
if sys.argv:
    sys.argv[0] = "{req.target_file}"

# Network isolation guard: prevent child network access during behavioral verification
try:
    import socket
    def _blocked_socket(*args, **kwargs):
        raise PermissionError("Network access blocked during sandbox behavioral verification.")
    socket.socket = _blocked_socket
    socket.create_connection = _blocked_socket
except Exception:
    pass

# Safe domain library imports for typed defensive assertions
{import_block}

# Target module import
try:
    from {module_import} import {func_name}
except Exception as import_err:
    print(json.dumps({{
        "sink_reached": False,
        "assertion_evaluated": False,
        "risky_effect_observed": False,
        "expected_security_exception": False,
        "unexpected_exception": True,
        "exception_type": type(import_err).__name__,
        "assertion": "UNEXPECTED_FAILURE",
        "detail": f"Failed to import target module {module_import}: {{import_err}}"
    }}))
    sys.exit(1)

sentinel = Path("{sentinel_name}")
if sentinel.exists():
    try:
        sentinel.unlink()
    except Exception:
        pass

# Benign sentinel marker verification payload
payload = {payload_expr}

try:
    # Execute target function in isolated sandbox
    res = {func_name}(payload)

    # Check if risky behavior materialized
    if sentinel.exists():
        print(json.dumps({{
            "sink_reached": True,
            "assertion_evaluated": True,
            "risky_effect_observed": True,
            "expected_security_exception": False,
            "unexpected_exception": False,
            "exception_type": None,
            "assertion": "RED_PASSED",
            "detail": "Risky behavioral path executed; sentinel marker created."
        }}))
        sys.exit(0)
    else:
        print(json.dumps({{
            "sink_reached": True,
            "assertion_evaluated": True,
            "risky_effect_observed": False,
            "expected_security_exception": False,
            "unexpected_exception": False,
            "exception_type": None,
            "assertion": "INCONCLUSIVE_NO_EFFECT",
            "detail": "Target executed without triggering sentinel or security exception."
        }}))
        sys.exit(10)

except sec_block_types as sec_err:
    # Explicit behavioral assertion: Verify expected defensive block occurred
    err_name = type(sec_err).__name__
    err_str = str(sec_err)

    if not sentinel.exists():
        # Multi-Input Behavioral Preservation Contract (P0.5.4)
        try:
            benign_cases = {benign_suite_code}
            executed_contracts = []

            for case in benign_cases:
                c_id = case["id"]
                r = {func_name}(case["input"])

                if r is None:
                    raise ValueError(f"Contract '{{c_id}}' failed: returned None")

                expected_t = case["req_type"]
                if not isinstance(r, expected_t):
                    raise TypeError(f"Contract '{{c_id}}' failed: expected {{expected_t}}, got {{type(r).__name__}}")

                if isinstance(r, (dict, list, str, set)) and len(r) == 0:
                    raise ValueError(f"Contract '{{c_id}}' failed: returned empty dummy container")

                if isinstance(r, dict):
                    for req_k in case.get("req_keys", []):
                        if req_k not in r:
                            raise KeyError(f"Contract '{{c_id}}' failed: missing required key '{{req_k}}'")
                        if r[req_k] is None:
                            raise ValueError(f"Contract '{{c_id}}' failed: key '{{req_k}}' has None value; expected non-null data")

                if "check" in case and not case["check"](r):
                    raise ValueError(f"Contract '{{c_id}}' failed: structural invariant or semantic value check failed")

                executed_contracts.append(c_id)

            print(json.dumps({{
                "sink_reached": True,
                "assertion_evaluated": True,
                "risky_effect_observed": False,
                "expected_security_exception": True,
                "unexpected_exception": False,
                "exception_type": err_name,
                "positive_control_passed": True,
                "contracts_verified": executed_contracts,
                "assertion": "GREEN_SECURITY_BLOCK_VERIFIED",
                "detail": f"Expected defensive security block verified ({{err_name}}) and all {{len(executed_contracts)}} behavioral preservation contracts verified."
            }}))
            sys.exit(42)  # Dedicated exit code for verified defensive block

        except Exception as benign_err:
            b_name = type(benign_err).__name__
            print(json.dumps({{
                "sink_reached": True,
                "assertion_evaluated": True,
                "risky_effect_observed": False,
                "expected_security_exception": False,
                "unexpected_exception": True,
                "exception_type": b_name,
                "positive_control_passed": False,
                "assertion": "POSITIVE_CONTROL_FAILED",
                "detail": f"Behavioral preservation contract failed: {{b_name}}: {{str(benign_err)}}"
            }}))
            sys.exit(1)
    else:
        print(json.dumps({{
            "sink_reached": True,
            "assertion_evaluated": True,
            "risky_effect_observed": True,
            "expected_security_exception": True,
            "unexpected_exception": False,
            "exception_type": err_name,
            "assertion": "INCONCLUSIVE_ERROR_WITH_SENTINEL",
            "detail": "Exception raised but sentinel file was created."
        }}))
        sys.exit(10)

except Exception as unexpected_err:
    # Check if this was a pre-validation guard
    u_name = type(unexpected_err).__name__
    u_str = str(unexpected_err).lower()
    is_guard = any(w in u_str for w in ["validation", "invalid input", "malformed", "blocked by guard", "untrusted", "disallowed", "guard", "security violation", "forbidden", "pre-filter"])

    if is_guard:
        print(json.dumps({{
            "sink_reached": False,
            "assertion_evaluated": True,
            "risky_effect_observed": False,
            "expected_security_exception": False,
            "unexpected_exception": True,
            "exception_type": u_name,
            "assertion": "INCONCLUSIVE_GUARD_BLOCKED",
            "detail": f"Pre-validation guard prevented execution: {{u_name}}: {{str(unexpected_err)}}"
        }}))
        sys.exit(10)
    else:
        # Unexpected crash / broken code
        print(json.dumps({{
            "sink_reached": False,
            "assertion_evaluated": False,
            "risky_effect_observed": False,
            "expected_security_exception": False,
            "unexpected_exception": True,
            "exception_type": u_name,
            "assertion": "UNEXPECTED_FAILURE",
            "detail": f"Unexpected execution error: {{u_name}}: {{str(unexpected_err)}}"
        }}))
        sys.exit(1)
'''

        dt = (time.perf_counter() - t0) * 1000.0
        return HarnessGenerateResponse(
            cve_id=req.cve_id,
            target_file=req.target_file,
            function_name=req.function_name,
            harness_code=harness_code.strip(),
            sentinel_filename=sentinel_name,
            latency_ms=round(dt, 2)
        )
