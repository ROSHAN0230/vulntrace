"""
Multi-File AST Call-Graph Analyzer & Reachability Solver
Parses Python source trees using native AST, resolves imports and aliases,
builds directed call graphs, and determines reachability from entrypoints.
"""

from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional, Any
import ast
import time
from collections import deque
from vulntrace.models import (
    AstAnalyzeRequest,
    AstAnalyzeResponse,
    CallGraphNode,
    CallGraphEdge,
    VulnerableCallSite
)

class FileAstAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path: Path, rel_path: str, target_symbols: List[str]):
        self.file_path = file_path
        self.rel_path = rel_path
        self.target_symbols = target_symbols
        self.current_func: Optional[str] = None
        self.imported_symbols: Dict[str, str] = {}  # alias -> original e.g. 'y' -> 'yaml', 'yload' -> 'yaml.load'
        self.imported_modules: Set[str] = set()
        self.locally_defined_symbols: Set[str] = set()
        self.defined_functions: Dict[str, int] = {}  # func_name -> line_number
        self.call_graph: Dict[str, List[str]] = {}   # func_name -> [called_func_names]
        self.vulnerable_calls: List[Dict[str, Any]] = []
        self.entrypoint_candidates: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            asname = alias.asname or alias.name
            self.imported_symbols[asname] = alias.name
            self.imported_modules.add(asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for alias in node.names:
            asname = alias.asname or alias.name
            full_orig = f"{mod}.{alias.name}" if mod else alias.name
            self.imported_symbols[asname] = full_orig
            self.imported_modules.add(asname)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        self.locally_defined_symbols.add(node.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_func = self.current_func
        func_name = node.name
        self.current_func = func_name
        self.locally_defined_symbols.add(func_name)
        self.defined_functions[func_name] = node.lineno
        self.call_graph.setdefault(func_name, [])

        # Check decorators for framework routes (FastAPI, Flask, Click)
        for dec in node.decorator_list:
            dec_id = ""
            if isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Attribute):
                    dec_id = dec.func.attr
                elif isinstance(dec.func, ast.Name):
                    dec_id = dec.func.id
            elif isinstance(dec, ast.Attribute):
                dec_id = dec.attr
            elif isinstance(dec, ast.Name):
                dec_id = dec.id
                
            if dec_id in ["get", "post", "put", "delete", "route", "command", "task"]:
                self.entrypoint_candidates.add(func_name)

        # Standard entrypoint heuristics
        if (
            func_name.startswith("test_")
            or func_name.endswith("_handler")
            or func_name.endswith("_endpoint")
            or func_name.startswith("api_")
            or func_name.startswith("handle_")
            or func_name in ["main", "handler", "run", "cli", "app", "serve", "index"]
        ):
            self.entrypoint_candidates.add(func_name)

        self.generic_visit(node)
        self.current_func = old_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        old_func = self.current_func
        func_name = node.name
        self.current_func = func_name
        self.locally_defined_symbols.add(func_name)
        self.defined_functions[func_name] = node.lineno
        self.call_graph.setdefault(func_name, [])

        for dec in node.decorator_list:
            dec_id = ""
            if isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Attribute):
                    dec_id = dec.func.attr
                elif isinstance(dec.func, ast.Name):
                    dec_id = dec.func.id
            elif isinstance(dec, ast.Attribute):
                dec_id = dec.attr
            elif isinstance(dec, ast.Name):
                dec_id = dec.id
                
            if dec_id in ["get", "post", "put", "delete", "route", "command", "task"]:
                self.entrypoint_candidates.add(func_name)

        if func_name.startswith("test_") or func_name in ["main", "handler", "run", "cli"]:
            self.entrypoint_candidates.add(func_name)

        self.generic_visit(node)
        self.current_func = old_func

    def _resolve_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                base_id = node.func.value.id
                # Check for shadowed local symbols (class or local variable)
                if base_id in self.locally_defined_symbols and base_id not in self.imported_symbols:
                    return f"local:{base_id}.{node.func.attr}"
                base = self.imported_symbols.get(base_id, base_id)
                return f"{base}.{node.func.attr}"
            elif isinstance(node.func.value, ast.Attribute):
                # Nested attribute like a.b.c
                parts = []
                curr = node.func
                while isinstance(curr, ast.Attribute):
                    parts.append(curr.attr)
                    curr = curr.value
                if isinstance(curr, ast.Name):
                    base_id = curr.id
                    if base_id in self.locally_defined_symbols and base_id not in self.imported_symbols:
                        return f"local:{base_id}.{'.'.join(reversed(parts))}"
                    base = self.imported_symbols.get(base_id, base_id)
                    parts.append(base)
                parts.reverse()
                return ".".join(parts)
            return node.func.attr
        elif isinstance(node.func, ast.Name):
            func_id = node.func.id
            if func_id in self.locally_defined_symbols and func_id not in self.imported_symbols:
                return f"local:{func_id}"
            return self.imported_symbols.get(func_id, func_id)
        return ""

    def visit_Call(self, node: ast.Call):
        call_name = self._resolve_call_name(node)
        caller = self.current_func or "<module>"

        if caller != "<module>":
            self.call_graph.setdefault(caller, []).append(call_name)

        # Check against target vulnerable symbols (local shadowed symbols are excluded)
        if not call_name.startswith("local:"):
            for sym in self.target_symbols:
                if call_name == sym or call_name.endswith(f".{sym}"):
                    self.vulnerable_calls.append({
                        "file": self.rel_path,
                        "function": caller,
                        "call": call_name,
                        "line": node.lineno
                    })
        self.generic_visit(node)


class AstReachabilityAnalyzer:
    @classmethod
    def analyze_repository(cls, req: AstAnalyzeRequest) -> AstAnalyzeResponse:
        t0 = time.perf_counter()
        repo_dir = Path(req.repo_path).resolve()

        if not repo_dir.exists() or not repo_dir.is_dir():
            dt = (time.perf_counter() - t0) * 1000.0
            return AstAnalyzeResponse(
                repo_path=str(repo_dir),
                analyzed_files=[],
                total_functions=0,
                discovered_calls=[],
                reachable_vulnerabilities_count=0,
                unreachable_dead_code_count=0,
                verdict="NO_VULNERABILITIES_FOUND",
                nodes=[],
                edges=[],
                latency_ms=round(dt, 2),
                error=f"Directory does not exist: {repo_dir}"
            )

        # Gather .py files, ignoring virtual environments and cache
        py_files = [
            f for f in repo_dir.rglob("*.py")
            if not any(part in f.parts for part in [".venv", "venv", "__pycache__", "node_modules", ".git", "build", "dist"])
        ]

        analyzed_files: List[str] = []
        global_defined_funcs: Dict[str, Tuple[str, int]] = {}  # func_name -> (rel_file, line)
        global_call_graph: Dict[str, Set[str]] = {}            # "file:func" -> set of called func names
        all_vulnerable_calls: List[Dict[str, Any]] = []
        entrypoints: Set[str] = set(req.entrypoints)

        for pf in py_files:
            rel_str = str(pf.relative_to(repo_dir)).replace("\\", "/")
            analyzed_files.append(rel_str)
            try:
                content = pf.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(content, filename=rel_str)
            except Exception:
                continue

            analyzer = FileAstAnalyzer(pf, rel_str, req.target_symbols)
            analyzer.visit(tree)

            for func, line in analyzer.defined_functions.items():
                node_id = f"{rel_str}:{func}"
                global_defined_funcs[func] = (rel_str, line)
                global_defined_funcs[node_id] = (rel_str, line)

            for caller, callees in analyzer.call_graph.items():
                caller_id = f"{rel_str}:{caller}"
                global_call_graph.setdefault(caller_id, set()).update(callees)
                global_call_graph.setdefault(caller, set()).update(callees)

            for ep in analyzer.entrypoint_candidates:
                entrypoints.add(f"{rel_str}:{ep}")
                entrypoints.add(ep)

            all_vulnerable_calls.extend(analyzer.vulnerable_calls)

        # Default fallback entrypoints if none explicitly identified
        if not entrypoints:
            for func_key in global_defined_funcs:
                if not func_key.startswith("<"):
                    entrypoints.add(func_key)

        # Trace reachability via BFS from entrypoints
        reachable_functions: Set[str] = set()
        queue = deque(entrypoints)
        reachability_paths: Dict[str, List[str]] = {ep: [ep] for ep in entrypoints}

        while queue:
            curr = queue.popleft()
            reachable_functions.add(curr)
            curr_path = reachability_paths.get(curr, [curr])

            callees = global_call_graph.get(curr, set())
            for callee in callees:
                targets = [callee]
                if "." in callee:
                    mod_p, fn_n = callee.rsplit(".", 1)
                    targets.extend([fn_n, f"{mod_p}.py:{fn_n}", f"{mod_p.replace('.', '/')}.py:{fn_n}"])
                elif ":" in callee:
                    _, fn_n = callee.split(":", 1)
                    targets.append(fn_n)

                for tgt in targets:
                    if tgt not in reachability_paths:
                        reachability_paths[tgt] = curr_path + [callee]
                        queue.append(tgt)

        # Classify vulnerable calls
        discovered_calls: List[VulnerableCallSite] = []
        reachable_count = 0
        dead_code_count = 0

        for vc in all_vulnerable_calls:
            func = vc["function"]
            file_rel = vc["file"]
            func_id = f"{file_rel}:{func}"

            # Check if function is reachable
            is_reachable = (func in reachable_functions) or (func_id in reachable_functions)
            call_path = reachability_paths.get(func_id) or reachability_paths.get(func) or []
            
            if is_reachable:
                reachable_count += 1
            else:
                dead_code_count += 1

            discovered_calls.append(VulnerableCallSite(
                file=file_rel,
                function_name=func,
                call_name=vc["call"],
                line_number=vc["line"],
                reachable=is_reachable,
                call_path_from_entrypoint=call_path
            ))

        # Build visual Nodes and Edges for frontend rendering
        nodes: List[CallGraphNode] = []
        edges: List[CallGraphEdge] = []
        node_seen = set()

        # Add function nodes
        for node_id, (file_rel, line) in global_defined_funcs.items():
            if ":" not in node_id:
                continue
            func_name = node_id.split(":", 1)[1]
            is_entry = (node_id in entrypoints) or (func_name in entrypoints)
            is_reachable = (node_id in reachable_functions) or (func_name in reachable_functions)
            
            vuln_for_func = [vc for vc in discovered_calls if vc.function_name == func_name and vc.file == file_rel]
            has_vuln = len(vuln_for_func) > 0
            vuln_text = ", ".join([v.call_name for v in vuln_for_func]) if has_vuln else None

            if has_vuln and is_reachable:
                n_type = "VULNERABLE_CALL"
            elif has_vuln and not is_reachable:
                n_type = "DEAD_CODE"
            elif is_entry:
                n_type = "ENTRYPOINT"
            else:
                n_type = "FUNCTION"

            nodes.append(CallGraphNode(
                id=node_id,
                label=f"{func_name}()",
                file=file_rel,
                node_type=n_type,
                line_number=line,
                is_vulnerable=has_vuln,
                vulnerability_details=vuln_text
            ))
            node_seen.add(node_id)

        # Add edges
        for caller_id, callees in global_call_graph.items():
            if ":" not in caller_id:
                continue
            for callee in callees:
                # Find matching target node
                target_matches = [n.id for n in nodes if n.label.startswith(f"{callee}(") or n.id.endswith(f":{callee}")]
                target_id = target_matches[0] if target_matches else callee
                edges.append(CallGraphEdge(
                    source=caller_id,
                    target=target_id,
                    call_name=callee
                ))

        if reachable_count > 0:
            verdict = "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"
        elif dead_code_count > 0:
            verdict = "UNREACHABLE_FALSE_POSITIVE"
        else:
            verdict = "NO_VULNERABILITIES_FOUND"

        dt = (time.perf_counter() - t0) * 1000.0

        return AstAnalyzeResponse(
            repo_path=str(repo_dir),
            analyzed_files=analyzed_files,
            total_functions=len(nodes),
            discovered_calls=discovered_calls,
            reachable_vulnerabilities_count=reachable_count,
            unreachable_dead_code_count=dead_code_count,
            verdict=verdict,
            nodes=nodes,
            edges=edges,
            latency_ms=round(dt, 2),
            error=None
        )
