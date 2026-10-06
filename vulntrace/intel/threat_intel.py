"""
VulnTrace Threat Intelligence Normalizer & Symbol Extractor (Spec §4.8)
Transforms raw Tavily search findings and OSV data into a canonical ThreatIntel model.
Extracts affected symbols, candidate sink classes, and safe fix patterns to materially
drive AST call-graph reachability and oracle selection.
"""

import re
import time
import json
import hashlib
from typing import List, Dict, Any, Optional
from vulntrace.models import ThreatIntel, PocFinding
from vulntrace.sinks.base import SinkClass

# Known vulnerability sink pattern mapping
SINK_SYMBOL_PATTERNS: Dict[str, List[str]] = {
    SinkClass.DESERIALIZATION.value: [
        "yaml.load",
        "yaml.full_load",
        "yaml.unsafe_load",
        "pickle.loads",
        "pickle.load",
        "_pickle.loads",
        "shelve.open",
        "jsonpickle.decode",
    ],
    SinkClass.PATH_TRAVERSAL.value: [
        "tarfile.extractall",
        "tarfile.extract",
        "zipfile.extractall",
        "zipfile.extract",
        "shutil.unpack_archive",
    ],
    SinkClass.COMMAND_INJECTION.value: [
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.run",
        "os.system",
        "os.popen",
        "posix.system",
    ],
    SinkClass.CODE_EVAL.value: [
        "eval",
        "exec",
        "builtins.eval",
        "builtins.exec",
    ],
}

SAFE_FIX_PATTERNS: Dict[str, List[str]] = {
    SinkClass.DESERIALIZATION.value: [
        "yaml.safe_load",
        "yaml.SafeLoader",
        "yaml.CSafeLoader",
    ],
    SinkClass.PATH_TRAVERSAL.value: [
        "filter='data'",
        "os.path.commonpath",
        "abspath_check",
    ],
    SinkClass.COMMAND_INJECTION.value: [
        "shell=False",
        "shlex.quote",
        "list_args",
    ],
    SinkClass.CODE_EVAL.value: [
        "ast.literal_eval",
    ],
}

class ThreatIntelNormalizer:
    """Processes search results and CVE metadata into structured ThreatIntel."""

    @classmethod
    def compute_response_hash(cls, raw_data: Any) -> str:
        """Computes deterministic SHA-256 fingerprint of the raw search response."""
        try:
            serialized = json.dumps(raw_data, sort_keys=True, default=str)
        except Exception:
            serialized = str(raw_data)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def extract_symbols_and_classes(
        cls,
        corpus_text: str,
        default_cve: str = ""
    ) -> Dict[str, Any]:
        """
        Scans advisory corpus for sink symbols and classifies vulnerability families.
        Guarantees that ThreatIntel materially identifies affected symbols and sinks.
        """
        corpus_lower = corpus_text.lower()
        matched_symbols: List[str] = []
        matched_classes: List[str] = []
        matched_fix_patterns: List[str] = []

        # 1. Match specific symbol calls
        for sink_cls, symbols in SINK_SYMBOL_PATTERNS.items():
            class_matched = False
            for sym in symbols:
                # Direct symbol mention or token match
                sym_lower = sym.lower()
                if "." in sym_lower:
                    sym_regex = re.escape(sym_lower).replace(r"\.", r"[\s._]+")
                    is_hit = sym_lower in corpus_lower or bool(re.search(sym_regex, corpus_lower))
                elif sym_lower in ("exec", "eval"):
                    # Bare eval/exec must be standalone or function call, not inside "execution" or "evaluation"
                    is_hit = bool(re.search(rf"\b{sym_lower}\s*\(", corpus_lower)) or bool(re.search(rf"[`'\"]{sym_lower}[`'\"]", corpus_lower))
                else:
                    is_hit = bool(re.search(rf"\b{re.escape(sym_lower)}\b", corpus_lower))

                if is_hit:
                    if sym not in matched_symbols:
                        matched_symbols.append(sym)
                    class_matched = True

            if class_matched and sink_cls not in matched_classes:
                matched_classes.append(sink_cls)

        # 2. Heuristic keywords if no exact symbol matched
        if "yaml" in corpus_lower or "deserializ" in corpus_lower or "pickle" in corpus_lower:
            if SinkClass.DESERIALIZATION.value not in matched_classes:
                matched_classes.append(SinkClass.DESERIALIZATION.value)
            if "yaml" in corpus_lower and "yaml.load" not in matched_symbols:
                matched_symbols.extend(["yaml.load", "yaml.full_load"])
            if "pickle" in corpus_lower and "pickle.loads" not in matched_symbols:
                matched_symbols.append("pickle.loads")

        if "tar" in corpus_lower or "zip" in corpus_lower or "path traversal" in corpus_lower or "directory traversal" in corpus_lower:
            if SinkClass.PATH_TRAVERSAL.value not in matched_classes:
                matched_classes.append(SinkClass.PATH_TRAVERSAL.value)
            if "tar" in corpus_lower and "tarfile.extractall" not in matched_symbols:
                matched_symbols.append("tarfile.extractall")
            if "zip" in corpus_lower and "zipfile.extractall" not in matched_symbols:
                matched_symbols.append("zipfile.extractall")

        if "command injection" in corpus_lower or "shell injection" in corpus_lower or "os.system" in corpus_lower:
            if SinkClass.COMMAND_INJECTION.value not in matched_classes:
                matched_classes.append(SinkClass.COMMAND_INJECTION.value)
            if "subprocess.popen" not in matched_symbols:
                matched_symbols.extend(["subprocess.Popen", "os.system"])

        # 3. Extract recommended fix patterns
        for sink_cls in matched_classes:
            for fix in SAFE_FIX_PATTERNS.get(sink_cls, []):
                if fix.lower() in corpus_lower:
                    if fix not in matched_fix_patterns:
                        matched_fix_patterns.append(fix)

        # Fallback fix pattern if none matched explicitly
        if not matched_fix_patterns and SinkClass.DESERIALIZATION.value in matched_classes:
            matched_fix_patterns.append("yaml.safe_load")

        return {
            "affected_symbols": matched_symbols,
            "sink_classes": matched_classes,
            "fix_patterns": matched_fix_patterns,
        }

    @classmethod
    def build_threat_intel(
        cls,
        cve_id: str,
        query: str,
        raw_items: List[Dict[str, Any]],
        retained_findings: List[PocFinding],
        status_code: int = 200,
        rejection_reasons: Optional[List[str]] = None,
        error_msg: Optional[str] = None,
        latency_ms: float = 0.0
    ) -> ThreatIntel:
        """Constructs canonical ThreatIntel from processed search findings."""
        timestamp = time.time()
        resp_hash = cls.compute_response_hash({"raw_items": raw_items, "cve_id": cve_id})
        source_urls = [f.url for f in retained_findings if f.url]

        # Aggregate snippet text for semantic symbol extraction
        corpus_parts = [cve_id]
        for f in retained_findings:
            corpus_parts.extend([f.title, f.snippet])
        for item in raw_items:
            corpus_parts.extend([item.get("title", ""), item.get("content", "")[:300]])
        corpus_text = " ".join(corpus_parts)

        extracted = cls.extract_symbols_and_classes(corpus_text, default_cve=cve_id)

        is_degraded = (
            status_code != 200
            or bool(error_msg)
            or (len(raw_items) == 0 and not retained_findings)
        )
        status = "degraded" if is_degraded else "ok"

        confidence = 0.95 if (len(retained_findings) >= 2 and extracted["affected_symbols"]) else (0.75 if extracted["affected_symbols"] else 0.50)
        if is_degraded:
            confidence = 0.30

        return ThreatIntel(
            cve_id=cve_id,
            status=status,
            query=query,
            timestamp=timestamp,
            response_hash=resp_hash,
            source_urls=source_urls,
            findings=retained_findings,
            affected_symbols=extracted["affected_symbols"],
            fix_patterns=extracted["fix_patterns"],
            safe_patterns=extracted["fix_patterns"],
            sink_classes=extracted["sink_classes"],
            confidence=round(confidence, 2),
            raw_findings_count=len(raw_items),
            retained_findings_count=len(retained_findings),
            rejection_reasons=rejection_reasons or [],
            latency_ms=round(latency_ms, 2),
            summary=(
                f"Identified {len(extracted['affected_symbols'])} candidate symbol(s) across "
                f"{len(extracted['sink_classes'])} sink class(es) from {len(source_urls)} source(s)."
                if not is_degraded else f"Threat intelligence degraded: {error_msg or 'No verified advisories returned.'}"
            ),
            error=error_msg
        )
