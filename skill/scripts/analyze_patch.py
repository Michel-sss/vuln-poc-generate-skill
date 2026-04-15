#!/usr/bin/env python3
"""Analyze unified diff/patch files and extract vulnerability-relevant signals."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from collections import Counter, defaultdict
from typing import Dict, List, Set

SOURCE_PATTERNS = {
    "http_input": [r"request", r"req\.", r"query", r"params?", r"header", r"cookie", r"body"],
    "cli_input": [r"argv", r"getopt", r"argparse", r"flag"],
    "file_input": [r"read", r"fopen", r"open\(", r"ifstream", r"fs\.read"],
    "deserialization_input": [r"deserialize", r"unmarshal", r"pickle", r"yaml\.load", r"json\.loads"],
}

SINK_PATTERNS = {
    "command_execution": [r"system\(", r"exec\(", r"popen\(", r"subprocess", r"Runtime\.exec"],
    "file_write": [r"write", r"fwrite", r"ofstream", r"fs\.write", r"open\(.*['\"]w"],
    "dynamic_eval": [r"eval\(", r"Function\(", r"vm\.run", r"exec\("],
    "database_query": [r"SELECT", r"INSERT", r"UPDATE", r"DELETE", r"query\("],
    "unsafe_memory": [r"strcpy", r"memcpy", r"sprintf", r"gets\(", r"malloc"],
    "path_ops": [r"\.\./", r"path\.join", r"realpath", r"normalize\("],
}

GUARD_PATTERNS = {
    "bounds_or_length_check": [r"len\(", r"length", r"size", r"max", r"min"],
    "auth_or_acl_check": [r"auth", r"authorize", r"permission", r"role", r"acl"],
    "input_validation": [r"validate", r"sanitize", r"escape", r"allowlist", r"denylist"],
    "path_normalization": [r"realpath", r"normalize", r"clean", r"canonical"],
    "null_or_error_check": [r"null", r"nil", r"None", r"if\s*!", r"if\s*\("],
}

CWE_HINTS = {
    "cwe-79-xss": [r"innerHTML", r"script", r"escape", r"sanitize"],
    "cwe-89-sqli": [r"SELECT", r"INSERT", r"query\(", r"prepare", r"bind"],
    "cwe-22-path-traversal": [r"\.\./", r"path\.join", r"realpath", r"normalize"],
    "cwe-78-command-injection": [r"system\(", r"exec\(", r"subprocess", r"popen\("],
    "cwe-287-auth-bypass": [r"auth", r"authorize", r"token", r"session"],
    "cwe-119-memory-corruption": [r"strcpy", r"memcpy", r"sprintf", r"bounds"],
    "cwe-502-deserialization": [r"deserialize", r"pickle", r"yaml\.load", r"unmarshal"],
}

DIFF_HEADER_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")


def line_has_any(line: str, patterns: List[str]) -> bool:
    return any(re.search(p, line, re.IGNORECASE) for p in patterns)


def collect_matches(line: str, mapping: Dict[str, List[str]]) -> List[str]:
    hits: List[str] = []
    for label, patterns in mapping.items():
        if line_has_any(line, patterns):
            hits.append(label)
    return hits


def clamp_examples(examples: List[dict], max_items: int = 20) -> List[dict]:
    return examples[:max_items]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract likely vulnerability signals from a unified diff or patch file."
    )
    parser.add_argument("input", help="Path to .diff or .patch file")
    parser.add_argument(
        "--out",
        default="",
        help="Output JSON path (default: <input>.analysis.json)",
    )
    args = parser.parse_args()

    in_path = pathlib.Path(args.input).expanduser().resolve()
    if not in_path.exists():
        print(f"[ERROR] Input not found: {in_path}", file=sys.stderr)
        return 2

    text = in_path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    current_file = "<unknown>"
    files_touched: Set[str] = set()
    file_score: Counter = Counter()

    likely_sources: Counter = Counter()
    likely_sinks: Counter = Counter()
    added_guards: Counter = Counter()
    removed_guards: Counter = Counter()
    cwe_hints: Counter = Counter()

    evidence = defaultdict(list)

    for raw in lines:
        m = DIFF_HEADER_RE.match(raw)
        if m:
            current_file = m.group(2)
            files_touched.add(current_file)
            continue

        if raw.startswith("+++") or raw.startswith("---") or raw.startswith("@@"):
            continue

        sign = ""
        content = ""
        if raw.startswith("+"):
            sign = "+"
            content = raw[1:]
        elif raw.startswith("-"):
            sign = "-"
            content = raw[1:]
        else:
            continue

        source_hits = collect_matches(content, SOURCE_PATTERNS)
        sink_hits = collect_matches(content, SINK_PATTERNS)
        guard_hits = collect_matches(content, GUARD_PATTERNS)
        cwe_hit_labels = collect_matches(content, CWE_HINTS)

        weight = 2 if sign == "-" else 1
        if source_hits or sink_hits or guard_hits or cwe_hit_labels:
            file_score[current_file] += weight

        for h in source_hits:
            likely_sources[h] += 1
            evidence["sources"].append({"file": current_file, "sign": sign, "label": h, "line": content.strip()})

        for h in sink_hits:
            likely_sinks[h] += 1
            evidence["sinks"].append({"file": current_file, "sign": sign, "label": h, "line": content.strip()})

        for h in guard_hits:
            if sign == "+":
                added_guards[h] += 1
                evidence["added_guards"].append({"file": current_file, "label": h, "line": content.strip()})
            else:
                removed_guards[h] += 1
                evidence["removed_guards"].append({"file": current_file, "label": h, "line": content.strip()})

        for h in cwe_hit_labels:
            cwe_hints[h] += 1
            evidence["cwe_hints"].append({"file": current_file, "sign": sign, "label": h, "line": content.strip()})

    output = {
        "input": str(in_path),
        "summary": {
            "files_changed": len(files_touched),
            "lines_total": len(lines),
        },
        "hot_files": [
            {"file": fp, "score": score}
            for fp, score in file_score.most_common(10)
        ],
        "likely_sources": likely_sources.most_common(),
        "likely_sinks": likely_sinks.most_common(),
        "added_guards": added_guards.most_common(),
        "removed_guards": removed_guards.most_common(),
        "cwe_hints": cwe_hints.most_common(),
        "evidence": {
            "sources": clamp_examples(evidence["sources"]),
            "sinks": clamp_examples(evidence["sinks"]),
            "added_guards": clamp_examples(evidence["added_guards"]),
            "removed_guards": clamp_examples(evidence["removed_guards"]),
            "cwe_hints": clamp_examples(evidence["cwe_hints"]),
        },
        "notes": [
            "Heuristic-only output. Confirm against real code paths before final PoC.",
            "Prefer signals from hot_files and removed/added guard deltas first.",
        ],
    }

    out_path = pathlib.Path(args.out).expanduser().resolve() if args.out else in_path.with_suffix(in_path.suffix + ".analysis.json")
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    print("[OK] Analysis written:")
    print(f"- {out_path}")
    print("[OK] Top signals:")
    print(f"- hot_files: {len(output['hot_files'])}")
    print(f"- likely_sources: {len(output['likely_sources'])}")
    print(f"- likely_sinks: {len(output['likely_sinks'])}")
    print(f"- cwe_hints: {len(output['cwe_hints'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
