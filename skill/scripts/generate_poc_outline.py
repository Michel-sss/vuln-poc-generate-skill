#!/usr/bin/env python3
"""Generate a PoC markdown outline from commit metadata and patch analysis."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import Counter
from typing import Any, Dict, List, Tuple


LANG_CONFIG: Dict[str, Dict[str, str]] = {
    "python": {"ext": "py", "run": "python3 ./{file} --target localhost --mode check"},
    "go": {"ext": "go", "run": "go run ./{file} --target localhost --mode check"},
    "javascript": {"ext": "js", "run": "node ./{file} --target localhost --mode check"},
    "typescript": {"ext": "ts", "run": "npx ts-node ./{file} --target localhost --mode check"},
    "java": {"ext": "java", "run": "javac {file} && java {class_name} --target localhost --mode check"},
    "ruby": {"ext": "rb", "run": "ruby ./{file} --target localhost --mode check"},
    "php": {"ext": "php", "run": "php ./{file} --target localhost --mode check"},
    "rust": {"ext": "rs", "run": "rustc {file} -o poc_bin && ./poc_bin --target localhost --mode check"},
    "c": {"ext": "c", "run": "cc -O2 -o poc_bin {file} && ./poc_bin --target localhost --mode check"},
    "cpp": {"ext": "cpp", "run": "c++ -O2 -o poc_bin {file} && ./poc_bin --target localhost --mode check"},
}

EXT_TO_LANG = {
    ".go": "go",
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
}


def read_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def to_bullets(pairs: List[List[Any]], limit: int = 5) -> List[str]:
    if not pairs:
        return ["- (none detected)"]
    out = []
    for item in pairs[:limit]:
        if isinstance(item, list) and len(item) >= 2:
            out.append(f"- {item[0]} ({item[1]})")
        else:
            out.append(f"- {item}")
    return out


def to_hot_files(hot: List[dict], limit: int = 5) -> List[str]:
    if not hot:
        return ["- (no high-signal files)"]
    out = []
    for row in hot[:limit]:
        out.append(f"- {row.get('file', '<unknown>')} (score={row.get('score', 0)})")
    return out


def infer_language_from_hot_files(hot_files: List[dict]) -> str:
    scores: Counter = Counter()
    for row in hot_files:
        file_path = str(row.get("file", ""))
        score = int(row.get("score", 1) or 1)
        suffix = pathlib.Path(file_path).suffix.lower()
        lang = EXT_TO_LANG.get(suffix)
        if lang:
            scores[lang] += max(score, 1)

    if not scores:
        return "python"
    return scores.most_common(1)[0][0]


def build_artifact_info(repo: str, sha: str, poc_lang: str) -> Tuple[str, str]:
    cfg = LANG_CONFIG[poc_lang]
    short_sha = sha[:12] if sha and sha != "<sha>" else "<sha>"
    script_file = f"poc_{repo}_{short_sha}.{cfg['ext']}"
    class_name = pathlib.Path(script_file).stem
    run_cmd = cfg["run"].format(file=script_file, class_name=class_name)
    return script_file, run_cmd


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a PoC markdown outline from JSON artifacts.")
    parser.add_argument("--meta", required=True, help="Path to commit metadata JSON from fetch_commit_diff.py")
    parser.add_argument("--analysis", required=True, help="Path to analysis JSON from analyze_patch.py")
    parser.add_argument("--out", default="", help="Output markdown path (default: <meta>.poc-outline.md)")
    parser.add_argument("--os", default="Ubuntu 22.04 x86_64", help="Default OS/arch assumption")
    parser.add_argument("--runtime", default="Project default runtime/toolchain", help="Default runtime assumption")
    parser.add_argument(
        "--poc-lang",
        default="auto",
        choices=["auto", *sorted(LANG_CONFIG.keys())],
        help="PoC language. Use 'auto' to infer from changed files.",
    )

    args = parser.parse_args()

    meta_path = pathlib.Path(args.meta).expanduser().resolve()
    analysis_path = pathlib.Path(args.analysis).expanduser().resolve()

    if not meta_path.exists():
        print(f"[ERROR] Meta JSON not found: {meta_path}", file=sys.stderr)
        return 2
    if not analysis_path.exists():
        print(f"[ERROR] Analysis JSON not found: {analysis_path}", file=sys.stderr)
        return 3

    meta = read_json(meta_path)
    analysis = read_json(analysis_path)

    owner = meta.get("owner", "<owner>")
    repo = meta.get("repo", "<repo>")
    sha = meta.get("sha", "<sha>")
    commit_url = meta.get("commit_url", "<commit_url>")

    hot_files_raw = analysis.get("hot_files", [])
    hot_files = to_hot_files(hot_files_raw, limit=6)
    likely_sources = to_bullets(analysis.get("likely_sources", []), limit=6)
    likely_sinks = to_bullets(analysis.get("likely_sinks", []), limit=6)
    added_guards = to_bullets(analysis.get("added_guards", []), limit=6)
    removed_guards = to_bullets(analysis.get("removed_guards", []), limit=6)
    cwe_hints = to_bullets(analysis.get("cwe_hints", []), limit=4)

    if args.poc_lang == "auto":
        poc_lang = infer_language_from_hot_files(hot_files_raw)
        lang_source = "auto-inferred from patch file extensions"
    else:
        poc_lang = args.poc_lang
        lang_source = "manually specified by --poc-lang"

    script_file, run_cmd = build_artifact_info(repo, sha, poc_lang)

    outline = f"""# Vulnerability PoC Draft

## Vulnerability Summary
- Commit URL: {commit_url}
- Repository: {owner}/{repo}
- Commit hash: `{sha}`
- Affected files/functions (high signal):
{chr(10).join(hot_files)}
- Root cause (draft):
- Before patch: Input reaches sensitive logic without sufficient checks.
- Trigger condition: Crafted input exercises a risky path shown in the diff.
- Patch blocks by: Introducing or strengthening validation/guard logic.
- Vulnerability class (heuristic hints):
{chr(10).join(cwe_hints)}

## Reproduction Environment
- OS / Architecture: {args.os}
- Runtime / Compiler / Interpreter: {args.runtime}
- Dependency versions: Pin to pre-patch revision lockfile/toolchain where available.
- Build commands:
```bash
# Example skeleton
# git clone https://github.com/{owner}/{repo}.git
# cd {repo}
# git checkout {sha}^  # likely vulnerable parent
# <build-command>
```

## Reproduction Steps
1. Checkout vulnerable revision (usually `{sha}^`) and build/start target.
2. Prepare payload from likely input vectors:
{chr(10).join(likely_sources)}
3. Trigger potentially sensitive sink behavior:
{chr(10).join(likely_sinks)}
4. Capture deterministic evidence (logs/error/response/crash marker).
5. Checkout patched revision `{sha}` and re-run same trigger.

## Patch Signal Notes
- Added guards (likely mitigation):
{chr(10).join(added_guards)}
- Removed guards (potential regression indicators):
{chr(10).join(removed_guards)}

## PoC Artifact
- PoC language: `{poc_lang}` ({lang_source})
- Script path: `./{script_file}`
- Invocation command: `{run_cmd}`
- Required inputs: endpoint/CLI args/file payload inferred from affected code path.

## Expected Results
- Vulnerable revision: Trigger should produce unsafe behavior, error, or violated invariant.
- Patched revision: Same trigger should be rejected/sanitized/no longer reach unsafe sink.

## Assumptions
- Vulnerable baseline is the parent commit of fix (`{sha}^`).
- Local disposable test environment is permitted.
- No production or third-party targets are involved.

## Safety Notes
- Restrict to local/disposable test targets.
- Avoid destructive payloads; prove vulnerability with minimal impact only.
- Do not run against production or unauthorized systems.
"""

    out_path = pathlib.Path(args.out).expanduser().resolve() if args.out else meta_path.with_suffix(".poc-outline.md")
    out_path.write_text(outline, encoding="utf-8")

    print("[OK] PoC outline written:")
    print(f"- {out_path}")
    print("[OK] PoC language:")
    print(f"- {poc_lang} ({lang_source})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
