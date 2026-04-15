#!/usr/bin/env python3
"""Run end-to-end PoC flow: generate outline -> verify on vulnerable/patched revisions."""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
from typing import Optional, Tuple


SCRIPT_PATH_RE = re.compile(r"^- Script path: `(.+?)`\s*$")
INVOCATION_RE = re.compile(r"^- Invocation command: `(.+?)`\s*$")


def parse_outline(outline_path: pathlib.Path) -> Tuple[Optional[str], Optional[str]]:
    script_path = None
    invocation = None
    for line in outline_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m1 = SCRIPT_PATH_RE.match(line)
        if m1:
            script_path = m1.group(1).strip()
        m2 = INVOCATION_RE.match(line)
        if m2:
            invocation = m2.group(1).strip()
    return script_path, invocation


def run_step(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, text=True)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run generate_poc_outline + verify_repro as one pipeline.")
    parser.add_argument("--meta", required=True, help="Path to commit metadata JSON")
    parser.add_argument("--analysis", required=True, help="Path to analysis JSON")
    parser.add_argument("--work-dir", default="./pipeline-work", help="Pipeline working directory")
    parser.add_argument("--outline-out", default="", help="Optional output path for generated outline")
    parser.add_argument("--poc-lang", default="auto", help="PoC language for outline generation")
    parser.add_argument("--os", default="Ubuntu 22.04 x86_64", help="OS assumption for outline")
    parser.add_argument("--runtime", default="Project default runtime/toolchain", help="Runtime assumption for outline")
    parser.add_argument("--poc-script", default="", help="Optional generated PoC script to verify")
    parser.add_argument("--check-cmd", default="", help="Optional verification command override")
    parser.add_argument("--setup-cmd", default="", help="Optional setup command in each revision")
    parser.add_argument("--repo-url", default="", help="Optional repo URL override for verify step")
    parser.add_argument("--sha", default="", help="Optional patched SHA override for verify step")
    parser.add_argument(
        "--verdict-mode",
        default="different_exit_codes",
        choices=[
            "vuln_nonzero_patched_zero",
            "vuln_zero_patched_nonzero",
            "different_exit_codes",
            "same_exit_codes",
        ],
        help="Verification verdict strategy",
    )
    parser.add_argument("--timeout-sec", type=int, default=300, help="Timeout per command in seconds")

    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    gen_script = script_dir / "generate_poc_outline.py"
    verify_script = script_dir / "verify_repro.py"

    work_dir = pathlib.Path(args.work_dir).expanduser().resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    outline_out = pathlib.Path(args.outline_out).expanduser().resolve() if args.outline_out else work_dir / "generated-outline.md"

    gen_cmd = [
        sys.executable,
        str(gen_script),
        "--meta",
        str(pathlib.Path(args.meta).expanduser().resolve()),
        "--analysis",
        str(pathlib.Path(args.analysis).expanduser().resolve()),
        "--out",
        str(outline_out),
        "--poc-lang",
        args.poc_lang,
        "--os",
        args.os,
        "--runtime",
        args.runtime,
    ]

    print("[STEP] generate_poc_outline")
    run_step(gen_cmd)

    script_path, invocation = parse_outline(outline_out)
    check_cmd = args.check_cmd.strip() or (invocation or "")
    if not check_cmd:
        print("[ERROR] Could not resolve check command. Provide --check-cmd.", file=sys.stderr)
        return 2

    verify_cmd = [
        sys.executable,
        str(verify_script),
        "--meta",
        str(pathlib.Path(args.meta).expanduser().resolve()),
        "--work-dir",
        str(work_dir / "verify"),
        "--check-cmd",
        check_cmd,
        "--verdict-mode",
        args.verdict_mode,
        "--timeout-sec",
        str(args.timeout_sec),
        "--out-json",
        str(work_dir / "verification-report.json"),
        "--out-md",
        str(work_dir / "verification-report.md"),
    ]

    if args.setup_cmd.strip():
        verify_cmd.extend(["--setup-cmd", args.setup_cmd.strip()])
    if args.repo_url.strip():
        verify_cmd.extend(["--repo-url", args.repo_url.strip()])
    if args.sha.strip():
        verify_cmd.extend(["--sha", args.sha.strip()])

    poc_script = args.poc_script.strip()
    if poc_script:
        poc_abs = pathlib.Path(poc_script).expanduser().resolve()
        if not poc_abs.exists():
            print(f"[ERROR] --poc-script not found: {poc_abs}", file=sys.stderr)
            return 3
        dest = "./poc_generated"
        if script_path:
            dest = script_path
        verify_cmd.extend(["--poc-script", str(poc_abs), "--poc-dest", dest])

    print("[STEP] verify_repro")
    run_step(verify_cmd)

    print("[OK] Pipeline complete")
    print(f"- Outline: {outline_out}")
    print(f"- Verification JSON: {work_dir / 'verification-report.json'}")
    print(f"- Verification Markdown: {work_dir / 'verification-report.md'}")
    print(f"- Effective check command: {check_cmd}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
