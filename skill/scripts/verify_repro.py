#!/usr/bin/env python3
"""Run real vulnerable vs patched verification for a commit-based PoC workflow."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple


COMMIT_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})/?$")


@dataclass
class CmdResult:
    command: str
    cwd: str
    exit_code: int
    stdout: str
    stderr: str
    duration_sec: float


@dataclass
class RunSummary:
    label: str
    revision: str
    setup: Optional[CmdResult]
    check: CmdResult


def read_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run_cmd(command: str, cwd: pathlib.Path, timeout_sec: int) -> CmdResult:
    start = datetime.now(timezone.utc)
    proc = subprocess.run(
        command,
        cwd=str(cwd),
        shell=True,
        text=True,
        capture_output=True,
        timeout=timeout_sec,
    )
    end = datetime.now(timezone.utc)
    duration = (end - start).total_seconds()
    return CmdResult(
        command=command,
        cwd=str(cwd),
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        duration_sec=duration,
    )


def stage_poc_script(src: pathlib.Path, dest_rel: str, cwd: pathlib.Path) -> str:
    dest_rel_clean = dest_rel.strip() or src.name
    if pathlib.Path(dest_rel_clean).is_absolute():
        raise ValueError("--poc-dest must be a relative path inside worktree")

    dest_path = (cwd / dest_rel_clean).resolve()
    if cwd.resolve() not in [dest_path, *dest_path.parents]:
        raise ValueError("resolved --poc-dest is outside worktree")

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest_path)
    if os.access(src, os.X_OK):
        os.chmod(dest_path, dest_path.stat().st_mode | 0o111)
    return str(dest_path)


def parse_commit_url(commit_url: str) -> Tuple[str, str, str]:
    m = COMMIT_RE.match(commit_url.strip())
    if not m:
        raise ValueError("Invalid commit URL format. Expected https://github.com/<owner>/<repo>/commit/<sha>")
    return m.group(1), m.group(2), m.group(3)


def infer_repo_url(meta: dict) -> Tuple[str, str]:
    commit_url = str(meta.get("commit_url", "")).strip()
    owner = str(meta.get("owner", "")).strip()
    repo = str(meta.get("repo", "")).strip()
    sha = str(meta.get("sha", "")).strip()

    if commit_url:
        owner2, repo2, sha2 = parse_commit_url(commit_url)
        owner = owner or owner2
        repo = repo or repo2
        sha = sha or sha2

    if not owner or not repo or not sha:
        raise ValueError("meta JSON must include commit_url or owner/repo/sha fields")

    repo_url = f"https://github.com/{owner}/{repo}.git"
    return repo_url, sha


def ensure_repo(repo_url: str, repo_cache_dir: pathlib.Path, timeout_sec: int) -> None:
    if (repo_cache_dir / ".git").exists():
        subprocess.run(
            ["git", "-C", str(repo_cache_dir), "fetch", "--all", "--tags", "--prune"],
            check=True,
            text=True,
            capture_output=True,
            timeout=timeout_sec,
        )
    else:
        repo_cache_dir.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--no-checkout", repo_url, str(repo_cache_dir)],
            check=True,
            text=True,
            capture_output=True,
            timeout=timeout_sec,
        )


def remove_worktree_if_exists(repo_cache_dir: pathlib.Path, worktree_path: pathlib.Path, timeout_sec: int) -> None:
    if worktree_path.exists():
        subprocess.run(
            ["git", "-C", str(repo_cache_dir), "worktree", "remove", "--force", str(worktree_path)],
            check=True,
            text=True,
            capture_output=True,
            timeout=timeout_sec,
        )


def add_worktree(repo_cache_dir: pathlib.Path, worktree_path: pathlib.Path, revision: str, timeout_sec: int) -> None:
    subprocess.run(
        ["git", "-C", str(repo_cache_dir), "worktree", "add", "--force", str(worktree_path), revision],
        check=True,
        text=True,
        capture_output=True,
        timeout=timeout_sec,
    )


def evaluate_verdict(mode: str, vuln_exit: int, patched_exit: int) -> Tuple[bool, str]:
    if mode == "vuln_nonzero_patched_zero":
        ok = vuln_exit != 0 and patched_exit == 0
        return ok, "vulnerable should fail while patched should pass"
    if mode == "vuln_zero_patched_nonzero":
        ok = vuln_exit == 0 and patched_exit != 0
        return ok, "vulnerable should pass while patched should fail"
    if mode == "different_exit_codes":
        ok = vuln_exit != patched_exit
        return ok, "vulnerable and patched should produce different exit codes"
    if mode == "same_exit_codes":
        ok = vuln_exit == patched_exit
        return ok, "vulnerable and patched should produce same exit codes"
    raise ValueError(f"Unsupported verdict mode: {mode}")


def render_markdown(report: dict) -> str:
    vuln = report["runs"]["vulnerable"]
    patched = report["runs"]["patched"]
    verdict = report["verdict"]

    def fmt_block(label: str, run: dict) -> str:
        setup = run.get("setup")
        setup_line = "(skipped)"
        if setup:
            setup_line = f"exit={setup['exit_code']} duration={setup['duration_sec']:.2f}s"
        return (
            f"### {label}\n"
            f"- Revision: `{run['revision']}`\n"
            f"- Setup: {setup_line}\n"
            f"- Check exit: {run['check']['exit_code']}\n"
            f"- Check duration: {run['check']['duration_sec']:.2f}s\n"
        )

    return (
        "# Verification Report\n\n"
        "## Inputs\n"
        f"- Repo URL: `{report['repo_url']}`\n"
        f"- Patched SHA: `{report['patched_sha']}`\n"
        f"- Vulnerable Revision: `{report['vulnerable_revision']}`\n"
        f"- Verdict Mode: `{verdict['mode']}` ({verdict['rule']})\n\n"
        "## Results\n"
        f"- Verdict: `{'PASS' if verdict['pass'] else 'FAIL'}`\n"
        f"- Vulnerable check exit: `{vuln['check']['exit_code']}`\n"
        f"- Patched check exit: `{patched['check']['exit_code']}`\n\n"
        f"{fmt_block('Vulnerable', vuln)}\n"
        f"{fmt_block('Patched', patched)}\n"
        "## Notes\n"
        "- Validate business-level behavior, not only exit codes, before final claims.\n"
        "- Run only in local/disposable authorized environments.\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run real vulnerable vs patched verification.")
    parser.add_argument("--meta", required=True, help="Path to commit metadata JSON from fetch_commit_diff.py")
    parser.add_argument("--repo-url", default="", help="Optional repo URL override (git clone target)")
    parser.add_argument("--sha", default="", help="Optional patched SHA override")
    parser.add_argument("--work-dir", default="./verify-work", help="Working directory for repo cache and worktrees")
    parser.add_argument("--setup-cmd", default="", help="Optional setup command run in each revision checkout")
    parser.add_argument("--check-cmd", required=True, help="Verification command run in each revision checkout")
    parser.add_argument(
        "--poc-script",
        default="",
        help="Optional local PoC script to copy into each worktree before running setup/check",
    )
    parser.add_argument(
        "--poc-dest",
        default="./poc_generated",
        help="Relative destination path in each worktree for --poc-script (default: ./poc_generated)",
    )
    parser.add_argument(
        "--verdict-mode",
        default="different_exit_codes",
        choices=[
            "vuln_nonzero_patched_zero",
            "vuln_zero_patched_nonzero",
            "different_exit_codes",
            "same_exit_codes",
        ],
        help="How to evaluate vulnerable vs patched check exits",
    )
    parser.add_argument("--timeout-sec", type=int, default=300, help="Timeout per command in seconds")
    parser.add_argument("--out-json", default="", help="Output JSON report path")
    parser.add_argument("--out-md", default="", help="Output markdown report path")

    args = parser.parse_args()

    meta_path = pathlib.Path(args.meta).expanduser().resolve()
    if not meta_path.exists():
        print(f"[ERROR] meta JSON not found: {meta_path}", file=sys.stderr)
        return 2

    meta = read_json(meta_path)
    try:
        inferred_repo_url, inferred_sha = infer_repo_url(meta)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 3

    repo_url = args.repo_url.strip() or inferred_repo_url
    sha = args.sha.strip() or inferred_sha
    vulnerable_revision = f"{sha}^"
    poc_script_path = pathlib.Path(args.poc_script).expanduser().resolve() if args.poc_script.strip() else None
    if poc_script_path and not poc_script_path.exists():
        print(f"[ERROR] --poc-script not found: {poc_script_path}", file=sys.stderr)
        return 7

    work_dir = pathlib.Path(args.work_dir).expanduser().resolve()
    repo_slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", repo_url.rsplit("/", 1)[-1].replace(".git", "")) or "repo"
    repo_cache_dir = work_dir / "repos" / repo_slug
    worktrees_root = work_dir / "worktrees"
    vuln_dir = worktrees_root / f"{repo_slug}-vuln"
    patched_dir = worktrees_root / f"{repo_slug}-patched"

    try:
        ensure_repo(repo_url, repo_cache_dir, args.timeout_sec)
        remove_worktree_if_exists(repo_cache_dir, vuln_dir, args.timeout_sec)
        remove_worktree_if_exists(repo_cache_dir, patched_dir, args.timeout_sec)
        add_worktree(repo_cache_dir, vuln_dir, vulnerable_revision, args.timeout_sec)
        add_worktree(repo_cache_dir, patched_dir, sha, args.timeout_sec)
    except subprocess.CalledProcessError as exc:
        print(f"[ERROR] git command failed: {' '.join(shlex.quote(x) for x in exc.cmd)}", file=sys.stderr)
        if exc.stdout:
            print(exc.stdout, file=sys.stderr)
        if exc.stderr:
            print(exc.stderr, file=sys.stderr)
        return 4
    except subprocess.TimeoutExpired:
        print("[ERROR] git operation timed out", file=sys.stderr)
        return 5

    def run_for(label: str, revision: str, cwd: pathlib.Path) -> RunSummary:
        if poc_script_path:
            try:
                stage_poc_script(poc_script_path, args.poc_dest, cwd)
            except ValueError as exc:
                print(f"[ERROR] {exc}", file=sys.stderr)
                raise
        setup_result: Optional[CmdResult] = None
        if args.setup_cmd.strip():
            setup_result = run_cmd(args.setup_cmd, cwd, args.timeout_sec)
            if setup_result.exit_code != 0:
                # Continue to check command for fuller signal, unless setup failed catastrophically.
                pass
        check_result = run_cmd(args.check_cmd, cwd, args.timeout_sec)
        return RunSummary(label=label, revision=revision, setup=setup_result, check=check_result)

    try:
        vuln_run = run_for("vulnerable", vulnerable_revision, vuln_dir)
        patched_run = run_for("patched", sha, patched_dir)
    except ValueError:
        return 8
    except subprocess.TimeoutExpired:
        print("[ERROR] setup/check command timed out", file=sys.stderr)
        return 6

    verdict_pass, verdict_rule = evaluate_verdict(
        args.verdict_mode, vuln_run.check.exit_code, patched_run.check.exit_code
    )

    report = {
        "meta_file": str(meta_path),
        "repo_url": repo_url,
        "patched_sha": sha,
        "vulnerable_revision": vulnerable_revision,
        "work_dir": str(work_dir),
        "commands": {
            "setup_cmd": args.setup_cmd,
            "check_cmd": args.check_cmd,
        },
        "poc_script": {
            "source": str(poc_script_path) if poc_script_path else "",
            "dest": args.poc_dest if poc_script_path else "",
        },
        "runs": {
            "vulnerable": asdict(vuln_run),
            "patched": asdict(patched_run),
        },
        "verdict": {
            "mode": args.verdict_mode,
            "rule": verdict_rule,
            "pass": verdict_pass,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    out_json = pathlib.Path(args.out_json).expanduser().resolve() if args.out_json else work_dir / "verification-report.json"
    out_md = pathlib.Path(args.out_md).expanduser().resolve() if args.out_md else work_dir / "verification-report.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")

    print("[OK] Verification complete")
    print(f"- JSON: {out_json}")
    print(f"- Markdown: {out_md}")
    print(f"- Verdict: {'PASS' if verdict_pass else 'FAIL'} ({args.verdict_mode})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
