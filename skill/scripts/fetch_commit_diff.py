#!/usr/bin/env python3
"""Fetch GitHub commit diff/patch and write normalized artifacts for PoC analysis."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Tuple


GITHUB_HOSTS = {"github.com", "www.github.com"}
COMMIT_PATH_RE = re.compile(r"^/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})(?:/)?$")


def normalize_commit_url(url: str) -> Tuple[str, str, str, str]:
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL must start with http:// or https://")

    host = parsed.netloc.lower()
    if host not in GITHUB_HOSTS:
        raise ValueError("Only github.com commit URLs are supported")

    match = COMMIT_PATH_RE.match(parsed.path)
    if not match:
        raise ValueError("Expected URL like https://github.com/<owner>/<repo>/commit/<sha>")

    owner, repo, sha = match.groups()
    clean_url = f"https://github.com/{owner}/{repo}/commit/{sha}"
    return owner, repo, sha, clean_url


def fetch_text(url: str, timeout: float = 20.0) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "vuln-poc-generate/1.0",
            "Accept": "text/plain, */*",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset, errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch GitHub commit diff/patch artifacts for vulnerability PoC generation."
    )
    parser.add_argument("commit_url", help="GitHub commit URL")
    parser.add_argument(
        "--out-dir",
        default="./artifacts",
        help="Output directory for fetched artifacts (default: ./artifacts)",
    )
    parser.add_argument(
        "--prefix",
        default="commit",
        help="Filename prefix for outputs (default: commit)",
    )
    parser.add_argument(
        "--include-html",
        action="store_true",
        help="Also save commit HTML page for offline inspection",
    )

    args = parser.parse_args()

    try:
        owner, repo, sha, clean_url = normalize_commit_url(args.commit_url)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    out_dir = pathlib.Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    diff_url = f"{clean_url}.diff"
    patch_url = f"{clean_url}.patch"

    try:
        diff_text = fetch_text(diff_url)
        patch_text = fetch_text(patch_url)
        html_text = fetch_text(clean_url) if args.include_html else ""
    except urllib.error.HTTPError as exc:
        print(f"[ERROR] HTTP {exc.code} while fetching: {exc.url}", file=sys.stderr)
        return 3
    except urllib.error.URLError as exc:
        print(f"[ERROR] Network error: {exc.reason}", file=sys.stderr)
        return 4

    prefix = args.prefix
    diff_path = out_dir / f"{prefix}-{sha}.diff"
    patch_path = out_dir / f"{prefix}-{sha}.patch"
    meta_path = out_dir / f"{prefix}-{sha}.json"

    diff_path.write_text(diff_text, encoding="utf-8")
    patch_path.write_text(patch_text, encoding="utf-8")

    metadata = {
        "commit_url": clean_url,
        "owner": owner,
        "repo": repo,
        "sha": sha,
        "diff_url": diff_url,
        "patch_url": patch_url,
        "diff_file": str(diff_path),
        "patch_file": str(patch_path),
        "include_html": args.include_html,
    }

    if args.include_html:
        html_path = out_dir / f"{prefix}-{sha}.html"
        html_path.write_text(html_text, encoding="utf-8")
        metadata["html_file"] = str(html_path)

    meta_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    print("[OK] Saved artifacts:")
    print(f"- {diff_path}")
    print(f"- {patch_path}")
    print(f"- {meta_path}")
    if args.include_html:
        print(f"- {metadata['html_file']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
