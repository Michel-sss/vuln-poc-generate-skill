---
name: vuln-poc-generate
description: Analyze a GitHub vulnerability fix commit and generate a reproducible proof-of-concept (PoC) for the vulnerable behavior. Use when the user provides a GitHub commit URL and asks to reproduce, verify, or demonstrate the vulnerability before/after the patch.
---

# Vulnerability PoC Generator

## Workflow

1. Validate and normalize the commit URL.
2. Run `scripts/fetch_commit_diff.py` to fetch `.diff` and `.patch` artifacts.
3. Run `scripts/analyze_patch.py` on the fetched diff to extract likely sources/sinks/guards/CWE hints.
4. Run `scripts/generate_poc_outline.py` to create an initial Markdown PoC draft.
5. Run `scripts/run_poc_pipeline.py` to automatically chain draft generation and real verification.
6. Identify repository, commit hash, affected files, and vulnerability-relevant code paths.
7. Infer vulnerability class from patch delta plus analysis signals.
8. Refine the draft into a minimal, deterministic PoC.
9. Provide environment setup, run steps, expected results, and cleanup.
10. Include the verification report findings for both vulnerable and patched revisions.

## Input Requirements

Require at minimum:
- GitHub commit URL

Request if missing:
- Target runtime constraints (OS/container/toolchain)
- Whether Docker-based reproduction is acceptable
- Preferred output style (script-only, markdown report, both)

If details are missing, assume a safe, local, disposable environment and continue.

## Commit Analysis Procedure

1. Fetch artifacts:
```bash
python3 scripts/fetch_commit_diff.py <commit_url> --out-dir ./artifacts --prefix commit
```
2. Run heuristic analyzer:
```bash
python3 scripts/analyze_patch.py ./artifacts/commit-<sha>.diff
```
3. Generate an outline draft:
```bash
python3 scripts/generate_poc_outline.py \
  --meta ./artifacts/commit-<sha>.json \
  --analysis ./artifacts/commit-<sha>.diff.analysis.json \
  --poc-lang auto   # or force: go/python/js/...
```
4. Run auto pipeline (outline + verification in one command):
```bash
python3 scripts/run_poc_pipeline.py \
  --meta ./artifacts/commit-<sha>.json \
  --analysis ./artifacts/commit-<sha>.diff.analysis.json \
  --poc-script ./poc_generated.py \
  --verdict-mode different_exit_codes
```
5. Parse `.diff`, `.patch`, `.analysis.json`, generated `.md`, and verification report together.
6. Extract:
- Changed files and functions
- Guard conditions added/removed
- Input sources (HTTP params, file paths, headers, serialized blobs, CLI args)
- Security-sensitive sinks (filesystem, eval, query execution, auth checks, unsafe memory ops)
7. Build a concise root-cause statement:
- "Before patch: ..."
- "Trigger condition: ..."
- "Impact in local test: ..."
- "Patch blocks by: ..."
8. Map to a candidate CVE/CWE class when strongly supported by diff evidence.

## PoC Construction Rules

1. Prefer minimal local impact and deterministic execution.
2. Prefer containerized or isolated setup instructions.
3. Keep payloads narrowly scoped to proving the bug, not maximizing damage.
4. Include prerequisites and exact version pinning when possible.
5. Include two checks:
- Vulnerable version should reproduce
- Patched version should fail to reproduce (or return safe behavior)

## Output Format

Produce the final result in this order:

1. `Vulnerability Summary`
- Commit URL
- Affected component
- Root cause
- Expected vulnerable behavior

2. `Reproduction Environment`
- OS/runtime/dependencies
- Build/run commands
- Dataset/fixtures required

3. `PoC Steps`
- Step-by-step commands
- PoC script or request examples
- Trigger payload

4. `Expected Results`
- On vulnerable commit
- On patched commit

5. `Troubleshooting`
- Common setup failures and fixes

6. `Safety Notes`
- Run only in local or explicitly authorized test environments
- Do not run against production or third-party systems

## PoC Script Guidance

When writing executable PoC scripts:
- Use clear command-line arguments (`--target`, `--port`, `--input`, `--mode`)
- Print explicit success/failure markers
- Use timeout/retry to avoid hanging tests
- Exit non-zero on setup failures
- Keep logs concise and actionable

## Resource Usage

- Use [fetch_commit_diff.py](scripts/fetch_commit_diff.py) first to produce normalized artifacts.
- Use [analyze_patch.py](scripts/analyze_patch.py) next to generate structured analysis signals.
- Use [generate_poc_outline.py](scripts/generate_poc_outline.py) to create an initial report draft (auto language inference; override with `--poc-lang`).
- Use [run_poc_pipeline.py](scripts/run_poc_pipeline.py) to chain generation + verification automatically.
- Use [verify_repro.py](scripts/verify_repro.py) directly for custom verification control and advanced command overrides.
- Read [poc-template.md](references/poc-template.md) before finalizing the answer.
- Reuse the template headings and fill only evidence-backed claims.
- If an assumption is required, label it as `Assumption`.

## Quality Checklist

Before finalizing, verify:
- Commit URL is valid and parsed correctly
- PoC references exact vulnerable behavior from diff
- Steps are reproducible without hidden prerequisites
- Patched behavior check is included
- Risky actions are excluded or clearly gated
