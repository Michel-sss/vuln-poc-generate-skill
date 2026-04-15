# vuln-poc-generate-skill

A Codex skill project for generating and validating vulnerability PoCs from GitHub fix commit URLs.

中文说明: [README.zh-CN.md](README.zh-CN.md)

## What This Project Includes

- `skill/SKILL.md`: skill behavior, workflow, and execution guidance
- `skill/agents/openai.yaml`: Codex UI metadata
- `skill/references/poc-template.md`: PoC report template
- `skill/scripts/fetch_commit_diff.py`: download `.diff/.patch/.json` from a commit URL
- `skill/scripts/analyze_patch.py`: heuristic extraction of vulnerability signals
- `skill/scripts/generate_poc_outline.py`: generate PoC markdown outline (auto language + manual override)
- `skill/scripts/verify_repro.py`: run vulnerable vs patched verification
- `skill/scripts/run_poc_pipeline.py`: one-command pipeline (outline + verification)

## Quick Start

1. Prepare artifacts:

```bash
python3 skill/scripts/fetch_commit_diff.py <commit_url> --out-dir ./artifacts --prefix commit
python3 skill/scripts/analyze_patch.py ./artifacts/commit-<sha>.diff
```

2. Generate PoC outline:

```bash
python3 skill/scripts/generate_poc_outline.py \
  --meta ./artifacts/commit-<sha>.json \
  --analysis ./artifacts/commit-<sha>.diff.analysis.json \
  --poc-lang auto
```

3. Verify vulnerable vs patched behavior:

```bash
python3 skill/scripts/verify_repro.py \
  --meta ./artifacts/commit-<sha>.json \
  --check-cmd "<your-check-command>" \
  --verdict-mode different_exit_codes
```

4. Run end-to-end in one command:

```bash
python3 skill/scripts/run_poc_pipeline.py \
  --meta ./artifacts/commit-<sha>.json \
  --analysis ./artifacts/commit-<sha>.diff.analysis.json \
  --poc-script ./your_generated_poc.py \
  --verdict-mode vuln_zero_patched_nonzero \
  --work-dir ./pipeline-work
```

## Safety

Use only in local/disposable and authorized environments.
Do not run against production or unauthorized third-party systems.

## Install as Codex Skill

Copy `skill/` to your Codex skills path (usually `~/.codex/skills/vuln-poc-generate`).
