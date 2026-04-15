# Contributing

Thanks for your interest in contributing to `vuln-poc-generate-skill`.

## Ways to Contribute

- Report bugs and reproduction issues
- Improve PoC generation or verification scripts
- Add language-specific PoC templates and examples
- Improve docs (English and Chinese)
- Improve safety checks and validation behavior

## Before You Start

- Use only authorized, local/disposable test environments
- Do not add instructions that target production or unauthorized systems
- Keep examples minimal and non-destructive

## Development Setup

```bash
git clone https://github.com/Michel-sss/vuln-poc-generate-skill.git
cd vuln-poc-generate-skill
```

Recommended checks:

```bash
python3 -m py_compile skill/scripts/*.py
```

## Pull Request Guidelines

1. Create a branch with a clear name, e.g. `feat/auto-cwe-improve` or `fix/verify-timeout`
2. Keep PRs focused and small when possible
3. Update documentation for behavior changes
4. Include command examples for new features
5. Add safety notes for any security-sensitive behavior

## Commit Message Style

Use short, clear messages, for example:

- `feat: add go template selector`
- `fix: handle missing sha in meta`
- `docs: update quick start examples`

## Reporting Issues

When opening an issue, include:

- Input commit URL (or redacted equivalent)
- Commands you ran
- Actual output/error
- Expected behavior
- OS and runtime versions

## Code of Conduct

Be respectful, constructive, and collaborative.
