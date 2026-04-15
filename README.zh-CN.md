# vuln-poc-generate-skill

这是一个 Codex Skill 项目，用于基于 GitHub 漏洞修复 commit URL 生成并验证漏洞 PoC。

English: [README.md](README.md)

## 项目内容

- `skill/SKILL.md`：Skill 行为定义、工作流和执行说明
- `skill/agents/openai.yaml`：Codex UI 元数据
- `skill/references/poc-template.md`：PoC 报告模板
- `skill/scripts/fetch_commit_diff.py`：根据 commit URL 下载 `.diff/.patch/.json`
- `skill/scripts/analyze_patch.py`：对补丁做启发式分析，提取漏洞信号
- `skill/scripts/generate_poc_outline.py`：生成 PoC Markdown 草稿（支持语言自动识别和手动覆盖）
- `skill/scripts/verify_repro.py`：在 vulnerable / patched 两个版本中执行真实验证
- `skill/scripts/run_poc_pipeline.py`：一条命令跑完整链路（生成草稿 + 真实验证）

## 快速开始

1. 准备 artifacts：

```bash
python3 skill/scripts/fetch_commit_diff.py <commit_url> --out-dir ./artifacts --prefix commit
python3 skill/scripts/analyze_patch.py ./artifacts/commit-<sha>.diff
```

2. 生成 PoC 草稿：

```bash
python3 skill/scripts/generate_poc_outline.py \
  --meta ./artifacts/commit-<sha>.json \
  --analysis ./artifacts/commit-<sha>.diff.analysis.json \
  --poc-lang auto
```

3. 执行 vulnerable vs patched 验证：

```bash
python3 skill/scripts/verify_repro.py \
  --meta ./artifacts/commit-<sha>.json \
  --check-cmd "<你的验证命令>" \
  --verdict-mode different_exit_codes
```

4. 一条命令端到端执行：

```bash
python3 skill/scripts/run_poc_pipeline.py \
  --meta ./artifacts/commit-<sha>.json \
  --analysis ./artifacts/commit-<sha>.diff.analysis.json \
  --poc-script ./your_generated_poc.py \
  --verdict-mode vuln_zero_patched_nonzero \
  --work-dir ./pipeline-work
```

## 安全说明

仅在本地/隔离且已授权的测试环境中使用。
不要对生产系统或未授权第三方目标运行。

## 作为 Codex Skill 安装

将 `skill/` 目录复制到你的 Codex skill 路径（通常是 `~/.codex/skills/vuln-poc-generate`）。
