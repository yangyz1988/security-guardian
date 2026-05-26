---
name: security-guardian
description: "Use when writing, reviewing, or deploying AI-generated code. Scans for OWASP Top 10 vulnerabilities, hardcoded secrets, insecure dependencies, and config risks. Provides auto-fix suggestions before code ships. Integrates with git pre-commit, GitHub Actions CI, and Code Scanning (SARIF)."
version: 0.2.0
author: 一人AI公司
license: MIT
metadata:
  hermes:
    tags: [security, owasp, vulnerability-scan, code-audit, secret-detection, devsecops, code-quality, ci-cd, pre-commit]
    related_skills: [test-driven-development, requesting-code-review, subagent-driven-development, plan]
---

# Security Guardian — AI 代码安全卫士

**让 AI 写的代码不再裸奔——部署前自动安全审计，git push 前自动卡点。**

## When to Use

Load this skill whenever:
- You've just written or generated code and want to check for vulnerabilities before committing
- You're doing a code review and want an automated security pass
- You're about to deploy and need a final safety check
- You want to check if any secrets/keys accidentally got into the codebase
- You suspect a dependency might have known vulnerabilities

**Triggers** (the agent should proactively suggest loading this skill):
- User mentions "commit", "deploy", "push", "ship", "go live"
- User opens or creates Dockerfile, .env, requirements.txt
- User reviews or writes code with database queries, user input, authentication
- A task involving 5+ files of code generation is completed

## Quick Start

### One-time scan
```bash
python scripts/scan.py --path . --output markdown
```

### Install as git pre-commit hook
```bash
cp templates/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### Install via pre-commit framework
```yaml
# 添加到项目 .pre-commit-config.yaml:
repos:
  - repo: local
    hooks:
      - id: security-guardian
        name: Security Guardian
        entry: python scripts/git-hook.py
        language: system
        types: [text]
        stages: [pre-commit]
```

### GitHub Actions CI (with Code Scanning)
复制 `templates/github-actions.yml` 到 `.github/workflows/security-scan.yml`

## What It Scans

### OWASP Top 10 + More
| Category | What's Detected | Severity |
|----------|----------------|----------|
| Secrets & Keys | OpenAI, GitHub, AWS, Stripe, Slack tokens; DB connection strings; private keys; hardcoded passwords | Critical/High |
| Injection | SQL injection, command injection, XSS, path traversal | Critical/High |
| Crypto | Hardcoded crypto keys, insecure random | Medium/Low |
| SSRF | User-controlled URLs in HTTP requests | Medium |
| Deserialization | Unsafe pickle/yaml.load usage | High |
| Race Condition | TOCTOU patterns | Low |
| Dependencies | Known-vulnerable versions of Django, Flask, requests, Pillow, etc. | High/Medium |
| Docker | Root user, privileged containers, host networking | Medium/High |
| Config | Empty env vars, misconfigured compose files | Low/Medium |

### Detection Rules: ~50+ patterns
- 10 secret/key patterns (OpenAI, GitHub, AWS, Stripe, Slack, generic API keys, passwords, JWT, SSH keys, DB URLs)
- 9 OWASP vulnerability patterns
- 9 known-vulnerable dependency versions
- 4 Docker/config checks

## Output Formats

### Markdown (human-readable)
```bash
python scripts/scan.py --path . --output markdown
```

### JSON (machine-readable)
```bash
python scripts/scan.py --path . --output json
```

### SARIF (GitHub Code Scanning)
```bash
python scripts/scan.py --path . --output sarif
```
Upload to GitHub Code Scanning for PR annotations.

## Pre-Commit Hook

`scripts/git-hook.py` 在 `git commit` 时自动扫描暂存区文件：

- **CRITICAL / HIGH** 问题 → 阻止提交
- **MEDIUM / LOW** 问题 → 警告但不阻止
- `SKIP_SECURITY_SCAN=1 git commit` 可紧急跳过
- `SECURITY_SCAN_STRICT=1 git commit` 让所有级别都阻止

## GitHub Actions CI

1. 复制 `templates/github-actions.yml` 到 `.github/workflows/`
2. 每次 push/PR 自动扫描
3. SARIF 结果上传到 GitHub Security → Code Scanning
4. PR 页面直接标注漏洞位置

## How to Interpret Results

### Severity Levels
- **🔴 Critical**: Fix immediately — secret exposed, SQL injection, code execution risk. Block deploy.
- **🟠 High**: Fix before next deploy — XSS, path traversal, hardcoded passwords.
- **🟡 Medium**: Fix this sprint — dependency vulns, SSRF risk, Docker misconfigs.
- **🔵 Low**: Address when convenient — insecure random, race condition risks.

### False Positives

v0.1.1 大幅改进了误报过滤，自扫描从 25 个误报降至 0。

**内置过滤规则**：
1. 注释行（`#` / `//`）自动跳过
2. 环境变量引用（`${VAR}`）不标记
3. 占位符关键词（`example`, `placeholder`, `YOUR_`, `TODO`, `xxx`）跳过
4. 正则规则定义行自动识别（`r'...'` / `(r'...'` + 正则元字符）
5. fix.py 示例代码（`'before':` 行）自动跳过
6. CVE 描述文本（`CVE-` / `vulnerab` 关键词）不标记
7. 测试文件（`test_*.py`）和文档（`.md`）默认排除

## Auto-Fix Engine

The fix engine (`scripts/fix.py`) can automatically fix:
- **Hardcoded secrets** → replaced with ${ENV_VAR} placeholder
- **Docker root user** → non-root user added
- **Privileged containers** → removed
- **SQL injection** → parameterized query suggestion
- **YAML deserialization** → safe_load suggestion
- **Command injection** → subprocess.run(list) suggestion

**Important**: 
- Always run with `--dry-run` (default) first to preview changes
- `--apply` creates `.security-guardian.bak` backups before modifying
- Suggestion-type fixes are never auto-applied — they only show before/after

## Integration with Other Skills

- **test-driven-development**: Scan before running tests
- **requesting-code-review**: Include scan report in review checklist
- **plan**: Add security scan as a step in implementation plans
- **subagent-driven-development**: Scan after each subagent completes work

## Pitfalls

- **Self-scanning**: v0.1.1 起自扫描已零误报。规则定义行、fix.py 示例、CVE 描述均自动过滤。扫描 `security-guardian/` 自身返回 0 findings。
- **Tests excluded by default**: `tests/` 目录和 `test_*.py` 文件默认不扫描（测试夹具含故意漏洞）。
- **Markdown excluded**: `.md` 文档默认不扫描（规则文档含示例代码）。
- **Network tools**: Does not need network access — all scanning is local and static.
- **Performance**: Scanning large projects (10K+ files) may take minutes. Use `--severity high` for quick scans.
- **Not a replacement for**: SAST tools (Semgrep, SonarQube) or penetration testing. This is a first-pass, pre-commit safety net for AI-generated code.
- **SQL injection regex**: 只检测 f-string 模式（`f"SELECT...{var}"`），不追踪变量赋值链。这是设计取舍（低误报 vs 全覆盖）。

## Commands Reference

```bash
# Scan with markdown report
python scripts/scan.py --path <project> --output markdown

# Scan with JSON (for CI/CD)
python scripts/scan.py --path <project> --output json

# Scan with SARIF (for GitHub Code Scanning)
python scripts/scan.py --path <project> --output sarif

# Only show critical and high
python scripts/scan.py --path <project> --severity high

# Preview fixes
python scripts/fix.py --path <project>

# Apply fixes (creates .bak backups)
python scripts/fix.py --path <project> --apply

# Fix specific rules only
python scripts/fix.py --path <project> --rule openai-key github-token

# Run pre-commit hook manually
python scripts/git-hook.py

# Run unit tests
python -m unittest tests.test_scan -v

# Weekly automated scan (for cron/CI)
python scripts/weekly_scan.py
```

## Project Structure

```
security-guardian/
├── SKILL.md                        # This file (Hermes Skill entry)
├── README.md
├── .gitignore
├── scripts/
│   ├── scan.py                     # Core scanning engine (no external deps)
│   ├── fix.py                      # Auto-fix engine
│   ├── git-hook.py                 # Pre-commit hook script
│   └── weekly_scan.py              # Cron-compatible weekly scan script
├── tests/
│   └── test_scan.py                # 41 unit tests (unittest, zero deps)
├── templates/
│   ├── pre-commit                  # Shell wrapper for .git/hooks/pre-commit
│   ├── .pre-commit-config.yaml     # pre-commit framework config
│   └── github-actions.yml          # GitHub Actions CI workflow
├── reports/                        # Auto-generated scan reports
├── references/
│   ├── rules.md                    # Full rules documentation
│   ├── owasp-top10.md              # OWASP Top 10 coverage map
│   └── feishu-mcp-lifecycle.md     # Feishu MCP 集成避坑指南
└── examples/
    └── sample-report.md            # Example scan report
```

## Version History

- **0.2.0** (2026-05-27): Pre-commit hook + CI/CD integration
  - SARIF 输出格式（`--output sarif`），兼容 GitHub Code Scanning
  - Git pre-commit hook (`scripts/git-hook.py`)：阻塞含密钥/高危漏洞的提交
  - GitHub Actions CI 模板：push/PR 自动扫描 + SARIF 上传
  - pre-commit 框架配置模板
  - templates/ 目录：预置集成模板
- **0.1.1** (2026-05-27): False positive elimination + tests + cron
  - 自扫描误报从 25→0（`has_regex_metas()`, `(r'...'` 检测, `'before':` 过滤, CVE 跳过, 排除 tests/ + .md）
  - SQL injection regex 增强：检测 f-string `{variable}` 模式
  - 41 个单元测试（tests/test_scan.py）
  - 周扫描脚本（scripts/weekly_scan.py）+ Hermes cron 集成
- **0.1.0** (2026-05-26): Initial MVP — scan engine + fix engine + 50+ rules
