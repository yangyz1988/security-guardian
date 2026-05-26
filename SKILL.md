---
name: security-guardian
description: "Use when writing, reviewing, or deploying AI-generated code. Scans for OWASP Top 10 vulnerabilities, hardcoded secrets, insecure dependencies, and config risks. Provides auto-fix suggestions before code ships. Load before any code review or deployment."
version: 0.1.0
author: 一人AI公司
license: MIT
metadata:
  hermes:
    tags: [security, owasp, vulnerability-scan, code-audit, secret-detection, devsecops, code-quality]
    related_skills: [test-driven-development, requesting-code-review, subagent-driven-development, plan]
---

# Security Guardian — AI 代码安全卫士

**让 AI 写的代码不再裸奔——部署前自动安全审计。**

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

### Scan a project
```
Run security scan on this project
```
The agent will execute:
```bash
python scripts/scan.py --path . --output markdown
```

### Scan with JSON output (for programmatic use)
```bash
python scripts/scan.py --path ./my-project --output json
```

### Filter by severity
```bash
python scripts/scan.py --path . --severity high
```

### Preview auto-fixes (dry-run, no changes to files)
```bash
python scripts/fix.py --path . --rule openai-key github-token
```

### Apply fixes (changes files — creates .bak backups)
```bash
python scripts/fix.py --path . --apply
```

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
- 9 secret/key patterns (OpenAI, GitHub, AWS, generic API keys, passwords, JWT, SSH keys, DB URLs, Stripe, Slack)
- 9 OWASP vulnerability patterns
- 10 known-vulnerable dependency versions
- 5 Docker/config checks

## Output Format

### Markdown (human-readable)
Shows grouped findings by severity with file location, code snippet, and fix suggestion:
```
## 🔴 CRITICAL (3)
### openai-key
- **文件**: `config.py:12`
- **问题**: Hardcoded OpenAI API Key
```
- **修复**: Move to environment variable: export OPENAI_API_KEY=sk-...

### JSON (machine-readable)
```json
{
  "scan_time": "2026-05-26T...",
  "summary": {"by_severity": {"critical": 2, "high": 5}},
  "findings": [...]
}
```

## How to Interpret Results

### Severity Levels
- **🔴 Critical**: Fix immediately — secret exposed, SQL injection, code execution risk. Block deploy.
- **🟠 High**: Fix before next deploy — XSS, path traversal, hardcoded passwords.
- **🟡 Medium**: Fix this sprint — dependency vulns, SSRF risk, Docker misconfigs.
- **🔵 Low**: Address when convenient — insecure random, race condition risks.

### False Positives
The scanner uses conservative patterns. If you see a false positive:
1. The rule definition lines in security-guardian's own code will self-match — this is expected
2. Commented-out code and example/test files are automatically filtered
3. Environment variable references (${VAR}) are not flagged
4. Lines with "example", "placeholder", "TODO", "xxx" are skipped

Report false positives as GitHub Issues with the snippet.

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

- **Self-scanning**: When scanning the security-guardian project itself, the regex rule definitions will self-match (e.g., `innerHTML` in the XSS pattern). This is expected noise for the tool's own codebase.
- **Network tools**: Does not need network access — all scanning is local and static.
- **Performance**: Scanning large projects (10K+ files) may take minutes. Use `--severity high` for quick scans.
- **Not a replacement for**: SAST tools (Semgrep, SonarQube) or penetration testing. This is a first-pass, pre-commit safety net for AI-generated code.

## Commands Reference

```bash
# Scan with markdown report
python scripts/scan.py --path <project> --output markdown

# Scan with JSON (for CI/CD)
python scripts/scan.py --path <project> --output json

# Only show critical and high
python scripts/scan.py --path <project> --severity high

# Preview fixes
python scripts/fix.py --path <project>

# Apply fixes (creates .bak backups)
python scripts/fix.py --path <project> --apply

# Fix specific rules only
python scripts/fix.py --path <project> --rule openai-key github-token
```

## Project Structure

```
security-guardian/
├── SKILL.md                    # This file (Hermes Skill entry)
├── scripts/
│   ├── scan.py                 # Core scanning engine (no external deps)
│   └── fix.py                  # Auto-fix engine
├── references/
│   ├── rules.md                # Full rules documentation
│   └── owasp-top10.md          # OWASP Top 10 coverage map
└── examples/
    └── sample-report.md        # Example scan report
```

## Version History

- **0.1.0** (2026-05-26): Initial MVP — scan engine + fix engine + 50+ rules
