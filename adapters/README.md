# Security Guardian — Multi-Agent 适配器

将 Security Guardian 安全扫描能力集成到主流 AI Coding Agent 生态。

## 已适配平台

| 平台 | 目录 | 集成方式 | 状态 |
|------|------|---------|------|
| **Hermes Agent** | `SKILL.md` (项目根) | 原生 Skill | ✅ 完成 |
| **Claude Code** | `claude-code/` | Hooks + Skill + Command + Agent | ✅ 完成 |
| **Cline/Caveman** | `cline/` | .clinerules + MCP Server | ✅ 完成 |
| **Codex (OpenAI)** | — | Prompt 工程 | 📋 低优先级 |

## 目录结构

```
adapters/
├── README.md
├── claude-code/
│   ├── hooks-settings.json       # PostToolUse + PreToolUse Hooks
│   ├── security-scan-skill.md    # 语义触发 Skill
│   ├── security-scan-command.md  # /security-scan 斜杠命令
│   └── security-reviewer-agent.md # 专用安全审查子代理
└── cline/
    ├── .clinerules               # 项目级安全编码规则
    ├── security-guardian-mcp.py  # MCP Server 包装器 (scan + fix tools)
    └── mcp-config.json           # Cline MCP 配置模板
```

## 安装

### 一键安装（推荐）
```bash
bash install.sh
```

### 手动安装

#### Claude Code
```bash
# 1. 复制 security-guardian 到项目
cp -r security-guardian/ .claude/security-guardian/

# 2. 合并 hooks 配置到 .claude/settings.json
cat adapters/claude-code/hooks-settings.json >> .claude/settings.json

# 3. 复制 skill/command/agent
cp adapters/claude-code/security-scan-skill.md .claude/skills/
cp adapters/claude-code/security-scan-command.md .claude/commands/
cp adapters/claude-code/security-reviewer-agent.md .claude/agents/
```

#### Cline/Caveman
```bash
# 1. 复制 security-guardian 到项目
cp -r security-guardian/ .cline/security-guardian/

# 2. 安装 .clinerules
cp adapters/cline/.clinerules .cline/rules/security-guardian.md

# 3. 配置 MCP (手动添加到 VS Code settings.json)
# 参考 adapters/cline/mcp-config.json
```

## 功能对比

| 功能 | Hermes | Claude Code | Cline |
|------|--------|-------------|-------|
| 语义自动加载 | ✅ | ✅ (Skill) | ✅ (.clinerules) |
| 文件写入后自动扫描 | ❌ | ✅ (PostToolUse Hook) | ✅ (.clinerules) |
| Git commit 前卡点 | ✅ (pre-commit) | ✅ (PreToolUse Hook) | ❌ |
| 手动触发命令 | `/skill security-guardian` | `/security-scan` | 对话中触发 |
| 自动修复 | ✅ | ✅ | ✅ |
| MCP 工具调用 | ❌ | ❌ | ✅ |
| 子代理审查 | ❌ | ✅ (security-reviewer) | ❌ |
| SARIF / Code Scanning | ✅ | ✅ | ✅ |
