#!/usr/bin/env bash
# Security Guardian — 一键安装到 AI Coding Agent 生态
# 用法: bash install.sh [--hermes] [--claude] [--cline] [--all]
#
# 将 security-guardian 安装到目标 AI Coding Agent 的项目目录中。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SG_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🔒 Security Guardian — Multi-Agent 适配器安装"
echo "=============================================="
echo ""

# ============================================================
# 参数解析
# ============================================================
INSTALL_HERMES=false
INSTALL_CLAUDE=false
INSTALL_CLINE=false
INSTALL_ALL=false

if [ $# -eq 0 ]; then
    INSTALL_ALL=true
fi

for arg in "$@"; do
    case "$arg" in
        --hermes) INSTALL_HERMES=true ;;
        --claude) INSTALL_CLAUDE=true ;;
        --cline)  INSTALL_CLINE=true ;;
        --all)    INSTALL_ALL=true ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

if $INSTALL_ALL; then
    INSTALL_HERMES=true
    INSTALL_CLAUDE=true
    INSTALL_CLINE=true
fi

# ============================================================
# 获取目标项目目录
# ============================================================
TARGET="${1:-.}"
if [ ! -d "$TARGET" ]; then
    echo "❌ 目标目录不存在: $TARGET"
    exit 1
fi

TARGET="$(cd "$TARGET" && pwd)"
echo "📂 目标项目: $TARGET"
echo ""

# ============================================================
# Hermes Agent
# ============================================================
if $INSTALL_HERMES; then
    echo "─── Hermes Agent ───"
    echo "security-guardian v0.3.0 已作为 Hermes Skill 安装。"
    echo "位置: ~/.hermes/skills/one-person-company/security-guardian/"
    echo "在 Hermes 对话中输入 /skill security-guardian 加载。"
    echo "✅ Hermes Agent: 已安装"
    echo ""
fi

# ============================================================
# Claude Code
# ============================================================
if $INSTALL_CLAUDE; then
    echo "─── Claude Code ───"

    CLAUDE_DIR="$TARGET/.claude"
    SG_CC_DIR="$CLAUDE_DIR/security-guardian"

    # 复制核心脚本
    mkdir -p "$SG_CC_DIR/scripts"
    cp -r "$SG_ROOT/scripts/"* "$SG_CC_DIR/scripts/" 2>/dev/null || true

    # Skill
    mkdir -p "$CLAUDE_DIR/skills"
    cp "$SG_ROOT/adapters/claude-code/security-scan-skill.md" "$CLAUDE_DIR/skills/" 2>/dev/null || true

    # Command
    mkdir -p "$CLAUDE_DIR/commands"
    cp "$SG_ROOT/adapters/claude-code/security-scan-command.md" "$CLAUDE_DIR/commands/" 2>/dev/null || true

    # Subagent
    mkdir -p "$CLAUDE_DIR/agents"
    cp "$SG_ROOT/adapters/claude-code/security-reviewer-agent.md" "$CLAUDE_DIR/agents/" 2>/dev/null || true

    # 合并 hooks 配置
    if [ -f "$CLAUDE_DIR/settings.json" ]; then
        echo "  ⚠ .claude/settings.json 已存在，请手动合并 adapters/claude-code/hooks-settings.json"
    else
        cp "$SG_ROOT/adapters/claude-code/hooks-settings.json" "$CLAUDE_DIR/settings.json"
    fi

    echo "  ✅ Skill: .claude/skills/security-scan-skill.md"
    echo "  ✅ Command: .claude/commands/security-scan-command.md"
    echo "  ✅ Agent: .claude/agents/security-reviewer-agent.md"
    echo "  ✅ Core scripts: .claude/security-guardian/scripts/"
    echo ""
fi

# ============================================================
# Cline / Caveman
# ============================================================
if $INSTALL_CLINE; then
    echo "─── Cline / Caveman ───"

    CLINE_DIR="$TARGET/.cline"
    SG_CL_DIR="$CLINE_DIR/security-guardian"

    # 复制核心脚本
    mkdir -p "$SG_CL_DIR/scripts"
    cp -r "$SG_ROOT/scripts/"* "$SG_CL_DIR/scripts/" 2>/dev/null || true

    # 复制 MCP 包装器
    mkdir -p "$SG_CL_DIR/adapters/cline"
    cp "$SG_ROOT/adapters/cline/security-guardian-mcp.py" "$SG_CL_DIR/adapters/cline/" 2>/dev/null || true

    # .clinerules
    mkdir -p "$CLINE_DIR/rules"
    cp "$SG_ROOT/adapters/cline/.clinerules" "$CLINE_DIR/rules/security-guardian.md" 2>/dev/null || true

    echo "  ✅ .clinerules: .cline/rules/security-guardian.md"
    echo "  ✅ MCP Server: .cline/security-guardian/adapters/cline/security-guardian-mcp.py"
    echo "  ✅ Core scripts: .cline/security-guardian/scripts/"
    echo ""
    echo "  📋 手动步骤: 将 MCP 配置添加到 VS Code settings.json:"
    echo "    参考: adapters/cline/mcp-config.json"
    echo ""
fi

# ============================================================
# 完成
# ============================================================
echo "=============================================="
echo "🔒 Security Guardian 安装完成!"
echo ""
echo "验证安装:"
if $INSTALL_CLAUDE; then
    echo "  Claude Code: ls .claude/security-guardian/scripts/"
fi
if $INSTALL_CLINE; then
    echo "  Cline: ls .cline/security-guardian/scripts/"
fi
echo ""
echo "快速测试:"
echo "  python scripts/scan.py --path . --output markdown --severity high"
