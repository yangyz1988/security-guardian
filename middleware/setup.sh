#!/usr/bin/env bash
# Security Guardian MCP Middleware — 一键接入 AI 编程 Agent
# =============================================================
# 用法:
#   bash middleware/setup.sh                 # 交互式（自动检测 Agent）
#   bash middleware/setup.sh --list          # 列出已检测到的 Agent
#   bash middleware/setup.sh --claude        # 只配置 Claude Code
#   bash middleware/setup.sh --cline         # 只配置 Cline
#   bash middleware/setup.sh --cursor        # 只配置 Cursor
#   bash middleware/setup.sh --upstream "np ..."  # 自定义上游 MCP 服务器
#
# 在 CI / 无交互环境下:
#   bash middleware/setup.sh --claude --upstream "npx @mcpserver/xxx" --policy strict
#
# 本脚本会自动:
#   1. 检测系统中已安装的 AI 编程 Agent
#   2. 替换 MCP 配置中的占位符（SG_ROOT, WORKSPACE）
#   3. 创建或追加 MCP 服务器条目到 Agent 配置中

set -euo pipefail

# ============================================================
# 路径与配置
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROXY_SCRIPT="$SCRIPT_DIR/mcp_proxy.py"
TEMPLATES_DIR="$SCRIPT_DIR/config-templates"

DEFAULT_UPSTREAM="npx @modelcontextprotocol/server-filesystem"
DEFAULT_POLICY="normal"
UPSTREAM=""
POLICY="$DEFAULT_POLICY"
INSTALL_CLAUDE=false
INSTALL_CLINE=false
INSTALL_CURSOR=false
DO_LIST=false
INTERACTIVE=true
BACKUP=true

# ============================================================
# 颜色
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[SG]${NC} $1"; }
ok()    { echo -e "${GREEN}[✅]${NC} $1"; }
warn()  { echo -e "${YELLOW}[⚠]${NC} $1"; }
err()   { echo -e "${RED}[❌]${NC} $1"; }

# ============================================================
# 参数解析
# ============================================================
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --help|-h)
                echo "用法: bash middleware/setup.sh [选项]"
                echo ""
                echo "选项:"
                echo "  --list              列出已检测到的 AI 编程 Agent"
                echo "  --claude            仅配置 Claude Code"
                echo "  --cline             仅配置 Cline (VS Code)"
                echo "  --cursor            仅配置 Cursor"
                echo "  --all               配置所有已检测到的 Agent"
                echo "  --upstream CMD      上游 MCP 服务器命令（默认: npx @mcps/server-filesystem）"
                echo "  --policy MODE       策略模式: normal | strict | relaxed（默认: normal）"
                echo "  --no-backup         不备份已有配置"
                echo "  --yes / -y          非交互模式（直接应用配置）"
                echo ""
                echo "示例:"
                echo "  bash middleware/setup.sh"
                echo "  bash middleware/setup.sh --claude --upstream \"npx @mcps/server-github\""
                echo "  bash middleware/setup.sh --cline --policy strict -y"
                exit 0
                ;;
            --list)          DO_LIST=true; INTERACTIVE=false ;;
            --claude)        INSTALL_CLAUDE=true; INTERACTIVE=false ;;
            --cline)         INSTALL_CLINE=true; INTERACTIVE=false ;;
            --cursor)        INSTALL_CURSOR=true; INTERACTIVE=false ;;
            --all)           INSTALL_CLAUDE=true; INSTALL_CLINE=true; INSTALL_CURSOR=true; INTERACTIVE=false ;;
            --upstream)      shift; UPSTREAM="$1" ;;
            --policy)        shift; POLICY="$1" ;;
            --no-backup)     BACKUP=false ;;
            --yes|-y)        INTERACTIVE=false ;;
            *)               err "未知参数: $1"; echo "使用 --help 查看帮助"; exit 1 ;;
        esac
        shift
    done
}

parse_args "$@"

# ============================================================
# 依赖检查
# ============================================================
check_deps() {
    local missing=false
    if [ ! -f "$PROXY_SCRIPT" ]; then
        err "找不到 MCP 代理脚本: $PROXY_SCRIPT"
        err "请确保在 security-guardian 项目根目录运行本脚本"
        missing=true
    fi
    if ! command -v python &>/dev/null && ! command -v python3 &>/dev/null; then
        err "未检测到 Python，MCP Middleware 依赖 Python 3.10+"
        missing=true
    fi
    if $missing; then exit 1; fi
}

# ============================================================
# Agent 检测
# ============================================================
detect_agents() {
    local claude=false cline=false cursor=false

    # Claude Code
    if [ -f "$HOME/.claude/settings.json" ] || [ -d ".claude" ]; then
        claude=true
    fi
    if command -v claude &>/dev/null; then
        claude=true
    fi

    # Cline (VS Code)
    local vscode_settings
    if [ "$(uname)" = "Darwin" ]; then
        vscode_settings="$HOME/Library/Application Support/Code/User/settings.json"
    elif [ "$(uname)" = "Linux" ]; then
        vscode_settings="$HOME/.config/Code/User/settings.json"
    else
        # Windows (git-bash)
        vscode_settings="$APPDATA/Code/User/settings.json" 2>/dev/null || true
        if [ ! -f "$vscode_settings" ]; then
            vscode_settings="$HOME/Library/Application Support/Code/User/settings.json" 2>/dev/null || true
        fi
    fi
    if [ -f "$vscode_settings" ] && grep -q "cline" "$vscode_settings" 2>/dev/null; then
        cline=true
    fi
    # Cline 也可能有独立的 cline_mcp_settings.json
    if [ -f "$HOME/.config/cline/cline_mcp_settings.json" ] || [ -f "cline_mcp_settings.json" ]; then
        cline=true
    fi

    # Cursor
    if command -v cursor &>/dev/null || [ -d "$HOME/.cursor" ]; then
        if [ -f "$HOME/.cursor/mcp.json" ] || ls "$HOME/.cursor/"*.json &>/dev/null 2>&1; then
            cursor=true
        fi
    fi
    # Cursor 工作区设置
    if [ -f ".cursor/mcp.json" ]; then
        cursor=true
    fi

    echo "$claude|$cline|$cursor"
}

list_agents() {
    echo "🔍 检测 AI 编程 Agent 中..."
    echo ""
    IFS='|' read -r claude cline cursor <<< "$(detect_agents)"
    echo "  Claude Code: $([ "$claude" = true ] && echo '✅ 已安装' || echo '❌ 未检测到')"
    echo "  Cline:       $([ "$cline" = true ] && echo '✅ 已安装' || echo '❌ 未检测到')"
    echo "  Cursor:      $([ "$cursor" = true ] && echo '✅ 已安装' || echo '❌ 未检测到')"
    echo ""
    echo "MCP Middleware: $PROXY_SCRIPT"
    echo "Security Guardian 根目录: $SG_ROOT"
}

# ============================================================
# 替换占位符
# ============================================================
render_template() {
    local template="$1"
    local workspace="${2:-$(pwd)}"
    local policy="${3:-normal}"
    local agent_name="${4:-agent}"

    # 将模板中的占位符替换为实际路径
    sed -e "s|\${SG_ROOT}|$SG_ROOT|g" \
        -e "s|\${WORKSPACE}|$workspace|g" \
        -e "s|\${POLICY}|$policy|g" \
        -e "s|\${AGENT_NAME}|$agent_name|g" \
        "$template"
}

# ============================================================
# 替换代理命令中的 UPSTREAM（除非用户已自定义）
# ============================================================
set_upstream_in_json() {
    local json_file="$1"
    local new_upstream="$2"
    if [ -z "$new_upstream" ]; then
        cat "$json_file"
        return
    fi
    # 用 Python 做 JSON 安全的字符串替换
    python -c "
import json, sys
with open('$json_file') as f:
    data = json.load(f)
for name, server in data.get('mcpServers', {}).items():
    args = server.get('args', [])
    for i, arg in enumerate(args):
        if arg == '--upstream' and i + 1 < len(args):
            args[i + 1] = '$new_upstream'
with open('$json_file', 'w') as f:
    json.dump(data, f, indent=2)
print('✅ 已更新 upstream')
"
}

# ============================================================
# 配置 Claude Code
# ============================================================
setup_claude() {
    local workspace="${1:-$(pwd)}"
    echo ""
    info "── Claude Code ──"

    # Claude Code 配置位置（按优先级）
    local config_files=()
    if [ -f ".claude/settings.local.json" ]; then
        config_files+=(".claude/settings.local.json")
    fi
    config_files+=("$HOME/.claude/settings.json")

    local done=false
    for config_file in "${config_files[@]}"; do
        local config_dir
        config_dir="$(dirname "$config_file")"
        mkdir -p "$config_dir"

        # 备份
        if [ -f "$config_file" ] && $BACKUP; then
            local backup="${config_file}.$(date +%Y%m%d_%H%M%S).bak"
            cp "$config_file" "$backup"
            ok "已备份: $backup"
        fi

        # 生成配置条目
        local proxy_entry
        proxy_entry=$(python -c "
import json

entry = {
    'command': 'python',
    'args': [
        '$PROXY_SCRIPT',
        '--upstream', '${UPSTREAM:-$DEFAULT_UPSTREAM}',
        '--policy', '$POLICY'
    ],
    'env': {
        'SG_AGENT_NAME': 'claude-code'
    }
}
print(json.dumps({'mcpServers': {'filesystem': entry}}, indent=2))
")

        # 合并到已有配置或新建
        if [ -f "$config_file" ]; then
            python -c "
import json
with open('$config_file') as f:
    cfg = json.load(f)
if 'mcpServers' not in cfg:
    cfg['mcpServers'] = {}
cfg['mcpServers']['filesystem'] = json.loads('''$(python -c "
import json
entry = {
    'command': 'python',
    'args': [
        '$PROXY_SCRIPT',
        '--upstream', '${UPSTREAM:-$DEFAULT_UPSTREAM}',
        '--policy', '$POLICY'
    ],
    'env': {
        'SG_AGENT_NAME': 'claude-code'
    }
}
print(json.dumps(entry))
")''')
cfg.setdefault('hooks', {})
with open('$config_file', 'w') as f:
    json.dump(cfg, f, indent=2)
" 2>&1
        else
            python -c "
import json
cfg = json.loads('''$proxy_entry''')
with open('$config_file', 'w') as f:
    json.dump(cfg, f, indent=2)
"
        fi

        ok "已配置: $config_file"
        done=true
        break
    done

    if ! $done; then
        warn "无法写入任何 Claude Code 配置文件"
        warn "请手动复制: $TEMPLATES_DIR/claude-code-mcp.json"
    fi
}

# ============================================================
# 配置 Cline
# ============================================================
setup_cline() {
    local workspace="${1:-$(pwd)}"
    echo ""
    info "── Cline ──"

    # 检测 Cline MCP 配置位置
    local cline_config=""
    if [ -f "$HOME/.config/cline/cline_mcp_settings.json" ]; then
        cline_config="$HOME/.config/cline/cline_mcp_settings.json"
    elif [ -f "cline_mcp_settings.json" ]; then
        cline_config="$(pwd)/cline_mcp_settings.json"
    else
        # VS Code 全局设置
        local vscode_settings
        if [ "$(uname)" = "Darwin" ]; then
            vscode_settings="$HOME/Library/Application Support/Code/User/settings.json"
        elif [ "$(uname)" = "Linux" ]; then
            vscode_settings="$HOME/.config/Code/User/settings.json"
        fi

        if [ -f "$vscode_settings" ]; then
            # 备份
            if $BACKUP; then
                cp "$vscode_settings" "${vscode_settings}.$(date +%Y%m%d_%H%M%S).bak" 2>/dev/null || true
            fi

            # 合并到 VS Code settings
            python -c "
import json
with open('$vscode_settings') as f:
    cfg = json.load(f)
if 'cline.mcpServers' not in cfg:
    cfg['cline.mcpServers'] = {}
cfg['cline.mcpServers']['security-guardian-filesystem'] = {
    'command': 'python',
    'args': [
        '$PROXY_SCRIPT',
        '--upstream', '${UPSTREAM:-$DEFAULT_UPSTREAM}',
        '--policy', '$POLICY'
    ],
    'env': {'SG_AGENT_NAME': 'cline'},
    'disabled': False
}
with open('$vscode_settings', 'w') as f:
    json.dump(cfg, f, indent=2)
" 2>&1
            ok "已配置 VS Code 全局设置: $vscode_settings"
            return
        fi
    fi

    if [ -n "$cline_config" ]; then
        # 备份
        if $BACKUP && [ -f "$cline_config" ]; then
            cp "$cline_config" "${cline_config}.$(date +%Y%m%d_%H%M%S).bak"
            ok "已备份: ${cline_config}.bak"
        fi
        # 写入
        python -c "
import json
cfg = {
    'mcpServers': {
        'security-guardian-filesystem': {
            'command': 'python',
            'args': [
                '$PROXY_SCRIPT',
                '--upstream', '${UPSTREAM:-$DEFAULT_UPSTREAM}',
                '--policy', '$POLICY'
            ],
            'env': {'SG_AGENT_NAME': 'cline'},
            'disabled': False
        }
    }
}
with open('$cline_config', 'w') as f:
    json.dump(cfg, f, indent=2)
" 2>&1
        ok "已配置: $cline_config"
    else
        warn "未检测到 Cline 配置目录"
        warn "手动配置: 将 $TEMPLATES_DIR/cline-mcp.json 的内容添加到 VS Code settings.json 的 cline.mcpServers"
    fi
}

# ============================================================
# 配置 Cursor
# ============================================================
setup_cursor() {
    local workspace="${1:-$(pwd)}"
    echo ""
    info "── Cursor ──"

    local cursor_config=""
    if [ -f ".cursor/mcp.json" ]; then
        cursor_config="$(pwd)/.cursor/mcp.json"
    elif [ -d "$HOME/.cursor" ]; then
        cursor_config="$HOME/.cursor/mcp.json"
    fi

    if [ -n "$cursor_config" ]; then
        # 备份
        if $BACKUP && [ -f "$cursor_config" ]; then
            cp "$cursor_config" "${cursor_config}.$(date +%Y%m%d_%H%M%S).bak"
            ok "已备份: ${cursor_config}.bak"
        fi
        mkdir -p "$(dirname "$cursor_config")"
        python -c "
import json
cfg = {}
if open('$cursor_config', 'a') as f:
    pass
try:
    with open('$cursor_config') as f:
        content = f.read().strip()
    if content:
        cfg = json.loads(content)
except (json.JSONDecodeError, FileNotFoundError):
    cfg = {}
if 'mcpServers' not in cfg:
    cfg['mcpServers'] = {}
cfg['mcpServers']['security-guardian'] = {
    'command': 'python',
    'args': [
        '$PROXY_SCRIPT',
        '--upstream', '${UPSTREAM:-$DEFAULT_UPSTREAM}',
        '--policy', '$POLICY'
    ],
    'env': {'SG_AGENT_NAME': 'cursor'}
}
with open('$cursor_config', 'w') as f:
    json.dump(cfg, f, indent=2)
" 2>&1
        ok "已配置: $cursor_config"
    else
        warn "未检测到 Cursor 配置目录"
        warn "手动配置: Cursor → Settings → MCP Servers → Add Server"
        warn "参考: $TEMPLATES_DIR/cursor-mcp.json"
    fi
}

# ============================================================
# 验证配置
# ============================================================
verify_setup() {
    echo ""
    info "── 验证配置 ──"
    echo ""

    if [ -f "$HOME/.claude/settings.json" ]; then
        if grep -q "mcp_proxy.py" "$HOME/.claude/settings.json" 2>/dev/null; then
            ok "Claude Code: MCP Middleware 已接入"
        fi
    fi
    if [ -f ".claude/settings.local.json" ] && grep -q "mcp_proxy.py" ".claude/settings.local.json" 2>/dev/null; then
        ok "Claude Code (项目): MCP Middleware 已接入"
    fi

    # 测试代理是否可启动
    echo ""
    info "测试 MCP Middleware 启动..."
    if python -c "import sys; sys.path.insert(0, '$SCRIPT_DIR'); from mcp_proxy import HAS_SCAN_ENGINE; print(f'扫描引擎: {\"✅ 就绪\" if HAS_SCAN_ENGINE else \"❌ 缺失\"}')" 2>&1; then
        ok "MCP Middleware 可正常加载"
    else
        warn "MCP Middleware 加载异常: $?"
    fi

    echo ""
    ok "配置完成！现在启动 AI 编程 Agent 时，所有文件写入操作都会先经过安全扫描。"
    echo ""
    echo "快速测试:"
    echo "  # 查看今天拦截记录"
    echo "  ls -la ~/.security-guardian/audit/"
    echo ""
    echo "  # 查看代理状态"
    echo "  python $PROXY_SCRIPT --status"
}

# ============================================================
# 主流程
# ============================================================
main() {
    # ASCII 标题
    echo ""
    echo "  ╔═══════════════════════════════════════════╗"
    echo "  ║   Security Guardian MCP Middleware Setup  ║"
    echo "  ║   一键接入 AI 编程 Agent                   ║"
    echo "  ╚═══════════════════════════════════════════╝"
    echo ""

    check_deps

    IFS='|' read -r has_claude has_cline has_cursor <<< "$(detect_agents)"

    if $DO_LIST; then
        list_agents
        exit 0
    fi

    # 交互模式：询问用户选择
    if $INTERACTIVE; then
        list_agents

        if ! $has_claude && ! $has_cline && ! $has_cursor; then
            echo ""
            warn "未检测到任何 AI 编程 Agent"
            warn "将创建可复用的 MCP 配置模板供手动配置"
        fi

        echo ""
        echo "要配置哪些 Agent？"
        echo "  1) Claude Code $([ "$has_claude" = true ] && echo '✅' || echo '(未安装)')"
        echo "  2) Cline      $([ "$has_cline" = true ] && echo '✅' || echo '(未安装)')"
        echo "  3) Cursor     $([ "$has_cursor" = true ] && echo '✅' || echo '(未安装)')"
        echo "  4) 全部"
        echo "  0) 退出"
        echo ""
        read -rp "选择 [0-4]: " choice </dev/tty

        case "$choice" in
            1) INSTALL_CLAUDE=true ;;
            2) INSTALL_CLINE=true ;;
            3) INSTALL_CURSOR=true ;;
            4) INSTALL_CLAUDE=true; INSTALL_CLINE=true; INSTALL_CURSOR=true ;;
            0) echo "退出"; exit 0 ;;
            *) err "无效选择"; exit 1 ;;
        esac

        if [ -z "$UPSTREAM" ]; then
            echo ""
            echo "上游 MCP 服务器（直接回车用默认 filesystem）:"
            read -rp "上游命令 [$DEFAULT_UPSTREAM]: " upstream_input </dev/tty
            UPSTREAM="${upstream_input:-$DEFAULT_UPSTREAM}"
        fi

        if [ "$POLICY" = "normal" ]; then
            echo ""
            echo "策略模式 (normal/strict/relaxed) [normal]:"
            read -rp "策略 [$DEFAULT_POLICY]: " policy_input </dev/tty
            POLICY="${policy_input:-$DEFAULT_POLICY}"
        fi
    fi

    # 如果没有指定任何 Agent && 非交互模式 -> 配置所有检测到的
    if ! $INTERACTIVE && ! $INSTALL_CLAUDE && ! $INSTALL_CLINE && ! $INSTALL_CURSOR; then
        INSTALL_CLAUDE=$has_claude
        INSTALL_CLINE=$has_cline
        INSTALL_CURSOR=$has_cursor
    fi

    # 如果没有 Agent 被选中，但用户手动指定了 --claude/--cline/--cursor
    # 此时也走对应流程

    local workspace
    workspace="$(pwd)"

    # 设置默认 upstream（如果用户没指定）
    UPSTREAM="${UPSTREAM:-$DEFAULT_UPSTREAM}"

    $INSTALL_CLAUDE && setup_claude "$workspace"
    $INSTALL_CLINE && setup_cline "$workspace"
    $INSTALL_CURSOR && setup_cursor "$workspace"

    verify_setup

    # 提示启动方式
    echo ""
    echo "  使用 Claude Code 时: 输入 /reload-mcp 或重启会话"
    echo "  使用 Cline 时: 重启 VS Code"
    echo "  使用 Cursor 时: Cursor 自动检测 MCP 配置变更"
}

main "$@"
