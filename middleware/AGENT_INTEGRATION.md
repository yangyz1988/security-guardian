# Security Guardian MCP Middleware — AI Agent 集成指南

> 把 MCP 透明代理接入你的 AI 编程 Agent，实时拦截密钥和漏洞代码写入。

---

## 快速开始（推荐）

```bash
# 在 security-guardian 项目根目录执行
bash middleware/setup.sh
```

脚本会自动检测 Claude Code / Cline / Cursor，交互式配置 MCP 代理。

---

## 手动配置

### Claude Code

**全局配置** (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "python",
      "args": [
        "/ABSOLUTE/PATH/TO/security-guardian/middleware/mcp_proxy.py",
        "--upstream", "npx @modelcontextprotocol/server-filesystem /your/project",
        "--policy", "normal"
      ],
      "env": {
        "SG_AGENT_NAME": "claude-code"
      }
    }
  }
}
```

**项目级配置** (项目目录下 `.claude/settings.local.json`) — 同上，但路径建议用相对项目根。

配置完成后，重启 Claude Code 会话或输入 `/reload-mcp`。

---

### Cline (VS Code)

**方式 A: 独立 MCP 配置文件**

`~/.config/cline/cline_mcp_settings.json`:

```json
{
  "mcpServers": {
    "security-guardian-filesystem": {
      "command": "python",
      "args": [
        "/ABSOLUTE/PATH/TO/security-guardian/middleware/mcp_proxy.py",
        "--upstream", "npx @modelcontextprotocol/server-filesystem /your/project",
        "--policy", "normal"
      ],
      "env": {
        "SG_AGENT_NAME": "cline"
      },
      "disabled": false
    }
  }
}
```

**方式 B: VS Code 全局设置**

在 VS Code `settings.json` 中添加 `"cline.mcpServers"`:

```json
{
  "cline.mcpServers": {
    "security-guardian-filesystem": { /* 同上配置 */ }
  }
}
```

配置完成后重启 VS Code。

---

### Cursor

Cursor → Settings → MCP Servers → Add Server:

| 字段 | 值 |
|------|-----|
| Name | `security-guardian` |
| Type | `stdio` |
| Command | `python /ABSOLUTE/PATH/TO/security-guardian/middleware/mcp_proxy.py --upstream "npx @modelcontextprotocol/server-filesystem /workspace" --policy normal` |

或者创建 `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "security-guardian": {
      "command": "python",
      "args": [
        "/ABSOLUTE/PATH/TO/security-guardian/middleware/mcp_proxy.py",
        "--upstream", "npx @modelcontextprotocol/server-filesystem /workspace",
        "--policy", "normal"
      ],
      "env": {
        "SG_AGENT_NAME": "cursor"
      }
    }
  }
}
```

---

## 策略说明

| 策略 | 行为 | 适用场景 |
|------|------|---------|
| `relaxed` | 只记录日志，不阻止任何操作 | 评估阶段，先看看项目有多少问题 |
| `normal` | 阻止 critical，警告 high | **默认**，日常开发 |
| `strict` | 阻止 critical+high，警告 medium | CI/合规审计 |

---

## 环境变量

| 变量 | 作用 |
|------|------|
| `SG_BYPASS=1` | 临时跳过安全检查（紧急情况） |
| `SG_POLICY=strict` | 覆盖策略模式 |
| `SG_AGENT_NAME=claude-code` | 标记审计日志中的 Agent 来源 |
| `SG_LICENSE_KEY=SG-XXX-XXX` | 激活 Pro 功能 |

---

## 验证是否生效

```bash
# 1. 直接测试代理
python middleware/mcp_proxy.py --status

# 2. 查看审计日志（看看有没有拦截记录）
cat ~/.security-guardian/audit/$(date +%Y-%m-%d).jsonl

# 3. 强制测试：让 AI 写个含密钥的文件
# 正常的 MCP 工具流会触发扫描
```

---

## 预置配置模板

`middleware/config-templates/` 目录下有各 Agent 的 JSON 模板文件：

| 文件 | 适用 |
|------|------|
| `claude-code-mcp.json` | Claude Code MCP 配置 |
| `cline-mcp.json` | Cline MCP 配置 |
| `cursor-mcp.json` | Cursor MCP 配置 |
| `README.md` | 模板使用说明 |

使用前将 `${SG_ROOT}` 替换为 `security-guardian` 的绝对路径。

---

## 常见问题

### Q: 代理会影响正常读写吗？

不会。代理只扫描**写入**操作的内容。正常的代码读写、搜索、编译等操作直接透传，零延迟。

### Q: 我不想保护所有 MCP 服务器怎么办？

只把你关心的 MCP server 地址改成代理地址。其他 MCP 服务器保持原样。

### Q: 如何临时禁用？

```bash
SG_BYPASS=1 claude   # Claude Code 启动时绕过
# 或
export SG_BYPASS=1   # 当前终端绕过
```

### Q: 代理本身会写入我的代码吗？

不会。代理是一个纯检查层，不修改任何文件。所有拦截操作只返回错误提示，不自动修改代码。
