"""
Security Guardian MCP Middleware — AI Agent 配置示例

本文件包含如何将 MCP Middleware 接入主流 AI 编程 Agent 的配置示例。

## 通用启动方式

代理本身作为一个 MCP 工具服务器运行，站在你的 MCP 服务器前面：

```bash
# 代理访问文件系统
python middleware/mcp_proxy.py \\
    --upstream "npx @modelcontextprotocol/server-filesystem /your/project" \\
    --policy strict
```
"""

MARKDOWN_DOC = """# Security Guardian MCP Middleware — 集成指南

## 接入说明

MCP Middleware 是一个**透明代理**。你在 MCP 配置文件里把原 MCP 服务器地址
换成代理地址即可。代理会自动转发所有合法请求，只拦截含安全问题的不安全写入。

## 配置方式

### 方式一：Claude Code (hooks-settings.json)

```json
{
  "mcpServers": {
    "security-guardian": {
      "command": "python",
      "args": [
        "C:/Users/yangyz/一人AI公司/security-guardian/middleware/mcp_proxy.py",
        "--upstream", "npx @modelcontextprotocol/server-filesystem C:/workspace",
        "--policy", "normal"
      ]
    }
  }
}
```

放在 `~/.claude/settings.json` 或项目 `.claude/settings.local.json`。

### 方式二：Cline (cline_mcp_settings.json)

```json
{
  "mcpServers": {
    "security-guardian": {
      "command": "python",
      "args": [
        "C:/Users/yangyz/一人AI公司/security-guardian/middleware/mcp_proxy.py",
        "--upstream", "npx @modelcontextprotocol/server-filesystem C:/workspace",
        "--policy", "normal"
      ],
      "env": {
        "SG_POLICY": "strict"
      }
    }
  }
}
```

### 方式三：Cursor (cursor MCP)

在 Cursor 设置 → MCP Servers 中添加:

```
名称: security-guardian
类型: stdio
命令: python middleware/mcp_proxy.py --upstream "npx @modelcontextprotocol/server-filesystem /project" --policy normal
工作目录: C:/Users/yangyz/一人AI公司/security-guardian/
```

## 策略选择

| 策略 | 行为 | 适用场景 |
|------|------|---------|
| relaxed | 只记录，不阻止 | 评估阶段，了解问题量 |
| normal (默认) | 阻止 critical，警告 high | 日常使用 |
| strict | 阻止所有 critical+high，警告 medium | 合规审计 |

## 环境变量

| 变量 | 作用 |
|------|------|
| `SG_BYPASS=1` | 临时跳过安全检查 |
| `SG_POLICY=strict` | 覆盖策略模式 |
| `SG_AGENT_NAME=claude-code` | 标记审计日志中的 Agent 来源 |
"""

print(MARKDOWN_DOC)
