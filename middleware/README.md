# Security Guardian MCP Middleware

> **AI 编程 Agent 的代码安全层** — 在 AI 写文件时实时扫描并拦截密钥/漏洞代码。

## 解决的问题

你用 Claude Code / Cline / Cursor 写代码，让 AI 加个 API Key：

```
你: "帮我加个 OpenAI API Key"
AI: 写入 api_key = "sk-***"
     ↓
中间件: 🚨 检测到密钥! 已阻止!
        💡 建议改成环境变量
```

**没有中间件** → 密钥明文写入文件 → commit → push → 等着 GitHub 发安全告警
**有中间件** → AI 刚要写入 → 被拦截 → 提示改成安全写法

## 快速开始

```bash
# 自动检测并配置 AI 编程 Agent（推荐）
cd security-guardian/
bash middleware/setup.sh

# 或手动配置：将代理挡在 filesystem MCP 前面测试
python middleware/mcp_proxy.py \
    --upstream "npx @modelcontextprotocol/server-filesystem /your/project" \
    --policy normal
```

## 使用场景

| 你的 AI 工具 | 怎么连 | 配置位置 |
|-------------|--------|---------|
| Claude Code | MCP 配置 | `~/.claude/settings.json` |
| Cline (VS Code) | MCP 配置 | `cline_mcp_settings.json` |
| Cursor | MCP 设置 | Settings → MCP Servers |
| 任何 MCP 客户端 | 任何 MCP 服务器 | 把原地址换成代理地址 |

**一键配置**: 运行 `bash middleware/setup.sh` 自动检测并配置。

**预置模板**: `middleware/config-templates/` 下有各 Agent 的 JSON 模板。

详见 `middleware/AGENT_INTEGRATION.md`。

## 策略模式

```
normal  (默认): 阻止 critical 级别，警告 high 级别
strict         : 阻止所有 critical + high
relaxed        : 只记录日志，不阻止任何操作
```

## 审计日志

所有操作自动记录到 `~/.security-guardian/audit/YYYY-MM-DD.jsonl`：

```json
{"timestamp":"2026-05-27T16:11:14","tool":"write_file",
 "action":"block","findings_count":1,"max_severity":"critical",
 "file":"/bad.py"}
```

### 查看今日审计

```bash
cat ~/.security-guardian/audit/$(date +%Y-%m-%d).jsonl
```

## 与 security-guardian 的关系

```
security-guardian (已有的 CLI 扫描工具):
  └─ 事后扫描: 手动跑 python scan.py 检查代码

MCP Middleware (新增的实时拦截层):
  └─ 实时拦截: AI 写文件时自动扫描并阻止
```

**它们共享同一个规则引擎**（65+ 条安全规则）。加一个等于同时推进两个。

## 变现方式

| 等级 | 价格 | 功能 |
|------|------|------|
| 免费 | $0 | 核心拦截 + 审计日志 |
| Pro | $29/月 | SARIF/HTML 报告 + 自动修复 + 自定义规则 |
| Team | $99/月/5人 | 多项目管理 + 合规趋势 + 飞书/Slack 推送 |

## 技术架构

```
AI Agent ──→ [MCP Proxy (透明代理)] ──→ [上游 MCP 服务器]
                  │
            ┌─────┴─────┐
            │ 规则引擎    │
            │ 策略决策    │
            │ 审计日志    │
            └────────────┘
```

## 项目结构

```
security-guardian/
├── middleware/
│   ├── mcp_proxy.py           # MCP 透明代理（核心）
│   ├── policy_engine.py       # 策略决策引擎
│   ├── audit_logger.py        # 审计日志
│   ├── config.py              # 配置管理
│   ├── license.py             # License Key 校验
│   ├── setup.sh               # ✨ 一键接入 AI 编程 Agent
│   ├── AGENT_INTEGRATION.md   # AI Agent 集成指南
│   ├── config-templates/      # 预置配置模板
│   │   ├── claude-code-mcp.json
│   │   ├── cline-mcp.json
│   │   └── cursor-mcp.json
│   └── test/                  # 测试
├── scripts/
│   ├── scan.py                # 安全扫描引擎（65+ 规则）
│   └── ...
└── adapters/                  # 多平台适配器（旧版扫描集成）
```

## 测试

```bash
# 单元测试
python middleware/test/test_e2e.py

# 手动测试: 拦截含密钥的写入
echo '{"jsonrpc":"2.0","id":"1","method":"tools/call",\
"params":{"name":"write_file",\
"arguments":{"path":"/bad.py","content":"x=\\"sk-ABC...XYZ\\""}}}}' \
| python middleware/mcp_proxy.py --upstream "python middleware/test/fake_mcp_server.py"
```
