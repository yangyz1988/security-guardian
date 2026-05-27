# MCP Middleware — 配置模板

> 使用前用 `setup.sh` 自动配置，或手动复制以下模板。

## 用法

每个模板中的 `${SG_ROOT}` 和 `${WORKSPACE}` 是占位符，需要替换为实际路径。

### 自动配置（推荐）

```bash
bash middleware/setup.sh
```

### 手动配置

1. 找到对应模板文件
2. 将 `${SG_ROOT}` 替换为 `security-guardian` 的**绝对路径**
3. 将 `${WORKSPACE}` 替换为你的项目工作目录
4. 将配置内容复制到对应 Agent 的 MCP 配置中

---

## 文件清单

| 文件 | 适用于 | 配置文件位置 |
|------|--------|-------------|
| `claude-code-mcp.json` | Claude Code | `~/.claude/settings.json` 或 `.claude/settings.local.json` |
| `cline-mcp.json` | Cline (VS Code) | VS Code `settings.json` → `cline.mcpServers` |
| `cursor-mcp.json` | Cursor | Cursor Settings → MCP Servers |
