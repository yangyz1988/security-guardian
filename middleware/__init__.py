"""
Security Guardian MCP Middleware — AI 编程 Agent 代码安全层
============================================================

工作原理：
AI 编程 Agent（Claude Code / Cline / Cursor）通过 MCP 协议调用工具。
本中间件作为一个透明代理，拦截所有文件写入操作：

  1. AI Agent → 发出 write_file/edit_file 请求
  2. 中间件拦截请求，提取文件内容
  3. 调用 security-guardian 规则引擎扫描内容
  4. 根据策略决策：允许/警告/阻止
  5. 审计日志记录每次操作
  6. 允许的请求转发到上游 MCP 服务器

命令行用法：
  python -m middleware.mcp_proxy --upstream "python some-mcp-server.py"

或直接：
  python middleware/mcp_proxy.py --upstream "python some-mcp-server.py"
"""
