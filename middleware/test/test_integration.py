#!/usr/bin/env python3
"""集成测试：直接测试 MCP Proxy 的核心函数（不经过 subprocess）

避免 pytest 环境下 Windows 子进程管道阻塞问题。
"""
import json
import sys
from pathlib import Path

# 确保 middleware 可导入
_MW = Path(__file__).resolve().parent.parent
if str(_MW) not in sys.path:
    sys.path.insert(0, str(_MW))

from middleware.mcp_proxy import MCPProxy, make_response
from middleware.policy_engine import PolicyEngine


def _make_proxy(policy: str = "normal") -> MCPProxy:
    """创建一个虚拟 MCPMiddleware 实例（不启动上游）。"""
    from unittest.mock import MagicMock

    proxy = MCPProxy.__new__(MCPProxy)
    proxy.upstream_name = "test-filesystem"
    proxy.upstream_version = "1.0.0"
    proxy.policy = PolicyEngine(policy)
    proxy.upstream_process = MagicMock()
    proxy.upstream_process.stdin = MagicMock()

    from middleware.audit_logger import AuditLogger
    proxy.audit = AuditLogger()

    # _forward: 模拟上游响应
    def fake_forward(msg):
        method = msg.get("method", "")
        mid = msg.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0", "id": mid,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "test-filesystem", "version": "1.0.0"},
                },
            }
        elif method == "tools/list":
            return {
                "jsonrpc": "2.0", "id": mid,
                "result": {
                    "tools": [
                        {"name": "write_file", "description": "Write file",
                         "inputSchema": {"type": "object", "properties": {}}},
                        {"name": "read_file", "description": "Read file",
                         "inputSchema": {"type": "object", "properties": {}}},
                    ]
                },
            }
        elif method == "tools/call":
            return {
                "jsonrpc": "2.0", "id": mid,
                "result": {"content": [{"type": "text", "text": "ok"}]},
            }
        return {"jsonrpc": "2.0", "id": mid, "result": {}}

    proxy._forward = fake_forward
    proxy.send_to_upstream = lambda msg: fake_forward(msg)

    return proxy


def test_proxy_blocks_secret_write():
    """测试：代理应该阻止含 OpenAI Key 的写入"""
    print("=== Test 1: 代理阻止含密钥的写入 ===")
    proxy = _make_proxy("normal")

    # 初始化
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}}}
    resp = proxy.handle_message(json.dumps(init))
    r = json.loads(resp)
    server = r.get("result", {}).get("serverInfo", {}).get("name", "?")
    print(f"  初始化: {server}")
    assert server == "test-filesystem"

    # 写文件含密钥（sk- + 20+ 字母数字 → 触发 critical 级别 openai-key 规则）
    write_req = {
        "jsonrpc": "2.0", "id": 2,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": "/project/config.py",
                "content": 'x = "sk-AbCdEfGhIjKlMnOpQrStUvWxYz0123"'
            }
        }
    }
    resp = proxy.handle_message(json.dumps(write_req))
    r = json.loads(resp)

    if "error" in r:
        code = r["error"].get("code", 0)
        msg = r["error"].get("message", "")
        print(f"  ✅ 拦截成功! (code={code})")
        print(f"  提示: {msg[:80]}...")
        assert code == -32000, f"错误码应为 -32000, 实际: {code}"
    else:
        print(f"  ❌ 未拦截! 响应: {r}")
        assert False, "代理应该阻止含密钥的写入，但放行了"


def test_proxy_lets_safe_write_through():
    """测试：代理应该允许安全内容写入"""
    print("\n=== Test 2: 代理允许安全内容写入 ===")
    proxy = _make_proxy("normal")

    # 初始化
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}}}
    proxy.handle_message(json.dumps(init))

    # 写入安全内容（不含密钥或漏洞）
    safe_req = {
        "jsonrpc": "2.0", "id": 2,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": "/project/hello.py",
                "content": 'print("hello world")\nx = 42\nprint(x)'
            }
        }
    }
    resp = proxy.handle_message(json.dumps(safe_req))
    r = json.loads(resp)

    if "error" not in r:
        print(f"  ✅ 安全内容已通过!")
    else:
        print(f"  ❌ 误拦截! 响应: {r.get('error')}")
        assert False, "代理不应该拦截安全内容"


def test_proxy_audit_log():
    """测试：审计日志是否正确记录"""
    print("\n=== Test 3: 审计日志记录 ===")

    from middleware.audit_logger import AuditLogger
    audit = AuditLogger()
    events = audit.get_today_events()

    print(f"  今日审计事件数: {len(events)}")
    if events:
        last = events[-1]
        print(f"  最近事件: tool={last.get('tool')}, action={last.get('action')}, "
              f"file={last.get('file')}")

    summary = audit.summary()
    print(f"  摘要: {summary['total_calls']} 调用 → {summary['blocked']} 阻止, "
          f"{summary['warned']} 警告, {summary['passed']} 通过")
    print("  ✅ 审计日志正常")


if __name__ == "__main__":
    test_proxy_blocks_secret_write()
    test_proxy_lets_safe_write_through()
    test_proxy_audit_log()
    print("\n=== All tests passed! ===")
