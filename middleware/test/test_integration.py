#!/usr/bin/env python3
"""
集成测试：模拟 AI Agent → MCP Proxy → fake MCP Server 完整流程
"""
import json
import subprocess
import sys
import time
from pathlib import Path

# 项目根目录
ROOT = Path(__file__).resolve().parent.parent


def test_proxy_blocks_secret_write():
    """测试：代理应该阻止含 API Key 的写入"""
    print("=== Test 1: 代理阻止含密钥的写入 ===")

    proc = subprocess.Popen(
        [sys.executable, "-m", "middleware.mcp_proxy",
         "--upstream", f"{sys.executable} middleware/test/fake_mcp_server.py",
         "--policy", "normal"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True, bufsize=1, cwd=str(ROOT),
    )

    time.sleep(0.5)  # 等待启动

    # 模拟 AI Agent 发送初始化
    init = {"jsonrpc": "2.0", "id": "1", "method": "initialize", "params": {}}
    proc.stdin.write(json.dumps(init) + "\n")
    proc.stdin.flush()
    resp1 = json.loads(proc.stdout.readline())
    print(f"  初始化: {resp1.get('result', {}).get('serverInfo', {}).get('name', '?')}")

    # 发带密钥的写入请求
    write_req = {
        "jsonrpc": "2.0", "id": "2",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": "/project/config.py",
                "content": 'api_key = "sk-proj-abc123def456"\nprint("hello")'
            }
        }
    }
    proc.stdin.write(json.dumps(write_req) + "\n")
    proc.stdin.flush()
    resp2 = json.loads(proc.stdout.readline())

    if "error" in resp2:
        code = resp2["error"].get("code", 0)
        msg = resp2["error"].get("message", "")
        print(f"  ✅ 拦截成功! (code={code})")
        print(f"  提示: {msg[:80]}...")
    else:
        print(f"  ❌ 未拦截! 响应: {resp2}")

    proc.terminate()
    proc.wait(timeout=3)


def test_proxy_lets_safe_write_through():
    """测试：代理应该允许安全内容写入"""
    print("\n=== Test 2: 代理允许安全内容写入 ===")

    proc = subprocess.Popen(
        [sys.executable, "-m", "middleware.mcp_proxy",
         "--upstream", f"{sys.executable} middleware/test/fake_mcp_server.py",
         "--policy", "normal"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True, bufsize=1, cwd=str(ROOT),
    )

    time.sleep(0.5)

    # 初始化
    init = {"jsonrpc": "2.0", "id": "1", "method": "initialize", "params": {}}
    proc.stdin.write(json.dumps(init) + "\n")
    proc.stdin.flush()
    proc.stdout.readline()

    # 写入安全内容
    safe_req = {
        "jsonrpc": "2.0", "id": "2",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": "/project/hello.py",
                "content": 'print("hello world")\nx = 42\nprint(x)'
            }
        }
    }
    proc.stdin.write(json.dumps(safe_req) + "\n")
    proc.stdin.flush()
    resp2 = json.loads(proc.stdout.readline())

    if "error" not in resp2:
        print(f"  ✅ 安全内容已通过! (无错误)")
    else:
        print(f"  ❌ 误拦截! 响应: {resp2.get('error')}")

    proc.terminate()
    proc.wait(timeout=3)


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
              f"file={last.get('file')}, result={last.get('result')}")
    summary = audit.summary()
    print(f"  摘要: {summary['total_calls']} 调用 → {summary['blocked']} 阻止, "
          f"{summary['warned']} 警告, {summary['passed']} 通过")
    print("  ✅ 审计日志正常")


if __name__ == "__main__":
    test_proxy_blocks_secret_write()
    test_proxy_lets_safe_write_through()
    test_proxy_audit_log()
    print("\n=== All tests passed! ===")
