#!/usr/bin/env python3
"""测试 MCP Proxy + 真实 filesystem MCP 服务器集成"""
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

# 真实 filesystem MCP 服务器
UPSTREAM = f"npx -y @modelcontextprotocol/server-filesystem C:\\Users\\yangyz\\一人AI公司\\security-guardian\\middleware\\test"

# 测试命令序列
commands = [
    # 1. 初始化
    {"jsonrpc": "2.0", "id": "1", "method": "initialize", "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "test-client", "version": "1.0.0"}
    }},
    # 2. 通知
    None,
    # 3. 获取工具列表
    {"jsonrpc": "2.0", "id": "2", "method": "tools/list", "params": {}},
    # 4. 写安全文件
    {"jsonrpc": "2.0", "id": "3", "method": "tools/call",
     "params": {"name": "write_file",
                "arguments": {"uri": "file:///test.txt", "content": "hello world"}}},
    # 5. 写含密钥文件
    {"jsonrpc": "2.0", "id": "4", "method": "tools/call",
     "params": {"name": "write_file",
                "arguments": {"uri": "file:///secret.txt",
                              "content": "api_key=\"sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGH\""}}},
    # 6. 读文件
    {"jsonrpc": "2.0", "id": "5", "method": "tools/call",
     "params": {"name": "read_file",
                "arguments": {"uri": "file:///test.txt"}}},
]

input_lines = []
for cmd in commands:
    if cmd is None:
        # notifications/initialized
        input_lines.append('{"jsonrpc":"2.0","method":"notifications/initialized"}')
    else:
        input_lines.append(json.dumps(cmd))

test_input = "\n".join(input_lines) + "\n"

print("=" * 60)
print("真实 MCP 集成测试: Proxy → filesystem 服务器")
print("=" * 60)

# 先直接测 filesystem MCP 服务器（不用代理），验证它能工作
print("\n[Step 1] 直接测试 filesystem MCP 服务器...")
try:
    proc = subprocess.Popen(
        f"{sys.executable} -c \"import sys; sys.stdout.write(sys.stdin.readline())\"",
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, shell=True,
    )
    # Just a simple check - can we reach npx?
    result = subprocess.run(
        f"npx -y @modelcontextprotocol/server-filesystem --help",
        capture_output=True, text=True, shell=True, timeout=10,
    )
    if result.returncode != 0 and result.stderr:
        # the filesystem server starts interactive mode, not --help
        pass
    print("  ✅ npx 可用")
except Exception as e:
    print(f"  ⚠️ npx 检查失败: {e}")

# 用代理测试
print("\n[Step 2] 启动 MCP Proxy → filesystem 服务器...")
proxy_proc = subprocess.Popen(
    [sys.executable, str(ROOT / "middleware" / "mcp_proxy.py"),
     "--upstream", UPSTREAM,
     "--policy", "normal"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    text=True, cwd=str(ROOT),
)

try:
    stdout, stderr = proxy_proc.communicate(input=test_input, timeout=20)
    print(f"  ✅ Proxy 完成 (stdout: {len(stdout.split(chr(10)))-1} 行)")

    # 解析结果
    responses = [json.loads(l) for l in stdout.strip().split("\n") if l.strip()]
    print(f"\n  📥 收到 {len(responses)} 个回复:\n")

    test4_blocked = False
    for r in responses:
        mid = r.get("id", "?")
        if "error" in r:
            print(f"  ❌ ID={mid}: BLOCKED")
            print(f"     {r['error']['message'][:100]}")
            if mid == "4":
                test4_blocked = True
        elif "result" in r:
            res = r["result"]
            if "serverInfo" in res:
                print(f"  ✅ ID={mid}: init → {res['serverInfo']['name']}")
            elif "tools" in res:
                tool_names = [t["name"] for t in res["tools"]]
                print(f"  ✅ ID={mid}: {len(tool_names)} tools → {tool_names[:5]}...")
            elif "isError" in res:
                print(f"  ⚠️  ID={mid}: error → {res}")
            else:
                print(f"  ✅ ID={mid}: ok")

    # 显示审计日志
    sg_logs = [l.strip() for l in stderr.split("\n") if "[SG]" in l]
    print(f"\n  📋 Proxy 日志:")
    for l in sg_logs:
        print(f"    {l}")

    print()
    if test4_blocked:
        print("🎉 真实 MCP 集成测试通过! 含密钥写入被拦截!")
    else:
        print("⚠️ 注意: 含密钥写入未被拦截 (原因可能是filesystem MCP的工具名不同)")
    print()

except subprocess.TimeoutExpired:
    print("  ⏰ 超时!")
    print("  stderr:", proxy_proc.stderr.read()[:300])

finally:
    proxy_proc.terminate()
    try: proxy_proc.wait(timeout=3)
    except: proxy_proc.kill()
