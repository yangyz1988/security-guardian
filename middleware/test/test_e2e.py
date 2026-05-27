#!/usr/bin/env python3
"""Security Guardian MCP Middleware — E2E 测试"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

test_input = (
    '{"jsonrpc":"2.0","id":"1","method":"initialize","params":{}}\n'
    '{"jsonrpc":"2.0","id":"2","method":"tools/list","params":{}}\n'
    '{"jsonrpc":"2.0","id":"3","method":"tools/call",'
    '"params":{"name":"write_file","arguments":{"path":"/safe.py","content":"print(42)"}}}\n'
    '{"jsonrpc":"2.0","id":"4","method":"tools/call",'
    '"params":{"name":"write_file","arguments":{"path":"/secret.py",'
    '"content":"x=\\"sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefgh\\""}}}\\n'
    '{"jsonrpc":"2.0","id":"5","method":"tools/call",'
    '"params":{"name":"read_file","arguments":{"path":"/read.py"}}}\n'
)

proc = subprocess.Popen(
    [sys.executable, str(ROOT / "middleware" / "mcp_proxy.py"),
     "--upstream", f"{sys.executable} middleware/test/fake_mcp_server.py",
     "--policy", "normal"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    text=True, cwd=str(ROOT),
)

stdout, stderr = proc.communicate(input=test_input, timeout=15)

print("=" * 60)
print("E2E TEST: Security Guardian MCP Middleware")
print("=" * 60)

lines = [l for l in stdout.strip().split("\n") if l.strip()]
print(f"\n📤 5 requests → 📥 {len(lines)} responses\n")

test4_blocked = False
for line in lines:
    data = json.loads(line)
    mid = data.get("id", "?")
    if "error" in data:
        print(f"  ❌ ID={mid}: BLOCKED")
        print(f"     {data['error']['message'][:100]}...")
        if mid == "4":
            test4_blocked = True
    elif "result" in data:
        r = data["result"]
        if "tools" in r:
            print(f"  ✅ ID={mid}: tools → {[t['name'] for t in r['tools']]}")
        elif "serverInfo" in r:
            print(f"  ✅ ID={mid}: init → {r['serverInfo']['name']}")
        else:
            print(f"  ✅ ID={mid}: ok")

sg_lines = [l.strip() for l in stderr.split("\n") if "[SG]" in l]
print(f"\n📋 Proxy log:")
for l in sg_lines:
    print(f"  {l}")

print()
if test4_blocked:
    print("🎉 PASS: Secret write was BLOCKED as expected!")
else:
    print("⚠️  FAIL: Secret write was NOT blocked — check regex matching")

# Verify safe write still works
test3_safe = any(
    json.loads(l).get("id") == "3" and "result" in json.loads(l)
    for l in lines
)
print("📝 Safe write passed:", "✅" if test3_safe else "❌")

print("=" * 60)
