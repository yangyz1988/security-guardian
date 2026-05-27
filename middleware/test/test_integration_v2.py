#!/usr/bin/env python3
"""
集成测试 v2：使用 PIPE 而非 stdin 写入，用 communicate 替代。
"""
import json
import subprocess
import sys
import time
from pathlib import Path

# 项目根目录：test_integration_v2.py → middleware/test/ → middleware/ → security-guardian/
ROOT = Path(__file__).resolve().parent.parent.parent
PROXY_CMD = [sys.executable, str(ROOT / "middleware" / "mcp_proxy.py"),
             "--upstream", f"{sys.executable} middleware/test/fake_mcp_server.py",
             "--policy", "normal"]

# 代理的 CWD 设到项目根，让上游服务器的相对路径能正确解析
PROXY_CWD = str(ROOT)


def send_and_recv(proc, req_msg, timeout=10):
    """发送请求到代理进程并读取响应"""
    line = json.dumps(req_msg) + "\n"
    proc.stdin.write(line)
    proc.stdin.flush()

    start = time.time()
    while time.time() - start < timeout:
        import select
        if hasattr(select, "select"):
            # Windows 可能不支持 select on pipes
            pass
        resp_line = proc.stdout.readline()
        if resp_line:
            try:
                return json.loads(resp_line.strip())
            except json.JSONDecodeError:
                continue
        time.sleep(0.1)
    return None


def run_test():
    print("=" * 60)
    print("Security Guardian MCP Middleware 集成测试")
    print("=" * 60)

    # 启动代理
    print("\n[启动] MCP Proxy...")
    proc = subprocess.Popen(
        PROXY_CMD,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True, bufsize=1, cwd=PROXY_CWD,
    )
    time.sleep(1.0)  # 等启动

    # 检查进程活着
    if proc.poll() is not None:
        stderr_out = proc.stderr.read()
        print(f"❌ 代理进程已退出! stderr: {stderr_out[:200]}")
        return False

    try:
        # Test 1: 初始化
        print("\n[Test 1] 初始化...")
        init = {"jsonrpc": "2.0", "id": "1", "method": "initialize", "params": {}}
        proc.stdin.write(json.dumps(init) + "\n")
        proc.stdin.flush()
        resp = proc.stdout.readline()
        data = json.loads(resp.strip())
        print(f"  结果: {data.get('result', {}).get('serverInfo', {}).get('name', '?')}")
        assert "result" in data, "初始化失败"
        print("  ✅ 初始化通过")

        # Test 2: 工具列表
        print("\n[Test 2] 获取工具列表...")
        list_req = {"jsonrpc": "2.0", "id": "2", "method": "tools/list", "params": {}}
        proc.stdin.write(json.dumps(list_req) + "\n")
        proc.stdin.flush()
        resp = proc.stdout.readline()
        data = json.loads(resp.strip())
        tools = data.get("result", {}).get("tools", [])
        print(f"  工具有: {[t['name'] for t in tools]}")
        assert len(tools) > 0, "工具列表为空"
        print("  ✅ 工具列表通过")

        # Test 3: 安全内容写入 → 应通过
        print("\n[Test 3] 安全内容写入 (期望: 通过)...")
        safe_req = {
            "jsonrpc": "2.0", "id": "3",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "/project/hello.py", "content": 'print("hello")'}
            }
        }
        proc.stdin.write(json.dumps(safe_req) + "\n")
        proc.stdin.flush()
        resp = proc.stdout.readline()
        data = json.loads(resp.strip())
        assert "error" not in data, f"误拦截: {data.get('error', {}).get('message', '')[:60]}"
        print("  ✅ 安全内容正确通过")

        # Test 4: 含密钥的写入 → 应阻止
        print("\n[Test 4] 含密钥写入 (期望: 阻止)...")
        secret_req = {
            "jsonrpc": "2.0", "id": "4",
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "/project/secret.py", "content": 'api_key = "sk-pro..."'}
            }
        }
        proc.stdin.write(json.dumps(secret_req) + "\n")
        proc.stdin.flush()
        resp = proc.stdout.readline()
        data = json.loads(resp.strip())
        assert "error" in data, "密钥写入未被阻止!"
        print(f"  ✅ 密钥写入被阻止")
        print(f"  提示信息: {data['error']['message'][:80]}...")

        # Test 5: 读文件
        print("\n[Test 5] 读操作审计 (期望: 通过+记录)...")
        read_req = {
            "jsonrpc": "2.0", "id": "5",
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/project/safe.py"}
            }
        }
        proc.stdin.write(json.dumps(read_req) + "\n")
        proc.stdin.flush()
        resp = proc.stdout.readline()
        data = json.loads(resp.strip())
        assert "error" not in data, f"读操作被错误拦截: {data}"
        print("  ✅ 读操作正确通过")

        print("\n" + "=" * 60)
        print("🎉 全部 5 个测试通过!")
        print("=" * 60)
        return True

    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        print("\n[清理] 停止代理...")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)
