#!/usr/bin/env python3
"""
Security Guardian — Cline MCP Server 包装器
将 scan.py 和 fix.py 暴露为 MCP tools，供 Cline/Caveman 调用。

用法:
  python security-guardian-mcp.py

MCP 协议:
  - stdio transport
  - tools: scan, fix
"""

import sys
import json
import subprocess
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "scripts"


def handle_request(request: dict) -> dict:
    """处理 MCP 请求"""
    method = request.get("method", "")
    req_id = request.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "security-guardian",
                    "version": "0.3.0"
                }
            }
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "security_scan",
                        "description": "Scan project for security vulnerabilities (secrets, OWASP, dependencies, Docker, config)",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string", "description": "Project path to scan"},
                                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"], "description": "Minimum severity level"},
                                "output": {"type": "string", "enum": ["markdown", "json", "sarif", "html"], "description": "Output format"}
                            }
                        }
                    },
                    {
                        "name": "security_fix",
                        "description": "Auto-fix security issues with dry-run preview",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string", "description": "Project path to fix"},
                                "apply": {"type": "boolean", "description": "Apply fixes (default: dry-run preview only)"}
                            }
                        }
                    }
                ]
            }
        }

    if method == "tools/call":
        params = request.get("params", {})
        tool_name = params.get("name", "")
        args = params.get("arguments", {})

        if tool_name == "security_scan":
            return _run_scan(args, req_id)
        if tool_name == "security_fix":
            return _run_fix(args, req_id)

        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}}

    if method == "notifications/initialized":
        return None  # No response for notifications

    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}}


def _run_scan(args: dict, req_id) -> dict:
    """执行 scan.py"""
    cmd = [sys.executable, str(SCRIPTS_DIR / "scan.py")]
    path = args.get("path", ".")
    severity = args.get("severity", "high")
    output = args.get("output", "json")

    cmd.extend(["--path", path, "--severity", severity, "--output", output])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": result.stdout or result.stderr or "Scan complete (no findings)"}]
            }
        }
    except Exception as e:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": f"Scan error: {str(e)}"}]
            }
        }


def _run_fix(args: dict, req_id) -> dict:
    """执行 fix.py"""
    cmd = [sys.executable, str(SCRIPTS_DIR / "fix.py")]
    path = args.get("path", ".")
    apply_fix = args.get("apply", False)

    cmd.extend(["--path", path])
    if apply_fix:
        cmd.append("--apply")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": result.stdout or result.stderr or "Fix complete"}]
            }
        }
    except Exception as e:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": f"Fix error: {str(e)}"}]
            }
        }


def main():
    """MCP stdio 主循环"""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            response = handle_request(request)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError:
            continue


if __name__ == "__main__":
    main()
