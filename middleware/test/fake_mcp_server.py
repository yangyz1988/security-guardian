#!/usr/bin/env python3
"""
测试用假 MCP 服务器 — 模拟一个文件系统工具服务。
接受 write_file 请求并返回成功（假装写入了）。
"""
import json
import sys


def handle(line):
    msg = json.loads(line)
    method = msg.get("method", "")
    mid = msg.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0", "id": mid,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "test-filesystem", "version": "1.0.0"}
            }
        }
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0", "id": mid,
            "result": {
                "tools": [
                    {
                        "name": "write_file",
                        "description": "Write content to a file",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                                "content": {"type": "string"}
                            }
                        }
                    },
                    {
                        "name": "read_file",
                        "description": "Read content from a file",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"}
                            }
                        }
                    }
                ]
            }
        }
    elif method == "tools/call":
        params = msg.get("params", {})
        name = params.get("name", "")
        args = params.get("arguments", {})
        if name == "write_file":
            return {
                "jsonrpc": "2.0", "id": mid,
                "result": {
                    "content": [{"type": "text", "text": f"Written {args.get('path', '?')}"}]
                }
            }
        elif name == "read_file":
            return {
                "jsonrpc": "2.0", "id": mid,
                "result": {
                    "content": [{"type": "text", "text": "file content with no secrets"}]
                }
            }
        else:
            return {
                "jsonrpc": "2.0", "id": mid,
                "result": {"content": [{"type": "text", "text": "ok"}]}
            }
    elif method == "notifications/initialized":
        return None  # notification, no response
    else:
        return {"jsonrpc": "2.0", "id": mid, "result": {}}


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    response = handle(line)
    if response:
        print(json.dumps(response), flush=True)
