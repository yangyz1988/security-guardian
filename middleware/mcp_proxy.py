#!/usr/bin/env python3
"""
Security Guardian MCP Middleware — MCP 透明代理
"""
import json
import os
import shlex
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Optional

# 确保项目根可导入（dev 和 pip 两种模式）
_mw_dir = Path(__file__).resolve().parent
_project_root = _mw_dir.parent
for d in [str(_project_root), str(_mw_dir)]:
    if d not in sys.path:
        sys.path.insert(0, d)

# 导入组件
import hashlib
from scripts.scan import scan_secrets, scan_owasp, Finding
from middleware.policy_engine import PolicyEngine, PolicyMode, should_block, PolicyAction
from middleware.audit_logger import AuditLogger
from middleware.config import load_config, get_default_config_path
from middleware import license as lic

HAS_SCAN_ENGINE = True
WRITE_TOOLS = {
    "write_file", "edit_file", "create_file",
    "apply_diff", "patch_file", "overwrite_file",
    "append_file", "create", "write",
}
READ_TOOLS = {"read_file", "read", "get_file", "search_files", "grep"}
MCP_PROTOCOL_VERSION = "2024-11-05"


def make_response(req_id, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": req_id}
    if error:
        msg["error"] = error
    else:
        msg["result"] = result or {}
    return msg


def scan_content(content: str, filepath: str) -> list:
    findings = []
    try:
        findings.extend(scan_secrets(content, filepath))
        findings.extend(scan_owasp(content, filepath))
    except Exception:
        pass
    return findings


def max_severity(findings: list) -> str:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
    best = "none"
    for f in findings:
        if order.get(f.severity, 99) < order.get(best, 99):
            best = f.severity
    return best


class MCPProxy:
    """MCP 透明代理"""

    def __init__(self, upstream_command: str, policy_mode: str = "normal",
                 audit_dir: str = None, config: dict = None):
        self.upstream_command = upstream_command
        self.upstream_process = None
        self.policy = PolicyEngine(policy_mode)
        self.audit = AuditLogger(audit_dir)
        self.config = config or {}
        self.upstream_name = "unknown"
        self.upstream_version = "0.0.0"

        for exc in self.config.get("exceptions", []):
            try:
                self.policy.add_exception(exc.get("pattern", ""),
                                          PolicyAction(exc.get("action", "pass")))
            except Exception:
                pass

    def start_upstream(self):
        print(f"[SG] 🚀 启动上游 MCP: {self.upstream_command}", file=sys.stderr)
        try:
            if os.name == "nt":
                # Windows: 用 subprocess.list2cmdline 做正确转义
                cmd = self.upstream_command
                self.upstream_process = subprocess.Popen(
                    cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, bufsize=1, shell=True,
                )
            else:
                cmd = shlex.split(self.upstream_command)
                self.upstream_process = subprocess.Popen(
                    cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, bufsize=1,
                )
        except Exception as e:
            print(f"[SG] ❌ 无法启动: {e}", file=sys.stderr)
            sys.exit(1)

    def send_to_upstream(self, message: dict) -> dict:
        if not self.upstream_process or not self.upstream_process.stdin:
            return None
        self.upstream_process.stdin.write(json.dumps(message) + "\n")
        self.upstream_process.stdin.flush()
        line = self.upstream_process.stdout.readline()
        return json.loads(line.strip()) if line else None

    def _handle_write_tool(self, msg, tool_name, file_path, content):
        findings = scan_content(content, file_path)
        severity = max_severity(findings)
        blocked, reason = should_block(findings, self.policy)
        action_taken = "block" if blocked else "warn" if severity in ("critical", "high") else "pass"

        self.audit.log(tool=tool_name, file_path=file_path, action=action_taken,
                       findings_count=len(findings), severity=severity,
                       details=reason if blocked else None)

        if findings:
            level = "🔴" if blocked else "🟡"
            print(f"[SG] {level} {tool_name} -> {file_path}", file=sys.stderr)
            print(f"[SG]    {len(findings)} 个问题 (最高: {severity})", file=sys.stderr)
            for f in findings[:3]:
                print(f"[SG]    • [{f.severity}] {f.rule_id}: {f.message[:60]}", file=sys.stderr)

        if blocked:
            error_msg = (
                f"Security Guardian blocked {tool_name}: "
                f"Detection of {findings[0].rule_id} in {file_path}.\n"
                f"⚠️  {findings[0].message}\n"
                f"💡  {findings[0].fix_suggestion}\n"
                f"Use SG_BYPASS=1 to bypass."
            )
            return make_response(msg["id"], error={"code": -32000, "message": error_msg})
        return self._forward(msg)

    def _handle_read_tool(self, msg, tool_name, file_path):
        response = self._forward(msg)
        if response and "result" in response and not response.get("error"):
            result_data = response["result"]
            content = result_data.get("content", "")
            if isinstance(content, list):
                texts = [item.get("text", "") for item in content if isinstance(item, dict)]
                content = "\n".join(texts)
            if content:
                findings = scan_content(content, file_path)
                if findings:
                    self.audit.log(tool=tool_name, file_path=file_path,
                                   action="pass_read", findings_count=len(findings),
                                   severity=max_severity(findings))
                    print(f"[SG] 📖 审计读取: {file_path} ({len(findings)} 发现)", file=sys.stderr)
        return response

    def _forward(self, msg):
        response = self.send_to_upstream(msg)
        return response or make_response(msg["id"], error={"code": -32000, "message": "已断开"})

    def handle_message(self, line: str) -> str:
        msg = json.loads(line)
        method = msg.get("method", "")
        mid = msg.get("id")

        if method == "initialize":
            resp = self._forward(msg)
            if resp and "result" in resp:
                info = resp["result"].get("serverInfo", {})
                self.upstream_name = info.get("name", "unknown")
                self.upstream_version = info.get("version", "0.0.0")
            return json.dumps(resp, ensure_ascii=False) if resp else None

        elif method == "tools/list":
            return json.dumps(self._forward(msg), ensure_ascii=False)

        elif method == "tools/call":
            params = msg.get("params", {})
            name = params.get("name", "")
            args = params.get("arguments", {})
            file_path = args.get("path", args.get("file", ""))
            content = args.get("content", args.get("text", args.get("data", "")))

            if name in WRITE_TOOLS and content:
                resp = self._handle_write_tool(msg, name, file_path, content)
            elif name in READ_TOOLS:
                resp = self._handle_read_tool(msg, name, file_path)
            else:
                resp = self._forward(msg)
            return json.dumps(resp, ensure_ascii=False) if resp else None

        elif method in ("notifications/initialized",):
            if self.upstream_process and self.upstream_process.stdin:
                self.upstream_process.stdin.write(line + "\n")
                self.upstream_process.stdin.flush()
            return None

        elif method == "ping":
            return json.dumps(make_response(mid, result={}), ensure_ascii=False)

        else:
            return json.dumps(self._forward(msg), ensure_ascii=False)

    def run(self):
        self.start_upstream()
        print(f"[SG] ✅ Security Guardian MCP Middleware 已启动", file=sys.stderr)
        print(f"[SG]    上游: {self.upstream_name} v{self.upstream_version}", file=sys.stderr)
        print(f"[SG]    策略: {self.policy.name}", file=sys.stderr)
        print(f"[SG]    审计: {self.audit.audit_dir}", file=sys.stderr)
        print(f"[SG]    SG_BYPASS=1 跳过检查", file=sys.stderr)

        try:
            for line in sys.stdin:
                if not line.strip():
                    continue
                if os.environ.get("SG_BYPASS") == "1":
                    msg = json.loads(line)
                    print(json.dumps(self._forward(msg), ensure_ascii=False), flush=True)
                    continue
                resp = self.handle_message(line)
                if resp:
                    print(resp, flush=True)
        except (EOFError, KeyboardInterrupt):
            pass
        finally:
            self.shutdown()

    def shutdown(self):
        if self.upstream_process:
            summary = self.audit.summary()
            print(f"\n[SG] 📊 审计摘要 (策略: {self.policy.name})", file=sys.stderr)
            print(f"[SG]    {summary['total_calls']} 调用 | {summary['blocked']} 阻止 | "
                  f"{summary['warned']} 警告 | {summary['passed']} 通过", file=sys.stderr)
            self.upstream_process.terminate()
            try:
                self.upstream_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.upstream_process.kill()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Security Guardian MCP Middleware")
    parser.add_argument("--upstream", "-u", help="上游 MCP 服务器命令")
    parser.add_argument("--policy", "-p", choices=["strict", "normal", "relaxed"],
                        default="normal", help="安全策略模式")
    parser.add_argument("--audit-dir", default=None, help="审计日志目录")
    parser.add_argument("--status", action="store_true", help="查看当前状态 + 审计摘要")
    parser.add_argument("--license", metavar="KEY", help="设置 License Key (Pro/Team)")

    args = parser.parse_args()

    # 状态模式
    if args.status:
        audit = AuditLogger(args.audit_dir)
        summary = audit.summary()
        tier, key = lic.get_license_tier()
        print(f"Security Guardian MCP Middleware — 状态")
        print(f"{'='*50}")
        print(f"  License:   {tier.upper()}" + (f" ({key[:16]}...)" if key else ""))
        print(f"  策略:      {args.policy}")
        print(f"  审计目录:  {audit.audit_dir}")
        print(f"  {'='*30}")
        print(f"  今日审计:")
        print(f"    总调用:   {summary['total_calls']}")
        print(f"    已阻止:   {summary['blocked']}")
        print(f"    已警告:   {summary['warned']}")
        print(f"    已通过:   {summary['passed']}")
        if summary['blocked'] > 0:
            print(f"\n  ⚠️  发现 {summary['blocked']} 个安全问题已被拦截")
            print(f"  查看详情: cat {audit.audit_dir}/*.jsonl")
        return

    # License 设置模式
    if args.license:
        lic.set_license_key(args.license)
        print(f"✅ License Key 已保存")
        tier, _ = lic.get_license_tier()
        print(f"   当前: {tier.upper()}")
        return

    # 启动代理模式
    if not args.upstream:
        parser.print_help()
        print("\n❌ 需要指定 --upstream 来启动代理，或使用 --status 查看状态")
        return

    config = load_config()
    proxy = MCPProxy(
        upstream_command=args.upstream,
        policy_mode=args.policy or config.get("policy", "normal"),
        audit_dir=args.audit_dir,
        config=config,
    )
    try:
        proxy.run()
    except KeyboardInterrupt:
        proxy.shutdown()


if __name__ == "__main__":
    main()
