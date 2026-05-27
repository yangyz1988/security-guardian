#!/usr/bin/env python3
"""
Security Guardian CLI — `sg` 命令入口

子命令:
  sg scan    安全扫描
  sg fix     自动修复
  sg proxy   启动 MCP 透明代理
  sg status  查看状态
  sg license 管理 License
"""

import sys
import argparse


def main():
    """主 CLI 入口，将子命令路由到对应模块的 main()。"""
    parser = argparse.ArgumentParser(
        prog="sg",
        description="Security Guardian - AI 代码安全工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
子命令:
  scan     安全扫描代码
  fix      自动修复安全问题
  proxy    启动 MCP 透明代理
  status   查看运行状态与审计摘要
  license  查看/设置 License Key

使用 "sg <子命令> --help" 查看具体参数。
        """.strip(),
    )
    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # --- sg scan ---
    scan_p = subparsers.add_parser("scan", help="安全扫描代码",
                                   description="Security Guardian - 代码安全扫描引擎")
    scan_p.add_argument("--path", "-p", default=".", help="目标项目路径 (默认: 当前目录)")
    scan_p.add_argument("--output", "-o",
                        choices=["json", "markdown", "sarif", "html", "pdf"],
                        default="markdown",
                        help="输出格式 (PDF 需安装 reportlab)")
    scan_p.add_argument("--severity", "-s",
                        choices=["critical", "high", "medium", "low"],
                        help="最低严重度过滤")
    scan_p.add_argument("--compliance",
                        choices=["owasp", "soc2", "iso27001", "pci"],
                        help="合规框架映射 (仅 PDF)")
    scan_p.add_argument("--company", type=str, default="",
                        help="公司名称 (仅 PDF)")
    scan_p.add_argument("--project", type=str, default="",
                        help="项目名称 (仅 PDF)")
    scan_p.add_argument("--output-file", type=str, default="",
                        help="PDF 输出路径 (仅 PDF)")

    # --- sg fix ---
    fix_p = subparsers.add_parser("fix", help="自动修复安全问题",
                                  description="Security Guardian - 自动修复引擎")
    fix_p.add_argument("--path", "-p", default=".", help="目标项目路径")
    fix_p.add_argument("--rule", "-r", nargs="+", help="仅修复指定规则 (rule_id)")
    fix_p.add_argument("--apply", action="store_true",
                       help="实际应用修复 (默认 dry-run)")
    fix_p.add_argument("--file", "-f", help="修复单个文件")

    # --- sg proxy ---
    proxy_p = subparsers.add_parser("proxy", help="启动 MCP 透明代理",
                                    description="Security Guardian MCP Middleware — 透明代理")
    proxy_p.add_argument("--upstream", "-u", required=True,
                         help="上游 MCP 服务器命令 (如 'python my-server.py')")
    proxy_p.add_argument("--policy", "-p",
                         choices=["strict", "normal", "relaxed"],
                         default="normal", help="安全策略模式")
    proxy_p.add_argument("--audit-dir", default=None, help="审计日志目录")

    # --- sg status ---
    status_p = subparsers.add_parser("status", help="查看运行状态与审计摘要",
                                     description="查看 Security Guardian 运行状态")
    status_p.add_argument("--audit-dir", default=None, help="审计日志目录")

    # --- sg license ---
    lic_p = subparsers.add_parser("license", help="查看/设置 License Key",
                                  description="Security Guardian License 管理")
    lic_p.add_argument("key", nargs="?", help="License Key (不提供则查看当前)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # ── 路由到各模块 ──────────────────────────────────
    if args.command == "scan":
        _run_scan(args)

    elif args.command == "fix":
        _run_fix(args)

    elif args.command in ("proxy", "status", "license"):
        _run_proxy_command(args)

    else:
        parser.print_help()


# ═══════════════════════════════════════════════════════
# 路由实现
# ═══════════════════════════════════════════════════════

def _run_scan(args):
    """路由到 scripts.scan.main()"""
    from scripts.scan import main as scan_main

    # 构造 fake argv 让 scan 模块的 argparse 正确解析
    argv = ["sg scan"]
    argv += ["--path", args.path]
    argv += ["--output", args.output]
    if args.severity:
        argv += ["--severity", args.severity]
    if args.compliance:
        argv += ["--compliance", args.compliance]
    if args.company:
        argv += ["--company", args.company]
    if args.project:
        argv += ["--project", args.project]
    if args.output_file:
        argv += ["--output-file", args.output_file]

    _call_with_argv(scan_main, argv)


def _run_fix(args):
    """路由到 scripts.fix.main()"""
    from scripts.fix import main as fix_main

    argv = ["sg fix"]
    argv += ["--path", args.path]
    if args.rule:
        argv += ["--rule"] + args.rule
    if args.apply:
        argv.append("--apply")
    if args.file:
        argv += ["--file", args.file]

    _call_with_argv(fix_main, argv)


def _run_proxy_command(args):
    """路由到 middleware.mcp_proxy.main()"""
    from middleware.mcp_proxy import main as proxy_main

    if args.command == "proxy":
        argv = ["sg proxy"]
        argv += ["--upstream", args.upstream]
        argv += ["--policy", args.policy]
        if args.audit_dir:
            argv += ["--audit-dir", args.audit_dir]

    elif args.command == "status":
        argv = ["sg status", "--status"]
        if args.audit_dir:
            argv += ["--audit-dir", args.audit_dir]

    elif args.command == "license":
        if args.key:
            argv = ["sg license", "--license", args.key]
        else:
            # 直接调用 license 模块查看
            from middleware import license as lic
            tier, key = lic.get_license_tier()
            print(f"Security Guardian License")
            print(f"{'=' * 30}")
            masked = key[:16] + "..." if len(key) > 16 else (key or "(not set)")
            print(f"  Tier:  {tier.upper()}")
            print(f"  Key:   {masked}")
            return

    _call_with_argv(proxy_main, argv)


def _call_with_argv(func, argv):
    """临时替换 sys.argv 并调用 func，之后恢复。"""
    saved = sys.argv[:]
    try:
        sys.argv = argv
        func()
    finally:
        sys.argv = saved


if __name__ == "__main__":
    main()
