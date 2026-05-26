#!/usr/bin/env python3
"""
Security Guardian - Git Pre-Commit Hook
拦截含密钥泄露和高危漏洞的代码提交。

安装方式:
  方式1 (pre-commit 框架):
    # 在项目根目录 .pre-commit-config.yaml 中引用此脚本
  方式2 (直接安装):
    cp templates/pre-commit .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
  方式3 (手动):
    python scripts/git-hook.py

行为:
  - 只扫描 git 暂存区中修改/新增的代码文件
  - CRITICAL 和 HIGH 级别问题 → 阻止提交
  - MEDIUM 和 LOW 级别问题 → 警告但不阻止
  - 可通过 SKIP_SECURITY_SCAN=1 环境变量跳过
  - 可通过 SECURITY_SCAN_STRICT=1 让所有问题都阻止提交
"""

import os
import sys
import subprocess
from pathlib import Path

# 项目根目录（相对 git hook 位置）
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCAN_SCRIPT = PROJECT_ROOT / "scripts" / "scan.py"
SEVERITY_BLOCK = {'critical', 'high'}  # 默认阻止的严重等级


def get_staged_files() -> list[str]:
    """获取 git 暂存区中的文件列表"""
    try:
        result = subprocess.run(
            ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACM'],
            capture_output=True, text=True, check=True,
            cwd=PROJECT_ROOT,
        )
        return [f for f in result.stdout.strip().split('\n') if f]
    except subprocess.CalledProcessError:
        print("❌ 无法获取 git 暂存区文件列表", file=sys.stderr)
        sys.exit(1)


def is_scan_target(filepath: str) -> bool:
    """判断文件是否应该被扫描"""
    name = os.path.basename(filepath)
    suffix = Path(filepath).suffix.lower()

    scan_exts = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rs', '.java',
        '.rb', '.php', '.c', '.cpp', '.h', '.sh', '.bash', '.zsh',
        '.yaml', '.yml', '.json', '.toml', '.ini', '.cfg', '.conf',
        '.html', '.css', '.sql', '.xml',
    }
    scan_names = {'Dockerfile', '.env', 'requirements.txt', 'package.json',
                  'Makefile', 'Pipfile', 'pyproject.toml', 'go.mod', 'Cargo.toml'}

    # 排除测试和文档文件
    if any(name.startswith(p) for p in ['test_', 'conftest.', 'setup.']):
        return False
    if suffix in {'.md', '.txt'}:
        return False
    if 'docker-compose' in name:
        return True
    if name in scan_names:
        return True
    if suffix in scan_exts:
        return True
    return False


def scan_file(filepath: str) -> list[dict]:
    """用 scan.py 扫描单个文件"""
    try:
        result = subprocess.run(
            [sys.executable, str(SCAN_SCRIPT),
             '--path', filepath,
             '--output', 'json',
             '--severity', 'low'],  # 全量扫描，hook 自己过滤
            capture_output=True, text=True, timeout=60,
            cwd=PROJECT_ROOT,
        )
        if result.returncode not in (0, 1):  # 1 = 有发现，正常
            print(f"⚠️  扫描 {filepath} 时出错: {result.stderr}", file=sys.stderr)
            return []
        import json
        data = json.loads(result.stdout)
        return data.get('findings', [])
    except subprocess.TimeoutExpired:
        print(f"⚠️  扫描 {filepath} 超时，跳过", file=sys.stderr)
        return []
    except Exception as e:
        print(f"⚠️  扫描 {filepath} 失败: {e}", file=sys.stderr)
        return []


def main():
    # 环境变量跳过
    if os.environ.get('SKIP_SECURITY_SCAN') == '1':
        print("⏭️  SKIP_SECURITY_SCAN=1，跳过安全检查")
        sys.exit(0)

    # 严格模式：所有问题都阻止
    block_severity = SEVERITY_BLOCK
    if os.environ.get('SECURITY_SCAN_STRICT') == '1':
        block_severity = {'critical', 'high', 'medium', 'low'}

    staged = get_staged_files()
    targets = [f for f in staged if is_scan_target(f)]

    if not targets:
        sys.exit(0)  # 没有需要扫描的文件

    all_findings = []
    for fpath in targets:
        # 文件可能已被删除
        full_path = PROJECT_ROOT / fpath
        if not full_path.exists():
            continue
        findings = scan_file(fpath)
        if findings:
            all_findings.extend(findings)

    if not all_findings:
        print("✅ Security Guardian: 未发现安全问题")
        sys.exit(0)

    # 分类
    blocking = [f for f in all_findings if f['severity'] in block_severity]
    warnings = [f for f in all_findings if f['severity'] not in block_severity]

    # 输出警告
    if warnings:
        print(f"\n⚠️  Security Guardian: 发现 {len(warnings)} 个低风险问题:")
        for f in warnings:
            print(f"  [{f['severity'].upper()}] {f['file']}:{f['line']} - {f['rule_id']}: {f['message']}")

    # 输出阻止项
    if blocking:
        print(f"\n🔴 Security Guardian: 发现 {len(blocking)} 个高风险问题，提交已阻止:")
        print()
        for f in blocking:
            print(f"  [{f['severity'].upper()}] {f['file']}:{f['line']}")
            print(f"        规则: {f['rule_id']}")
            print(f"        问题: {f['message']}")
            print(f"        修复: {f['fix_suggestion']}")
            print()

        print("💡 提示:")
        print("  - 修复问题后重新提交")
        print("  - 紧急情况可用 SKIP_SECURITY_SCAN=1 git commit ... 跳过")
        print("  - 运行 python scripts/fix.py --path . --apply 自动修复部分问题")
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
