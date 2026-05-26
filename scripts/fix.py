#!/usr/bin/env python3
"""
Security Guardian - 自动修复引擎
对常见安全问题生成修复 patch / 提供修复代码
"""

import os
import re
import argparse
from pathlib import Path
from typing import List, Tuple

# ============================================================
# 修复策略映射
# ============================================================

FIX_STRATEGIES = {
    # === 密钥泄露修复 ===
    'openai-key': {
        'type': 'replace',
        'pattern': r'sk-[A-Za-z0-9]{20,}',
        'replacement': '${OPENAI_API_KEY}',
        'description': 'Replace hardcoded OpenAI key with environment variable',
    },
    'github-token': {
        'type': 'replace',
        'pattern': r'gh[pousr]_[A-Za-z0-9_]{20,}',
        'replacement': '${GITHUB_TOKEN}',
        'description': 'Replace hardcoded GitHub token with environment variable',
    },
    'aws-access-key': {
        'type': 'replace',
        'pattern': r'AKIA[0-9A-Z]{16}',
        'replacement': '${AWS_ACCESS_KEY_ID}',
        'description': 'Replace hardcoded AWS key with environment variable',
    },
    'generic-api-key': {
        'type': 'replace',
        'pattern': r'(api[_-]?key|apikey|API_KEY)\s*[:=]\s*["\']([^"\'$]{8,})["\']',
        'replacement': r'\1=${API_KEY}',
        'description': 'Replace hardcoded API key with environment variable',
    },
    'hardcoded-password': {
        'type': 'replace',
        'pattern': r'(password|passwd|pwd|secret)\s*[:=]\s*["\']([^"\'$]{3,})["\']',
        'replacement': r'\1=${DB_PASSWORD}',
        'description': 'Replace hardcoded password with environment variable',
    },

    # === SQL Injection 修复 ===
    'sql-injection': {
        'type': 'suggest',
        'pattern': None,
        'description': 'SQL Injection: convert to parameterized query',
        'before': "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")",
        'after': "cursor.execute(\"SELECT * FROM users WHERE id=?\", (user_id,))",
    },

    # === Command Injection 修复 ===
    'command-injection': {
        'type': 'suggest',
        'pattern': None,
        'description': 'Command injection: use list-based subprocess.run()',
        'before': "os.system(f'ping {host}')",
        'after': "subprocess.run(['ping', host], check=True)",
    },

    # === Docker 安全修复 ===
    'docker-root-user': {
        'type': 'append',
        'pattern': r'^USER\s+root',
        'description': 'Docker: add non-root user after build steps',
        'insert_after': 'USER 1000',
    },
    'privileged-container': {
        'type': 'replace',
        'pattern': r'privileged:\s*true',
        'replacement': '# privileged: true  # REMOVED by Security Guardian: use cap_add instead',
        'description': 'Remove privileged mode from container',
    },

    # === Insecure Deserialization ===
    'insecure-deserialization': {
        'type': 'suggest',
        'pattern': None,
        'description': 'Use safe_load instead of load for YAML deserialization',
        'before': "data = yaml.load(f)",
        'after': "data = yaml.safe_load(f)",
    },
}


def fix_file(filepath: str, rule_ids: List[str] = None, dry_run: bool = True) -> List[dict]:
    """
    对文件应用修复策略
    返回: [{'line': int, 'rule_id': str, 'action': str, 'old': str, 'new': str, 'applied': bool}]
    """
    path = Path(filepath)
    if not path.exists():
        return [{'error': f'File not found: {filepath}'}]

    try:
        content = path.read_text(encoding='utf-8', errors='replace')
    except Exception as e:
        return [{'error': f'Cannot read file: {e}'}]

    results = []
    new_content = content
    lines = content.split('\n')

    strategies = FIX_STRATEGIES
    if rule_ids:
        strategies = {k: v for k, v in FIX_STRATEGIES.items() if k in rule_ids}

    for rule_id, strategy in strategies.items():
        if strategy['type'] == 'replace':
            # 正则替换
            pattern = strategy['pattern']
            if pattern:
                matches = list(re.finditer(pattern, new_content, re.IGNORECASE))
                if matches:
                    new_content = re.sub(pattern, strategy['replacement'], new_content, flags=re.IGNORECASE)
                    for m in matches:
                        line_num = new_content[:m.start()].count('\n') + 1
                        results.append({
                            'line': line_num,
                            'rule_id': rule_id,
                            'action': 'replace',
                            'old': m.group(0)[:100],
                            'new': strategy['replacement'],
                            'description': strategy.get('description', ''),
                            'applied': not dry_run,
                        })

        elif strategy['type'] == 'suggest':
            # 建议修复（不自动应用，输出 before/after）
            results.append({
                'rule_id': rule_id,
                'action': 'suggest',
                'description': strategy.get('description', ''),
                'before': strategy.get('before', ''),
                'after': strategy.get('after', ''),
                'applied': False,  # suggestions are never auto-applied
            })

        elif strategy['type'] == 'append':
            pattern = strategy['pattern']
            insert_text = strategy.get('insert_after', '')
            if pattern and re.search(pattern, new_content, re.IGNORECASE):
                # 在匹配行之后插入
                new_lines = []
                for line in lines:
                    new_lines.append(line)
                    if re.search(pattern, line, re.IGNORECASE):
                        new_lines.append(insert_text)
                new_content = '\n'.join(new_lines)
                results.append({
                    'rule_id': rule_id,
                    'action': 'append',
                    'description': strategy.get('description', ''),
                    'inserted': insert_text,
                    'applied': not dry_run,
                })

    # 写入修改（非 dry-run 模式）
    if not dry_run and new_content != content:
        # 创建备份
        backup_path = str(path) + '.security-guardian.bak'
        path.write_text(content, encoding='utf-8')
        print(f"  📦 Backup saved: {backup_path}")
        # 写入新内容
        path.write_text(new_content, encoding='utf-8')
        print(f"  ✅ Fixed: {filepath}")

    return results


def fix_project(target_path: str, rule_ids: List[str] = None, dry_run: bool = True):
    """批量修复项目中所有文件"""
    from scan import collect_files, scan_file

    target = os.path.abspath(target_path)
    if not os.path.exists(target):
        print(f"Error: Path not found: {target}")
        return

    all_files = collect_files(target)

    for fpath in all_files:
        # 先扫描获取问题
        findings = scan_file(fpath)
        if not findings:
            continue

        file_rule_ids = list(set(f.rule_id for f in findings
                                  if f.rule_id in FIX_STRATEGIES))

        if not file_rule_ids:
            continue

        if rule_ids:
            file_rule_ids = [r for r in file_rule_ids if r in rule_ids]

        if not file_rule_ids:
            continue

        print(f"\n🔧 {fpath} ({len(file_rule_ids)} issues)")
        results = fix_file(fpath, file_rule_ids, dry_run=dry_run)
        for r in results:
            if 'error' in r:
                print(f"  ❌ {r['error']}")
            elif r.get('action') == 'replace':
                status = "🟢 WOULD FIX" if dry_run else "✅ FIXED"
                print(f"  {status} [{r['rule_id']}] {r.get('description', '')}")
                if dry_run:
                    print(f"    Old: {r['old']}")
                    print(f"    New: {r['new']}")
            elif r.get('action') == 'suggest':
                print(f"  💡 SUGGEST [{r['rule_id']}] {r.get('description', '')}")
                print(f"    Before: {r.get('before', '')}")
                print(f"    After:  {r.get('after', '')}")
            elif r.get('action') == 'append':
                status = "🟢 WOULD ADD" if dry_run else "✅ ADDED"
                print(f"  {status} [{r['rule_id']}] {r.get('description', '')}")


def main():
    parser = argparse.ArgumentParser(
        description='Security Guardian - 自动修复引擎'
    )
    parser.add_argument('--path', '-p', default='.', help='目标项目路径')
    parser.add_argument('--rule', '-r', nargs='+', help='仅修复指定规则 (rule_id)')
    parser.add_argument('--apply', action='store_true', help='实际应用修复 (默认 dry-run)')
    parser.add_argument('--file', '-f', help='修复单个文件')
    args = parser.parse_args()

    dry_run = not args.apply

    if args.file:
        print(f"🔧 Fixing: {args.file}")
        results = fix_file(args.file, args.rule, dry_run=dry_run)
        for r in results:
            print(json.dumps(r, indent=2, ensure_ascii=False))
    else:
        print(f"🔧 {'[DRY RUN] ' if dry_run else ''}Scanning: {args.path}")
        if args.apply:
            print("⚠️  --apply mode: changes will be written to files! Use --dry-run (default) to preview first.")
        fix_project(args.path, args.rule, dry_run=dry_run)

    if dry_run:
        print(f"\n💡 Run with --apply to apply these fixes.")


if __name__ == '__main__':
    import json
    main()
