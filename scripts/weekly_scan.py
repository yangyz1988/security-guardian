#!/usr/bin/env python3
"""
weekly_scan.py - 周扫描脚本
由 Hermes cron job 每周自动执行
扫描指定目录并输出报告
"""
import sys
import os
from datetime import datetime

# 确保能导入 scan 模块
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCAN_DIR = os.path.join(SCRIPT_DIR, '..', 'scripts')
sys.path.insert(0, SCAN_DIR)
import scan

# 配置
TARGET = os.environ.get('SG_SCAN_TARGET', os.path.expanduser('~/一人AI公司'))
REPORT_DIR = os.path.join(SCRIPT_DIR, '..', 'reports')

def main():
    os.makedirs(REPORT_DIR, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H%M')
    report_path = os.path.join(REPORT_DIR, f'scan-{timestamp}.md')
    
    print(f"Scanning: {TARGET}")
    report = scan.scan_project(TARGET)
    
    output = scan.format_markdown(report)
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(output)
    
    # 同时输出最新报告到 latest.md
    latest_path = os.path.join(REPORT_DIR, 'latest.md')
    with open(latest_path, 'w', encoding='utf-8') as f:
        f.write(output)
    
    # 终端输出摘要
    sev = report.summary['by_severity']
    crit = sev.get('critical', 0)
    high = sev.get('high', 0)
    med = sev.get('medium', 0)
    low = sev.get('low', 0)
    
    summary = (
        f"Report: {report_path}\n"
        f"Files: {report.scanned_files}/{report.total_files} scanned\n"
        f"Findings: {report.summary['total_findings']} total "
        f"({crit}C / {high}H / {med}M / {low}L)"
    )
    print(summary)
    
    # 返回状态码：critical>0 时返回 1，方便 CI 捕获
    return 1 if crit > 0 else 0

if __name__ == '__main__':
    sys.exit(main())
