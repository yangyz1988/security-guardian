#!/usr/bin/env python3
"""
weekly_scan.py - 周扫描脚本
由 Hermes cron job 每周自动执行
扫描指定目录 → 输出报告 → 推送到飞书 (可选)
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

# 飞书配置 (可选)
FEISHU_APP_ID = os.environ.get('FEISHU_APP_ID', '')
FEISHU_APP_SECRET = os.environ.get('FEISHU_APP_SECRET', '')
FEISHU_CHAT_ID = os.environ.get('FEISHU_CHAT_ID', '')


def push_to_feishu(report_path: str, summary: str):
    """推送报告到飞书 (如果凭证可用)"""
    if not (FEISHU_APP_ID and FEISHU_APP_SECRET and FEISHU_CHAT_ID):
        print("[飞书] 未配置凭证，跳过推送")
        return False

    try:
        from feishu_reporter import FeishuClient
        client = FeishuClient(FEISHU_APP_ID, FEISHU_APP_SECRET)

        # 发送摘要消息
        resp = client.send_message(FEISHU_CHAT_ID, summary, "text")
        if resp.get("code") == 0:
            print(f"[飞书] 消息推送成功: {resp['data']['message_id']}")
            return True
        else:
            print(f"[飞书] 推送失败: {resp}")
            return False
    except Exception as e:
        print(f"[飞书] 推送异常: {e}")
        return False


def main():
    os.makedirs(REPORT_DIR, exist_ok=True)

    timestamp = datetime.now().strftime('%Y-%m-%d_%H%M')
    report_path = os.path.join(REPORT_DIR, f'scan-{timestamp}.md')

    print(f"🔍 Scanning: {TARGET}")
    report = scan.scan_project(TARGET)

    # Markdown 报告
    md_output = scan.format_markdown(report)
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(md_output)

    # HTML 报告
    html_path = os.path.join(REPORT_DIR, f'scan-{timestamp}.html')
    html_output = scan.format_html(report)
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_output)

    # 最新报告
    latest_md = os.path.join(REPORT_DIR, 'latest.md')
    latest_html = os.path.join(REPORT_DIR, 'latest.html')
    with open(latest_md, 'w', encoding='utf-8') as f:
        f.write(md_output)
    with open(latest_html, 'w', encoding='utf-8') as f:
        f.write(html_output)

    # 摘要
    sev = report.summary['by_severity']
    crit = sev.get('critical', 0)
    high = sev.get('high', 0)
    med = sev.get('medium', 0)
    low = sev.get('low', 0)
    total = report.summary['total_findings']

    summary = (
        f"🔒 Security Guardian 周扫描报告\n"
        f"📅 {timestamp}\n"
        f"📂 {TARGET}\n"
        f"📊 {report.scanned_files}/{report.total_files} 文件已扫描\n"
        f"⚠️ 发现 {total} 个问题: "
        f"{'🔴' if crit else ''}{crit}C "
        f"{'🟠' if high else ''}{high}H "
        f"{'🟡' if med else ''}{med}M "
        f"{'🔵' if low else ''}{low}L"
    )
    print(summary)

    # 推送到飞书
    if crit > 0 or total > 0:
        push_to_feishu(report_path, summary)

    return 1 if crit > 0 else 0


if __name__ == '__main__':
    sys.exit(main())
