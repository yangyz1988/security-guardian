#!/usr/bin/env python3
"""
Security Guardian - 飞书报告推送
将扫描报告推送到飞书消息/文档

用法:
  python feishu_reporter.py --report-file report.md --mode message
  python feishu_reporter.py --report-file report.html --mode doc --title "周扫描报告"

环境变量:
  FEISHU_APP_ID: 飞书应用 ID
  FEISHU_APP_SECRET: 飞书应用密钥
  FEISHU_CHAT_ID: 目标群聊 ID (message 模式)
  FEISHU_DOC_FOLDER: 文档文件夹 token (doc 模式, 可选)
"""
import sys
import os
import json
import argparse
import urllib.request
import urllib.error
from datetime import datetime

# ============================================================
# 飞书 API 客户端
# ============================================================

FEISHU_API_BASE = "https://open.feishu.cn/open-apis"


class FeishuClient:
    """飞书 Open API 客户端"""

    def __init__(self, app_id: str, app_secret: str):
        self.app_id = app_id
        self.app_secret = app_secret
        self._token = None

    def _request(self, method: str, path: str, body: dict = None) -> dict:
        """发送飞书 API 请求"""
        url = f"{FEISHU_API_BASE}{path}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json; charset=utf-8",
        }
        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            raise RuntimeError(f"Feishu API error {e.code}: {err_body}")

    @property
    def token(self) -> str:
        """获取 tenant_access_token (自动缓存)"""
        if self._token:
            return self._token
        resp = self._request("POST", "/auth/v3/tenant_access_token/internal", {
            "app_id": self.app_id,
            "app_secret": self.app_secret,
        })
        if resp.get("code") != 0:
            raise RuntimeError(f"Auth failed: {resp}")
        self._token = resp["tenant_access_token"]
        return self._token

    def send_message(self, chat_id: str, content: str, msg_type: str = "interactive") -> dict:
        """发送消息到飞书群聊"""
        if msg_type == "text":
            body = {
                "receive_id": chat_id,
                "msg_type": "text",
                "content": json.dumps({"text": content}),
            }
        else:
            # 使用卡片消息
            body = {
                "receive_id": chat_id,
                "msg_type": "interactive",
                "content": json.dumps({
                    "config": {"wide_screen_mode": True},
                    "header": {
                        "title": {"tag": "plain_text", "content": "🔒 Security Guardian 扫描报告"},
                        "template": "red",
                    },
                    "elements": [
                        {"tag": "markdown", "content": content[:3000]},
                        {
                            "tag": "note",
                            "elements": [
                                {"tag": "plain_text", "content": f"扫描时间: {datetime.now().isoformat()}"}
                            ],
                        },
                    ],
                }),
            }
        return self._request(
            "POST",
            f"/im/v1/messages?receive_id_type=chat_id",
            body,
        )

    def create_doc(self, title: str, content: str, folder_token: str = None) -> dict:
        """创建飞书文档"""
        body = {
            "title": title,
        }
        if folder_token:
            body["folder_token"] = folder_token
        resp = self._request("POST", "/docx/v1/documents", body)
        if resp.get("code") != 0:
            raise RuntimeError(f"Create doc failed: {resp}")

        doc_id = resp["data"]["document"]["document_id"]
        # 写入内容
        self._append_doc_content(doc_id, content)
        return resp

    def _append_doc_content(self, doc_id: str, content: str):
        """向文档追加内容 (简化版 - 纯文本块)"""
        # 将 markdown 转换为飞书文档块
        blocks = []
        for line in content.split("\n"):
            if line.startswith("# "):
                blocks.append({
                    "block_type": 3,  # heading1
                    "heading1": {
                        "elements": [{"text_run": {"content": line[2:]}}],
                    },
                })
            elif line.startswith("## "):
                blocks.append({
                    "block_type": 4,  # heading2
                    "heading2": {
                        "elements": [{"text_run": {"content": line[3:]}}],
                    },
                })
            elif line.startswith("```"):
                continue
            elif line.strip():
                blocks.append({
                    "block_type": 2,  # text
                    "text": {
                        "elements": [{"text_run": {"content": line}}],
                    },
                })

        if blocks:
            return self._request(
                "POST",
                f"/docx/v1/documents/{doc_id}/blocks/{doc_id}/children",
                {"children": blocks},
            )


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Security Guardian - 飞书报告推送")
    parser.add_argument("--report-file", "-f", required=True, help="扫描报告文件路径")
    parser.add_argument("--mode", "-m", choices=["message", "doc"], default="message",
                        help="推送模式: message(群消息) / doc(文档)")
    parser.add_argument("--title", "-t", default=None, help="文档标题 (doc 模式)")
    parser.add_argument("--chat-id", default=None, help="飞书群聊 ID (message 模式)")
    parser.add_argument("--app-id", default=None, help="飞书 App ID (默认从环境变量读取)")
    parser.add_argument("--app-secret", default=None, help="飞书 App Secret (默认从环境变量读取)")
    args = parser.parse_args()

    # 读取凭证
    app_id = args.app_id or os.environ.get("FEISHU_APP_ID")
    app_secret = args.app_secret or os.environ.get("FEISHU_APP_SECRET")
    if not app_id or not app_secret:
        print("错误: 请设置 FEISHU_APP_ID 和 FEISHU_APP_SECRET 环境变量", file=sys.stderr)
        sys.exit(1)

    # 读取报告
    try:
        with open(args.report_file, "r", encoding="utf-8") as f:
            report_content = f.read()
    except FileNotFoundError:
        print(f"错误: 报告文件不存在: {args.report_file}", file=sys.stderr)
        sys.exit(1)

    client = FeishuClient(app_id, app_secret)

    if args.mode == "message":
        chat_id = args.chat_id or os.environ.get("FEISHU_CHAT_ID")
        if not chat_id:
            print("错误: message 模式需要 --chat-id 或 FEISHU_CHAT_ID 环境变量", file=sys.stderr)
            sys.exit(1)
        print(f"📤 发送扫描报告到飞书群 {chat_id} ...", file=sys.stderr)
        try:
            # 发送文本摘要（前 3000 字符）
            summary = report_content[:3000]
            resp = client.send_message(chat_id, summary, "text")
            if resp.get("code") == 0:
                print(f"✅ 消息发送成功! message_id={resp['data']['message_id']}", file=sys.stderr)
            else:
                print(f"❌ 发送失败: {resp}", file=sys.stderr)
        except RuntimeError as e:
            print(f"❌ 飞书 API 错误: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.mode == "doc":
        title = args.title or f"Security Guardian 扫描报告 - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        folder = os.environ.get("FEISHU_DOC_FOLDER")
        print(f"📄 创建飞书文档: {title} ...", file=sys.stderr)
        try:
            resp = client.create_doc(title, report_content, folder)
            if resp.get("code") == 0:
                doc_url = resp["data"]["document"]["url"]
                print(f"✅ 文档创建成功! {doc_url}", file=sys.stderr)
                print(doc_url)  # stdout 输出文档链接
            else:
                print(f"❌ 创建失败: {resp}", file=sys.stderr)
        except RuntimeError as e:
            print(f"❌ 飞书 API 错误: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
