"""
Security Guardian — Audit Logger 审计日志

每次 AI Agent 调用的工具操作都会被记录为 JSONL 格式：
  - 日志文件: ~/.security-guardian/audit/YYYY-MM-DD.jsonl
  - 自动轮转: 每天一个文件
  - 自动清理: 保留 30 天

每条日志包含：
  - timestamp: ISO 格式时间戳
  - agent: AI Agent 标识
  - tool: 调用的工具名称
  - file: 操作的文件路径
  - action: 策略动作 (pass/warn/block)
  - findings: 扫描发现的条目数
  - result: 操作结果 (allowed/blocked)
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


class AuditLogger:
    """审计日志记录器"""

    def __init__(self, audit_dir: Optional[str] = None):
        self.audit_dir = Path(audit_dir or os.path.expanduser("~/.security-guardian/audit"))
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self._cleanup_old_logs()

    def _log_path(self) -> Path:
        """今日日志路径"""
        return self.audit_dir / f"{datetime.now().strftime('%Y-%m-%d')}.jsonl"

    def _cleanup_old_logs(self, days: int = 30):
        """清理 30 天前的日志"""
        cutoff = datetime.now() - timedelta(days=days)
        for f in self.audit_dir.glob("*.jsonl"):
            try:
                date_str = f.stem  # YYYY-MM-DD
                file_date = datetime.strptime(date_str, "%Y-%m-%d")
                if file_date < cutoff:
                    f.unlink(missing_ok=True)
            except ValueError:
                pass  # 文件名不符合日期格式，跳过

    def log(
        self,
        tool: str,
        file_path: str,
        action: str,
        findings_count: int,
        agent: str = "unknown",
        severity: str = "none",
        details: Optional[str] = None,
    ):
        """记录一条审计日志

        Args:
            tool: 工具名称 (如 write_file)
            file_path: 操作的文件路径
            action: 策略动作 (pass/warn/block)
            findings_count: 发现的条目数
            agent: AI Agent 名称
            severity: 最高严重级别
            details: 详细信息（可选）
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "agent": agent,
            "tool": tool,
            "file": str(file_path),
            "action": action,
            "findings_count": findings_count,
            "max_severity": severity,
            "result": "allowed" if action in ("pass", "warn") else "blocked",
        }
        if details:
            entry["details"] = details

        with open(self._log_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def get_today_events(self) -> list:
        """获取今日所有审计事件"""
        log_file = self._log_path()
        if not log_file.exists():
            return []
        events = []
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events

    def summary(self) -> dict:
        """生成今日审计摘要"""
        events = self.get_today_events()
        return {
            "total_calls": len(events),
            "blocked": sum(1 for e in events if e.get("result") == "blocked"),
            "warned": sum(1 for e in events if e.get("action") == "warn"),
            "passed": sum(1 for e in events if e.get("action") == "pass"),
            "findings_total": sum(e.get("findings_count", 0) for e in events),
        }
