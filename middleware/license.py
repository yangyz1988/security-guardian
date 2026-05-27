"""
Security Guardian — License Key 校验与付费功能管理

付费分层：
  Free:  核心拦截 + 审计日志
  Pro:   + SARIF/HTML 报告 + 自定义规则 + 自动修复
  Team:  + 多项目 Dashboard + 合规趋势 + 飞书/Slack 推送

License Key 格式:
  SG-XXXX-XXXX-XXXX-XXXX (简单的签名字符串)
  
当前 MVP 阶段: 不收费，不做真校验。埋好校验点，以后上线 Stripe。
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Optional


LICENSE_FILE = Path(os.path.expanduser("~/.security-guardian/license.key"))


class LicenseTier:
    FREE = "free"
    PRO = "pro"
    TEAM = "team"


def _read_license() -> Optional[str]:
    """读取本地 License Key"""
    if not LICENSE_FILE.exists():
        return None
    try:
        return LICENSE_FILE.read_text().strip()
    except Exception:
        return None


def _validate_format(key: str) -> bool:
    """校验 License Key 格式 (简单验证，不上线 Stripe 前不做真校验)"""
    if not key:
        return False
    if key.startswith("SG-") and len(key) >= 15:
        return True
    # 开发阶段: 任何非空 key 都视为有效
    return True


def get_license_tier() -> tuple:
    """
    获取当前 License 等级。

    Returns:
        (tier: str, key: str or None)
    """
    key = _read_license()
    if key and _validate_format(key):
        # 正式上线时这里会解密校验 + 查询 Stripe
        # MVP 阶段: 所有 key 都视为 Pro
        return LicenseTier.PRO, key
    return LicenseTier.FREE, None


def is_pro() -> bool:
    """当前是否是 Pro 及以上等级"""
    tier, _ = get_license_tier()
    return tier in (LicenseTier.PRO, LicenseTier.TEAM)


def is_team() -> bool:
    """当前是否是 Team 等级"""
    tier, _ = get_license_tier()
    return tier == LicenseTier.TEAM


def require_license(feature_name: str) -> bool:
    """
    检查特定功能是否需要 Pro License。
    不需要 Pro 的功能返回 True (免费可用)。
    需要 Pro 的返回 is_pro()。

    预算埋点 — 以后为每个 Pro 功能触发一次检查日志。
    """
    pro_features = {
        "sarif_report",
        "html_report",
        "pdf_compliance",
        "custom_rules",
        "auto_fix",
        "slack_webhook",
        "feishu_webhook",
        "multi_project_dashboard",
    }

    if feature_name not in pro_features:
        return True  # 免费功能

    return is_pro()


def set_license_key(key: str) -> bool:
    """写入 License Key（开发/测试用）"""
    LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
    LICENSE_FILE.write_text(key.strip())
    return True


def clear_license():
    """清除 License Key"""
    if LICENSE_FILE.exists():
        LICENSE_FILE.unlink()
