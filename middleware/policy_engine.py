"""
Security Guardian — Policy Engine 策略决策引擎

决定：扫描到安全问题后，应该做什么？

策略模式：
  - strict:  阻止所有 critical + high 级别的写操作
  - normal:  只阻止 critical 级别的写操作（默认）
  - relaxed: 不阻止，只记录到审计日志

每个模式都可以在 config.yaml 中自定义例外规则。
"""

from enum import Enum
from typing import List, Optional


class PolicyMode(str, Enum):
    STRICT = "strict"
    NORMAL = "normal"
    RELAXED = "relaxed"


class PolicyAction(str, Enum):
    PASS = "pass"       # 透传，不干预
    WARN = "warn"       # 允许但标记警告
    BLOCK = "block"     # 阻止操作
    BLOCK_WITH_FIX = "block_with_fix"  # 阻止并提供修复建议


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}

# 默认策略表：严重级别 → 各模式下的动作
DEFAULT_POLICY_TABLE = {
    "critical": {
        PolicyMode.STRICT: PolicyAction.BLOCK,
        PolicyMode.NORMAL: PolicyAction.BLOCK,
        PolicyMode.RELAXED: PolicyAction.WARN,
    },
    "high": {
        PolicyMode.STRICT: PolicyAction.BLOCK,
        PolicyMode.NORMAL: PolicyAction.WARN,
        PolicyMode.RELAXED: PolicyAction.PASS,
    },
    "medium": {
        PolicyMode.STRICT: PolicyAction.WARN,
        PolicyMode.NORMAL: PolicyAction.PASS,
        PolicyMode.RELAXED: PolicyAction.PASS,
    },
    "low": {
        PolicyMode.STRICT: PolicyAction.WARN,
        PolicyMode.NORMAL: PolicyAction.PASS,
        PolicyMode.RELAXED: PolicyAction.PASS,
    },
}


class PolicyEngine:
    """策略决策引擎——决定扫描结果对应的动作"""

    def __init__(self, mode: PolicyMode = PolicyMode.NORMAL):
        self.mode = mode if isinstance(mode, PolicyMode) else PolicyMode(mode)
        self.exceptions = []  # 例外规则: [(pattern, action)]

    def decide(self, severity: str, filepath: str = "") -> PolicyAction:
        """
        根据严重级别 + 策略模式 + 例外规则，做出决策。

        Args:
            severity: 严重级别 (critical/high/medium/low)
            filepath: 被扫描的文件路径（用于例外匹配）

        Returns:
            PolicyAction 枚举值
        """
        severity = severity.lower()

        # 检查例外规则
        if filepath and self.exceptions:
            for pattern, action in self.exceptions:
                if pattern in filepath or __import__("re").search(pattern, filepath):
                    return action

        # 查表
        severity_map = DEFAULT_POLICY_TABLE.get(severity, {})
        return severity_map.get(self.mode, PolicyAction.PASS)

    def add_exception(self, pattern: str, action: PolicyAction):
        """添加例外规则：匹配的文件路径使用指定动作"""
        self.exceptions.append((pattern, action))

    @property
    def name(self) -> str:
        return self.mode.value


# 快速判断：一个 findings 列表是否需要阻止
def should_block(findings: list, engine: PolicyEngine) -> tuple:
    """
    检查 findings 列表，是否有需要阻止的。

    Returns:
        (should_block: bool, reason: str or None)
    """
    for finding in findings:
        action = engine.decide(finding.severity, finding.file)
        if action in (PolicyAction.BLOCK, PolicyAction.BLOCK_WITH_FIX):
            return True, f"[BLOCKED] {finding.rule_id}: {finding.message}"
        if action == PolicyAction.WARN:
            # 记录最后一个警告，但不阻止
            pass
    return False, None
