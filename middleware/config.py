"""
Security Guardian — 用户配置管理

配置文件位置: ~/.security-guardian/config.yaml

示例配置：
```yaml
# 策略模式: strict / normal / relaxed
policy: normal

# 扫描排除的文件模式
exclude_patterns:
  - "*.md"
  - "tests/*"
  - "node_modules/*"

# 审计日志保留天数
audit_retention_days: 30

# 例外规则：某些路径总是允许/阻止
exceptions:
  - pattern: "*.prompt"
    action: pass
  - pattern: ".env"
    action: block

# License Key (Pro/Team 付费)
license_key: ""
```
"""

import os
from pathlib import Path
from typing import Optional

from policy_engine import PolicyMode

DEFAULT_CONFIG = {
    "policy": "normal",
    "exclude_patterns": ["*.md", "tests/*", "node_modules/*", ".git/*"],
    "audit_retention_days": 30,
    "exceptions": [],
    "license_key": "",
}


def _resolve_config_path() -> Path:
    """配置文件路径"""
    return Path(os.path.expanduser("~/.security-guardian/config.yaml"))


def get_default_config_path():
    """获取默认配置文件路径"""
    return str(_resolve_config_path())


def load_config(config_path: Optional[str] = None) -> dict:
    """
    加载配置。
    顺序：默认值 → 配置文件 → 环境变量覆盖
    """
    config = dict(DEFAULT_CONFIG)

    yaml_path = Path(config_path) if config_path else _resolve_config_path()

    # 尝试从 YAML 加载
    if yaml_path.exists():
        try:
            import yaml
            with open(yaml_path, "r") as f:
                user_config = yaml.safe_load(f) or {}
                config.update(user_config)
        except ImportError:
            # 没有 PyYAML，用简单的行解析
            loaded = _simple_load(yaml_path)
            config.update(loaded)
        except Exception:
            pass  # 配置文件损坏回退

    # 环境变量覆盖
    env_overrides = {
        "policy": ("SG_POLICY", None),
        "license_key": ("SG_LICENSE_KEY", ""),
    }
    for key, (env_name, _) in env_overrides.items():
        env_val = os.environ.get(env_name)
        if env_val:
            config[key] = env_val

    return config


def _simple_load(path: Path) -> dict:
    """没有 PyYAML 时的简易解析"""
    config = {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                key, _, val = line.partition(":")
                config[key.strip()] = val.strip().strip('"').strip("'")
    return config
