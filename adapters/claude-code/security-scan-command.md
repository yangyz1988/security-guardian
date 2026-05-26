# /security-scan — Security Guardian 手动安全扫描

手动触发安全扫描命令。

## 用法

在 Claude Code 对话中输入 `/security-scan` 触发全项目安全扫描。

## 参数

可以指定路径和严重度：

```
/security-scan                    # 全项目，所有严重度
/security-scan --severity high    # 只显示高危
/security-scan --path src/        # 扫描指定目录
/security-scan --output json      # JSON 输出
```

## 可用选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `--path PATH` | 扫描路径 | `.` (项目根目录) |
| `--output FORMAT` | 输出格式: markdown/json/sarif/html | markdown |
| `--severity LEVEL` | 最低严重度: critical/high/medium/low | low |

## 实现

执行命令：
```bash
python .claude/security-guardian/scripts/scan.py --path . --output markdown
```
