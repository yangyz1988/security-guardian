# Security Guardian — AI 代码安全扫描

**让 AI 写的代码不再裸奔**

## When to Use

加载此 Skill 当你需要：

- 检查 Claude 刚生成的代码是否有安全漏洞
- 在提交代码前做最终安全检查
- 检查是否有密钥/Token 被硬编码到代码中
- 检查依赖是否有已知漏洞
- 审查 Docker 配置是否安全

## Quick Start

```bash
# 全项目扫描
python scripts/scan.py --path . --output markdown

# 只看高危问题
python scripts/scan.py --path . --severity high

# JSON 格式（用于自动化）
python scripts/scan.py --path . --output json
```

## 扫描能力

| 类别 | 检测内容 | 严重度 |
|------|---------|--------|
| 密钥泄露 | OpenAI/GitHub/AWS/Stripe/Slack/GitLab/Azure Token, 数据库连接串, 私钥, 硬编码密码 | 🔴 Critical/🟠 High |
| 注入攻击 | SQL/NoSQL/命令注入, XSS, 路径穿越, LDAP注入 | 🔴 Critical/🟠 High |
| 加密问题 | 硬编码密钥, 不安全随机数 | 🟡 Medium/🔵 Low |
| SSRF | 用户可控URL的HTTP请求 | 🟡 Medium |
| XXE | XML解析未禁用外部实体 | 🔴 Critical |
| 开放重定向 | 用户可控URL的重定向 | 🟡 Medium |
| 反序列化 | 不安全的 pickle/yaml.load | 🟠 High |
| 依赖漏洞 | 已知漏洞的 Python/npm 包 | 🟠 High/🟡 Medium |
| Docker 安全 | Root用户, 特权容器, host网络 | 🟡 Medium/🟠 High |
| 配置风险 | 空环境变量, 错误配置 | 🔵 Low/🟡 Medium |

## 严重度处理规则

- 🔴 **Critical**: 立即修复 — 密钥暴露/SQL注入/代码执行风险。**阻止部署/提交**
- 🟠 **High**: 部署前修复 — XSS/路径穿越/硬编码密码
- 🟡 **Medium**: 本迭代修复 — 依赖漏洞/SSRF/Docker配置
- 🔵 **Low**: 方便时处理 — 不安全随机数/竞争条件

## 输出格式

- **Markdown**: 人类可读报告
- **JSON**: 机器可读（CI/CD集成）
- **SARIF**: GitHub Code Scanning 集成
- **HTML**: 暗色主题自包含报告

## 安装

项目已通过 Hook 自动集成。无需额外配置。
