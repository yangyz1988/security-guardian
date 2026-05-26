# 🛡️ Security Guardian

**AI 代码安全卫士 — 让 AI 写的代码不再裸奔**

[![Version](https://img.shields.io/badge/version-0.1.0-blue)](https://github.com/your-org/security-guardian)
[![Hermes Skill](https://img.shields.io/badge/Hermes-Skill-green)](https://hermes-agent.nousresearch.com)
[![License](https://img.shields.io/badge/license-MIT-brightgreen)](LICENSE)

> 部署前 10 秒自动安全审计，检测 OWASP Top 10 漏洞、密钥泄露、不安全依赖和配置风险。

## 为什么需要这个？

AI 生成的代码占比越来越高，但**没有人审计 AI 代码的安全性**。研究表明 AI 生成代码的漏洞率比人工代码高 30%+：

- Claude/GPT 生成的代码可能包含 SQL 注入
- 复制粘贴 API key 到代码里，然后 git push
- 使用已知有漏洞的旧版依赖
- Docker 容器以 root 运行

Security Guardian 在你部署前自动扫描这些问题，填补 "AI 写代码 → 没人审安全" 的致命空白。

## 快速开始

### 安装

```bash
hermes skills install security-guardian
```

### 使用

```
# 在 Hermes 会话中
scan code for vulnerabilities

# 或手动触发
python scripts/scan.py --path . --output markdown
```

### 示例输出

```
🔒 Security Guardian - 扫描报告

## 📊 摘要
| 严重等级 | 数量 |
|----------|------|
| 🔴 CRITICAL | 3 |
| 🟠 HIGH | 5 |
| 🟡 MEDIUM | 2 |
| 🔵 LOW | 1 |
| **总计** | **11** |

## 🔴 CRITICAL (3)

### openai-key
- **文件**: `config.py:12`
- **问题**: Hardcoded OpenAI API Key
- **修复**: Move to environment variable
```

## 检测能力

### 密钥泄露 (10+ 规则)
OpenAI、GitHub、AWS、Stripe、Slack tokens；数据库连接串；JWT；SSH 私钥；硬编码密码

### OWASP Top 10 (9+ 规则)
SQL 注入、XSS、命令注入、路径穿越、SSRF、不安全反序列化、TOCTOU

### 不安全依赖 (10+ 规则)
Django、Flask、Requests、Pillow、Cryptography、PyYAML 等已知漏洞版本

### 配置风险 (5+ 规则)
Docker root 用户、privileged 容器、host 网络、空环境变量

## 自动修复

```bash
# 预览修复
python scripts/fix.py --path .

# 应用修复 (创建 .bak 备份)
python scripts/fix.py --path . --apply
```

支持自动修复：密钥替换为环境变量、Docker 安全加固、SQL 注入参数化建议等。

## 特性

- ✅ **零外部依赖** — 纯 Python 标准库，pip install 都不需要
- ✅ **即插即用** — 10 秒完成扫描
- ✅ **Hermes 原生集成** — 适配 Skill 体系，天然触发
- ✅ **自动修复** — 常见问题一键修补
- ✅ **CI/CD 就绪** — JSON 输出，轻松集成 GitHub Actions
- ✅ **本地运行** — 代码不上传，隐私安全

## 项目结构

```
security-guardian/
├── SKILL.md           # Hermes Skill 定义
├── README.md          # 本文件
├── scripts/
│   ├── scan.py        # 扫描引擎
│   └── fix.py         # 修复引擎
├── references/
│   ├── rules.md       # 规则文档
│   └── owasp-top10.md # OWASP 覆盖
└── examples/
    └── sample-report.md
```

## 路线图

- [x] v0.1.0 — 核心扫描 + 修复引擎 (50+ 规则)
- [ ] v0.2.0 — CI/CD 集成 (GitHub Actions)
- [ ] v0.3.0 — 自定义规则支持
- [ ] v1.0.0 — Pro 版 (团队仪表板 + API)

## 许可

MIT License — 一人AI公司
