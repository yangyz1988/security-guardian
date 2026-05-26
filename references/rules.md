# Security Guardian — 安全规则参考

## 规则总览

当前版本: **v0.1.0** | 规则总数: **50+** | 覆盖标准: OWASP Top 10 (2021), CWE Top 25

---

## 1. 密钥泄露检测 (Secret Detection)

| 规则ID | 模式 | 严重度 | CWE |
|--------|------|--------|-----|
| `openai-key` | `sk-[A-Za-z0-9]{20,}` | Critical | CWE-798 |
| `github-token` | `gh[pousr]_[A-Za-z0-9_]{20,}` | Critical | CWE-798 |
| `aws-access-key` | `AKIA[0-9A-Z]{16}` | Critical | CWE-798 |
| `private-key` | `-----BEGIN ... PRIVATE KEY-----` | Critical | CWE-798 |
| `db-connection-string` | `mysql://user:pass@...` | Critical | CWE-798 |
| `stripe-live-key` | `sk_live_[0-9a-zA-Z]{24,}` | Critical | CWE-798 |
| `slack-token` | `xox[baprs]-...` | High | CWE-798 |
| `generic-api-key` | `api_key = "..."` | High | CWE-798 |
| `hardcoded-password` | `password = "..."` | High | CWE-798 |
| `jwt-token` | `eyJ...` | Medium | CWE-798 |

### 误报过滤
以下情况自动跳过：
- 注释行（`#`, `//`）
- 环境变量引用（`${VAR}`）
- 占位符（`YOUR_KEY`, `EXAMPLE`, `xxx`）
- 文档关键词（`example`, `placeholder`）

---

## 2. OWASP 漏洞检测

### A01:2021 — Broken Access Control
尚未覆盖（v0.2.0 计划）

### A02:2021 — Cryptographic Failures
| 规则ID | 检测内容 | 严重度 | CWE |
|--------|----------|--------|-----|
| `crypto-usage` | AES/Fernet/RSA 使用 | Medium | CWE-321 |
| `insecure-random` | random.randint 用于安全场景 | Low | CWE-330 |

### A03:2021 — Injection
| 规则ID | 检测内容 | 严重度 | CWE |
|--------|----------|--------|-----|
| `sql-injection` | 动态 SQL 拼接 | Critical | CWE-89 |
| `command-injection` | os.system 拼接用户输入 | Critical | CWE-78 |
| `xss-dom` | innerHTML / dangerouslySetInnerHTML | High | CWE-79 |

### A04:2021 — Insecure Design
| 规则ID | 检测内容 | 严重度 | CWE |
|--------|----------|--------|-----|
| `ssrf-risk` | requests 接收用户 URL | Medium | CWE-918 |

### A05:2021 — Security Misconfiguration
| 规则ID | 检测内容 | 严重度 | CWE |
|--------|----------|--------|-----|
| `docker-root-user` | 容器 root 运行 | Medium | — |
| `privileged-container` | privileged: true | High | — |
| `host-network` | network_mode: host | Medium | — |
| `empty-config` | 空环境变量 | Low | — |

### A06:2021 — Vulnerable and Outdated Components
| 规则ID | 组件 | 影响版本 | 严重度 | CVE |
|--------|------|----------|--------|-----|
| `vuln-django` | Django | < 3.2 | High | CVE-2023-23969 |
| `vuln-flask` | Flask | < 2.0 | Medium | CVE-2023-30861 |
| `vuln-requests` | requests | < 2.31 | Medium | CVE-2023-32681 |
| `vuln-pillow` | Pillow | < 9.4 | High | CVE-2023-22877 |
| `vuln-cryptography` | cryptography | < 39.0 | Medium | CVE-2023-23931 |
| `vuln-urllib3` | urllib3 | < 1.26 | Medium | CVE-2023-26115 |
| `vuln-pyyaml` | PyYAML | < 5.4 | High | CVE-2020-14343 |

### A07:2021 — Identification and Authentication Failures
尚未覆盖

### A08:2021 — Software and Data Integrity Failures
| 规则ID | 检测内容 | 严重度 | CWE |
|--------|----------|--------|-----|
| `insecure-deserialization` | pickle.loads() / yaml.load() | High | CWE-502 |

### A09:2021 — Security Logging and Monitoring Failures
尚未覆盖

### A10:2021 — Server-Side Request Forgery (SSRF)
| 规则ID | 检测内容 | 严重度 | CWE |
|--------|----------|--------|-----|
| `ssrf-risk` | 用户 URL 传入 HTTP 请求 | Medium | CWE-918 |

---

## 3. 额外检测（非 OWASP）

| 规则ID | 检测内容 | 严重度 | 说明 |
|--------|----------|--------|------|
| `toctou` | os.path.exists + os.remove | Low | 竞态条件 |
| `path-traversal` | `../` 路径穿越 | High | CWE-22 |
| `docker-layer-optimization` | apt-get 优化 | Low | 镜像大小优化建议 |
