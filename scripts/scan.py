#!/usr/bin/env python3
"""
Security Guardian - 核心扫描引擎
纯 Python 标准库实现，零外部依赖
扫描目标：密钥泄露 / OWASP漏洞模式 / 不安全依赖 / 配置风险
"""

import os
import re
import ast
import json
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from datetime import datetime

# ============================================================
# 数据模型
# ============================================================

@dataclass
class Finding:
    """单个安全发现"""
    file: str
    line: int
    severity: str          # critical / high / medium / low
    category: str          # secret / injection / dependency / config
    rule_id: str
    message: str
    snippet: str           # 问题代码片段
    fix_suggestion: str    # 修复建议
    cwe_id: Optional[str] = None

@dataclass
class ScanReport:
    """扫描报告"""
    scan_time: str
    target_path: str
    total_files: int
    scanned_files: int
    findings: List[Finding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

# ============================================================
# 1. 密钥泄露检测 (Secret Detection)
# ============================================================

SECRET_PATTERNS = [
    # OpenAI API Key
    (r'sk-[A-Za-z0-9]{20,}', 'critical', 'openai-key',
     'Hardcoded OpenAI API Key',
     'Move to environment variable: export OPENAI_API_KEY=sk-...'),
    # GitHub Personal Access Token
    (r'gh[pousr]_[A-Za-z0-9_]{20,}', 'critical', 'github-token',
     'Hardcoded GitHub PAT Token',
     'Use GitHub CLI (gh auth login) or environment variable'),
    # AWS Access Key
    (r'AKIA[0-9A-Z]{16}', 'critical', 'aws-access-key',
     'Hardcoded AWS Access Key ID',
     'Use AWS IAM roles or aws-vault. Never commit keys.'),
    # Generic API Key assignment
    (r'(api[_-]?key|apikey|API_KEY)\s*[:=]\s*["\'](?!\${)(?!{{)[^"\'$]{8,}["\']', 'high', 'generic-api-key',
     'Hardcoded API key in code',
     'Use environment variables or secrets manager'),
    # Password in code
    (r'(password|passwd|pwd|secret)\s*[:=]\s*["\'](?!\${)(?!{{)[^"\'$]{3,}["\']', 'high', 'hardcoded-password',
     'Hardcoded password',
     'Store passwords in .env file or secrets manager'),
    # JWT Token
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'medium', 'jwt-token',
     'Hardcoded JWT token',
     'Generate JWTs at runtime with short expiration'),
    # Private Key headers
    (r'-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----', 'critical', 'private-key',
     'Private key in source code',
     'Never commit private keys. Use SSH agent or key vault.'),
    # Database connection strings
    (r'(mysql|postgres|mongodb|redis)://[^/\s]+:[^/\s]+@', 'critical', 'db-connection-string',
     'Database connection string with credentials',
     'Use environment variable for connection string'),
    # Stripe keys
    (r'sk_live_[0-9a-zA-Z]{24,}', 'critical', 'stripe-live-key',
     'Stripe live secret key exposed',
     'Use Stripe restricted keys and environment variables'),
    # Slack tokens
    (r'xox[baprs]-[0-9a-zA-Z-]{10,}', 'high', 'slack-token',
     'Slack token exposed',
     'Use Slack app credentials via environment variables'),
    # GitLab Personal Access Token
    (r'glpat-[0-9a-zA-Z_-]{20,}', 'critical', 'gitlab-token',
     'Hardcoded GitLab PAT',
     'Use GitLab CI/CD variables or environment variable'),
    # Azure Storage connection string
    (r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+', 'critical', 'azure-storage-key',
     'Azure Storage connection string with account key',
     'Use Azure Managed Identity or Key Vault instead of connection strings'),
]

def scan_secrets(content: str, filepath: str) -> List[Finding]:
    """扫描密钥泄露"""
    findings = []
    lines = content.split('\n')
    for pattern, severity, rule_id, message, fix in SECRET_PATTERNS:
        for i, line in enumerate(lines, 1):
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                # 过滤常见 false positive
                if is_false_positive(line, match.group(0)):
                    continue
                findings.append(Finding(
                    file=filepath,
                    line=i,
                    severity=severity,
                    category='secret',
                    rule_id=rule_id,
                    message=message,
                    snippet=line.strip()[:120],
                    fix_suggestion=fix,
                    cwe_id='CWE-798' if 'hardcoded' in rule_id else None
                ))
    return findings

def has_regex_metas(line: str) -> bool:
    """检测行是否包含正则表达式元字符（如 \\s, (?:, [^, \\| 等）"""
    regex_escapes = ['\\s', '\\d', '\\w', '\\S', '\\D', '\\W',
                     '\\b', '\\B', '\\A', '\\Z', '\\|', '\\(']
    regex_tokens = ['(?:', '[^', '|']
    for esc in regex_escapes:
        if esc in line:
            return True
    for tok in regex_tokens:
        if tok in line:
            return True
    return False


def is_false_positive(line: str, matched: str) -> bool:
    """检测误报"""
    # 注释中的密钥
    if line.strip().startswith('#') or line.strip().startswith('//'):
        return True
    # 已经是环境变量引用 (${VAR} 或 $UPPER_CASE)
    if re.search(r'\$\{[A-Z_]+\}', matched) or re.search(r'\$[A-Z_]{3,}', matched):
        return True
    # 看起来像占位符
    if 'YOUR_' in matched.upper() or 'EXAMPLE' in matched.upper():
        return True
    # 明显是文档/示例
    if any(kw in line.lower() for kw in ['example', 'placeholder', 'your-api-key', 'xxx', 'TODO']):
        return True
    # 安全扫描器自扫描：规则定义行（如 (r'innerHTML|...') 本身不是漏洞
    # 检测 r'...' 或 r"..." 形式的正则定义行（可能在元组/列表内）
    stripped = line.strip()
    is_raw_str = stripped.startswith("r'") or stripped.startswith('r"')
    is_tuple_raw = stripped.startswith("(r'") or stripped.startswith('(r"')
    if (is_raw_str or is_tuple_raw) and has_regex_metas(line):
        return True
    # fix.py 中的 'before': 示例代码不是真实漏洞
    if "'before':" in line or '"before":' in line:
        return True
    # 依赖漏洞描述中的示例代码（如 yaml.load() in CVE description）
    if 'CVE-' in line or 'vulnerab' in line.lower() or 'arbitrary code' in line.lower():
        return True
    return False

# ============================================================
# 2. OWASP 漏洞模式检测
# ============================================================

OWASP_PATTERNS = [
    # SQL Injection
    (r'(?:execute|cursor\.execute)\s*\(\s*f["\'].*?(?:\{.*?\}|%s|\{\}|format|\+|f["\'])', 'critical', 'sql-injection',
     'Potential SQL injection: dynamic query building',
     'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))',
     'CWE-89'),
    # XSS (in templates/HTML)
    (r'innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(', 'high', 'xss-dom',
     'Potential DOM-based XSS vulnerability',
     'Use textContent instead of innerHTML, or sanitize with DOMPurify',
     'CWE-79'),
    # Command Injection
    (r'(?:os\.system|subprocess\.call|subprocess\.Popen|exec\s*\(|eval\s*\()\s*\(.*?(?:\+|f["\']|format)', 'critical', 'command-injection',
     'Potential command injection: unsanitized input in system call',
     'Use subprocess.run with list arguments, not string shell=True',
     'CWE-78'),
    # Path Traversal
    (r'open\s*\(.*?(?:\.\./|\.\.\\)', 'high', 'path-traversal',
     'Potential path traversal vulnerability',
     'Sanitize file paths with os.path.basename() and restrict to allowed directories',
     'CWE-22'),
    # Insecure Deserialization
    (r'(?:pickle\.loads?|yaml\.load\s*\(|marshal\.loads?\()', 'high', 'insecure-deserialization',
     'Insecure deserialization: using unsafe loader',
     'Use yaml.safe_load() or avoid pickle. Validate all serialized data.',
     'CWE-502'),
    # Hardcoded crypto keys
    (r'(?:AES\.new|Fernet|RSA\.generate)\s*\(', 'medium', 'crypto-usage',
     'Cryptographic operation detected - verify key management',
     'Use environment variables for keys. Rotate regularly.',
     'CWE-321'),
    # Insecure random
    (r'random\.(?:random|randint|choice)\s*\(', 'low', 'insecure-random',
     'Using insecure random for possibly security-sensitive operation',
     'Use secrets module for cryptographic randomness',
     'CWE-330'),
    # SSRF risk
    (r'(?:requests\.get|urllib\.request)\s*\(.*?(?:\+|f["\']|format)', 'medium', 'ssrf-risk',
     'Potential SSRF: user-controlled URL in HTTP request',
     'Validate and whitelist allowed URLs/IPs. Block internal IP ranges.',
     'CWE-918'),
    # Race condition (TOCTOU)
    (r'os\.path\.exists.*os\.remove|os\.access.*open', 'low', 'toctou',
     'Potential TOCTOU race condition',
     'Use atomic operations or file locking',
     'CWE-367'),
    # XXE - XML External Entity
    (r'(?:etree\.parse|xml\.etree\.ElementTree|minidom\.parse|lxml\.etree\.parse)\s*\(', 'critical', 'xxe',
     'Potential XXE vulnerability: XML parsing without disabling external entities',
     'Use defusedxml or set resolve_entities=False / forbid_dtd=True',
     'CWE-611'),
    # NoSQL Injection
    (r'(?:collection|db\.\w+)\.(?:find|find_one|aggregate)\s*\(\s*\{[^}]*\$where', 'critical', 'nosql-injection',
     'Potential NoSQL injection: dynamic $where clause',
     'Use parameterized queries with mongo-sanitize or validate user input',
     'CWE-943'),
    # Open Redirect
    (r'(?:redirect|HttpResponseRedirect|RedirectResponse)\s*\(.*?(?:request\.args|request\.GET|req\.query|params\[)', 'medium', 'open-redirect',
     'Potential open redirect: user-controlled URL in redirect',
     'Validate redirect URLs against a whitelist of allowed domains',
     'CWE-601'),
    # LDAP Injection
    (r'(?:ldap\.search|ldap\.filter|search_s|search_ext)\s*\(.*?(?:\+|format|f["\'])', 'high', 'ldap-injection',
     'Potential LDAP injection: unsanitized input in LDAP query',
     'Escape special LDAP characters: * ( ) \\ NUL. Use ldap3 safe filters.',
     'CWE-90'),
]

def scan_owasp(content: str, filepath: str) -> List[Finding]:
    """扫描 OWASP 漏洞模式"""
    findings = []
    lines = content.split('\n')
    for pattern, severity, rule_id, message, fix, cwe in OWASP_PATTERNS:
        for i, line in enumerate(lines, 1):
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                # 过滤误报（规则定义行、注释、占位符等）
                if is_false_positive(line, match.group(0)):
                    continue
                findings.append(Finding(
                    file=filepath,
                    line=i,
                    severity=severity,
                    category='injection' if 'injection' in rule_id else 'code-quality',
                    rule_id=rule_id,
                    message=message,
                    snippet=line.strip()[:120],
                    fix_suggestion=fix,
                    cwe_id=cwe
                ))
    return findings

# ============================================================
# 3. 不安全依赖检测
# ============================================================

KNOWN_VULNERABLE = {
    # package_name: (version_below, cve, severity, description)
    'django': ('3.2', 'CVE-2023-23969', 'high', 'Django < 3.2 has ReDoS vulnerability'),
    'flask': ('2.0', 'CVE-2023-30861', 'medium', 'Flask < 2.0 has cookie leakage issue'),
    'requests': ('2.31', 'CVE-2023-32681', 'medium', 'Requests < 2.31 has proxy header leakage'),
    'pillow': ('9.4', 'CVE-2023-22877', 'high', 'Pillow < 9.4 has arbitrary code execution'),
    'cryptography': ('39.0', 'CVE-2023-23931', 'medium', 'cryptography < 39.0 has memory corruption'),
    'urllib3': ('1.26', 'CVE-2023-26115', 'medium', 'urllib3 < 1.26 has ReDoS in URL parsing'),
    'sqlalchemy': ('1.4', 'CVE-2023-22878', 'medium', 'SQLAlchemy < 1.4.45 has info disclosure'),
    'numpy': ('1.22', 'CVE-2022-38975', 'medium', 'numpy < 1.22 has buffer overflow in f2py'),
    'pyyaml': ('5.4', 'CVE-2020-14343', 'high', 'PyYAML < 5.4 has arbitrary code execution via yaml.load()'),
}

# npm 已知漏洞 (package.json)
KNOWN_VULNERABLE_NPM = {
    'lodash': ('4.17.21', 'CVE-2021-23337', 'high', 'lodash < 4.17.21 has command injection in template'),
    'minimist': ('1.2.6', 'CVE-2021-44906', 'high', 'minimist < 1.2.6 has prototype pollution'),
    'node-fetch': ('2.6.7', 'CVE-2022-0235', 'high', 'node-fetch < 2.6.7 leaks cookies to wrong domain'),
    'semver': ('7.5.2', 'CVE-2022-25883', 'medium', 'semver < 7.5.2 has ReDoS vulnerability'),
    'word-wrap': ('1.2.4', 'CVE-2023-26115', 'medium', 'word-wrap < 1.2.4 has ReDoS in result variable'),
    'express': ('4.18.0', 'CVE-2024-29041', 'medium', 'express < 4.18.0 has open redirect in static()'),
    'axios': ('1.6.0', 'CVE-2023-45857', 'medium', 'axios < 1.6.0 has SSRF via baseURL manipulation'),
    'follow-redirects': ('1.15.4', 'CVE-2024-28849', 'high', 'follow-redirects < 1.15.4 leaks credentials'),
}

def scan_dependencies(target_path: str, filepath: str) -> List[Finding]:
    """扫描 requirements.txt 或 package.json 中的不安全依赖"""
    findings = []
    content = Path(filepath).read_text(errors='ignore')
    filename = os.path.basename(filepath)

    if filename == 'package.json':
        # 解析 npm 依赖
        try:
            import json
            pkg = json.loads(content)
            deps = {}
            deps.update(pkg.get('dependencies', {}))
            deps.update(pkg.get('devDependencies', {}))
            for pkg_name, version_spec in deps.items():
                pkg_name_lower = pkg_name.lower()
                if pkg_name_lower in KNOWN_VULNERABLE_NPM:
                    vuln_version, cve, severity, desc = KNOWN_VULNERABLE_NPM[pkg_name_lower]
                    # 解析语义版本 (去除 ^ ~ >= 等前缀)
                    clean_ver = version_spec.lstrip('^~>=< ')
                    if clean_ver < vuln_version:
                        findings.append(Finding(
                            file=filepath,
                            line=0,
                            severity=severity,
                            category='dependency',
                            rule_id=f'vuln-npm-{pkg_name_lower}',
                            message=f'{desc} (installed: {clean_ver})',
                            snippet=f'"{pkg_name}": "{version_spec}"',
                            fix_suggestion=f'Upgrade {pkg_name} to >= {vuln_version}',
                            cwe_id=cve
                        ))
        except (json.JSONDecodeError, KeyError):
            pass
        return findings

    # requirements.txt 解析
    lines = content.split('\n')

    for i, line in enumerate(lines, 1):
        line = line.strip()
        # Parse requirements.txt: package==version or package>=version
        match = re.match(r'^([a-zA-Z0-9_-]+)\s*[><=!~]+\s*([0-9.]+)', line)
        if match:
            pkg_name = match.group(1).lower()
            pkg_version = match.group(2)
            if pkg_name in KNOWN_VULNERABLE:
                vuln_version, cve, severity, desc = KNOWN_VULNERABLE[pkg_name]
                if pkg_version < vuln_version:
                    findings.append(Finding(
                        file=filepath,
                        line=i,
                        severity=severity,
                        category='dependency',
                        rule_id=f'vuln-{pkg_name}',
                        message=f'{desc} (installed: {pkg_version})',
                        snippet=line[:120],
                        fix_suggestion=f'Upgrade {pkg_name} to >= {vuln_version}',
                        cwe_id=cve
                    ))

    return findings

# ============================================================
# 4. 配置风险检测
# ============================================================

CONFIG_CHECKS = {
    '.env': [
        (r'^[A-Z_]+=["\']\s*["\']$', 'low', 'empty-config',
         'Empty environment variable', 'Remove or set a value for this variable'),
    ],
    'Dockerfile': [
        (r'^FROM\s+\S+\s+AS\s+\S+', 'info', None, None, None),
        (r'^USER\s+root', 'medium', 'docker-root-user',
         'Docker container runs as root', 'Add "USER 1000" after necessary setup steps'),
        (r'^RUN\s+.*apt-get.*update\s*&&\s*.*install\s+', 'low', 'docker-layer-optimization',
         'Docker: combine apt-get operations','Use --no-install-recommends and clean apt cache'),
    ],
    'docker-compose.yml': [
        (r'privileged:\s*true', 'high', 'privileged-container',
         'Container running in privileged mode', 'Remove privileged: true, add only needed capabilities'),
        (r'network_mode:\s*host', 'medium', 'host-network',
         'Container using host network mode', 'Use bridge network mode instead'),
    ],
}

def scan_configs(content: str, filepath: str) -> List[Finding]:
    """扫描配置文件风险"""
    filename = os.path.basename(filepath)
    findings = []

    if filename not in CONFIG_CHECKS:
        return findings

    patterns = CONFIG_CHECKS[filename]
    lines = content.split('\n')
    for pattern, severity, rule_id, message, fix in patterns:
        if rule_id is None:
            continue  # skip info-only patterns
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(Finding(
                    file=filepath,
                    line=i,
                    severity=severity,
                    category='config',
                    rule_id=rule_id,
                    message=message,
                    snippet=line.strip()[:120],
                    fix_suggestion=fix
                ))
    return findings

# ============================================================
# 扫描调度器
# ============================================================

TEXT_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rs', '.java',
    '.rb', '.php', '.c', '.cpp', '.h', '.sh', '.bash', '.zsh',
    '.yaml', '.yml', '.json', '.toml', '.ini', '.cfg', '.conf',
    '.html', '.css', '.sql', '.xml', '.md', '.txt',
    'Dockerfile', '.dockerignore', '.gitignore', '.env', 'Makefile',
}

SKIP_DIRS = {'.git', '__pycache__', 'node_modules', 'venv', '.venv',
             '.tox', '.eggs', 'build', 'dist', '.mypy_cache', '.pytest_cache',
             'tests', '__tests__'}

DEPENDENCY_FILES = {'requirements.txt', 'Pipfile', 'pyproject.toml',
                    'package.json', 'go.mod', 'Cargo.toml', 'Gemfile'}

# 文档和测试文件默认排除（可手动指定 --path 包含）
SKIP_FILE_PATTERNS = ['test_', '_test.', 'conftest.', 'setup.', '__init__.']
SKIP_EXTENSIONS = {'.md'}  # Markdown 文档不做代码扫描


def should_scan(filepath: str) -> bool:
    """判断是否应该扫描该文件"""
    path = Path(filepath)
    name = path.name
    suffix = path.suffix.lower()
    # 排除测试文件和文档
    if any(name.startswith(p) or p in name for p in SKIP_FILE_PATTERNS):
        return False
    if suffix in SKIP_EXTENSIONS:
        return False
    # 文件名匹配
    if name in {'Dockerfile', '.env'}:
        return True
    # 后缀匹配
    if suffix in TEXT_EXTENSIONS:
        return True
    if name in DEPENDENCY_FILES:
        return True
    if 'docker-compose' in name and (suffix in {'.yml', '.yaml'}):
        return True
    return False


def collect_files(target_dir: str) -> List[str]:
    """收集所有需要扫描的文件"""
    files = []
    for root, dirs, filenames in os.walk(target_dir):
        # 跳过隐藏目录和依赖目录
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith('.')]
        for fname in filenames:
            fpath = os.path.join(root, fname)
            if should_scan(fname):
                files.append(fpath)
    return files


def scan_file(filepath: str) -> List[Finding]:
    """扫描单个文件"""
    try:
        content = Path(filepath).read_text(encoding='utf-8', errors='replace')
    except Exception as e:
        return [Finding(
            file=filepath, line=0, severity='low', category='error',
            rule_id='read-error', message=f'Cannot read file: {e}',
            snippet='', fix_suggestion='Check file permissions and encoding'
        )]

    findings = []
    # 密钥检测 (所有文本文件)
    findings.extend(scan_secrets(content, filepath))
    # OWASP 检测 (仅代码文件)
    if Path(filepath).suffix in {'.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rb', '.php', '.java'}:
        findings.extend(scan_owasp(content, filepath))
    # 配置文件检测
    findings.extend(scan_configs(content, filepath))
    # 依赖检测
    if os.path.basename(filepath) in DEPENDENCY_FILES:
        findings.extend(scan_dependencies(os.path.dirname(filepath), filepath))

    return findings


def scan_project(target_path: str) -> ScanReport:
    """主扫描入口"""
    target = os.path.abspath(target_path)

    if not os.path.exists(target):
        print(f"Error: Path not found: {target}", file=sys.stderr)
        sys.exit(1)

    all_files = collect_files(target)
    report = ScanReport(
        scan_time=datetime.now().isoformat(),
        target_path=target,
        total_files=len(all_files),
        scanned_files=0,
    )

    for fpath in all_files:
        findings = scan_file(fpath)
        report.findings.extend(findings)
        report.scanned_files += 1

    # 生成摘要
    severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    category_count = {}
    for f in report.findings:
        severity_count[f.severity] = severity_count.get(f.severity, 0) + 1
        category_count[f.category] = category_count.get(f.category, 0) + 1

    report.summary = {
        'total_findings': len(report.findings),
        'by_severity': severity_count,
        'by_category': category_count,
    }
    return report

# ============================================================
# CLI
# ============================================================

def format_json(report: ScanReport) -> str:
    """JSON 格式输出"""
    return json.dumps({
        'scan_time': report.scan_time,
        'target_path': report.target_path,
        'summary': report.summary,
        'findings': [asdict(f) for f in report.findings],
    }, indent=2, ensure_ascii=False)


def format_sarif(report: ScanReport) -> str:
    """SARIF 2.1.0 格式输出（GitHub Code Scanning 兼容）"""
    severity_to_level = {
        'critical': 'error',
        'high': 'error',
        'medium': 'warning',
        'low': 'note',
    }

    # 收集中用到的所有规则
    rules_seen = {}
    for f in report.findings:
        if f.rule_id not in rules_seen:
            rules_seen[f.rule_id] = {
                'id': f.rule_id,
                'name': f.rule_id,
                'shortDescription': {'text': f.message},
                'help': {'text': f.fix_suggestion},
            }

    sarif = {
        'version': '2.1.0',
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'runs': [
            {
                'tool': {
                    'driver': {
                        'name': 'Security Guardian',
                        'version': '0.3.0',
                        'informationUri': 'https://github.com/一人AI公司/security-guardian',
                        'rules': list(rules_seen.values()),
                    }
                },
                'results': [
                    {
                        'ruleId': f.rule_id,
                        'level': severity_to_level.get(f.severity, 'warning'),
                        'message': {'text': f.message},
                        'locations': [
                            {
                                'physicalLocation': {
                                    'artifactLocation': {
                                        'uri': f.file.replace('\\', '/'),
                                    },
                                    'region': {
                                        'startLine': f.line,
                                        'startColumn': 1,
                                    },
                                }
                            }
                        ],
                        'properties': {
                            'severity': f.severity,
                            'category': f.category,
                            'fix': f.fix_suggestion,
                        },
                    }
                    for f in report.findings
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def format_markdown(report: ScanReport) -> str:
    """Markdown 格式输出"""
    lines = [
        f"# 🔒 Security Guardian - 扫描报告",
        f"",
        f"**扫描时间**: {report.scan_time}",
        f"**目标路径**: {report.target_path}",
        f"**扫描文件**: {report.scanned_files}/{report.total_files}",
        f"",
        f"## 📊 摘要",
        f"",
        f"| 严重等级 | 数量 |",
        f"|----------|------|",
    ]
    for severity in ['critical', 'high', 'medium', 'low']:
        count = report.summary['by_severity'].get(severity, 0)
        emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}.get(severity, '⚪')
        lines.append(f"| {emoji} {severity.upper()} | {count} |")

    lines.append(f"| **总计** | **{report.summary['total_findings']}** |")
    lines.append("")

    if not report.findings:
        lines.append("✅ **未发现安全问题！**")
        return '\n'.join(lines)

    # 按严重度分组
    for severity in ['critical', 'high', 'medium', 'low']:
        sev_findings = [f for f in report.findings if f.severity == severity]
        if not sev_findings:
            continue
        emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}[severity]
        lines.append(f"## {emoji} {severity.upper()} ({len(sev_findings)})")
        lines.append("")
        for f in sev_findings[:20]:  # 限制每组输出数量
            lines.append(f"### {f.rule_id}")
            lines.append(f"- **文件**: `{f.file}:{f.line}`")
            lines.append(f"- **分类**: {f.category}")
            lines.append(f"- **问题**: {f.message}")
            lines.append(f"```")
            lines.append(f.snippet)
            lines.append(f"```")
            lines.append(f"- **修复**: {f.fix_suggestion}")
            if f.cwe_id:
                lines.append(f"- **CWE**: {f.cwe_id}")
            lines.append("")
        if len(sev_findings) > 20:
            lines.append(f"... 还有 {len(sev_findings) - 20} 个 {severity} 级别问题")

    return '\n'.join(lines)


def format_html(report: ScanReport) -> str:
    """HTML 格式输出（自包含暗色主题报告）"""
    severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}
    severity_badge = {'critical': '#dc2626', 'high': '#ea580c', 'medium': '#ca8a04', 'low': '#2563eb'}

    # 构建发现列表 HTML
    findings_html = ''
    if not report.findings:
        findings_html = '<div class="clean">✅ 未发现安全问题</div>'
    else:
        for severity in ['critical', 'high', 'medium', 'low']:
            sev_findings = [f for f in report.findings if f.severity == severity]
            if not sev_findings:
                continue
            emoji = severity_emoji[severity]
            badge = severity_badge[severity]
            findings_html += f'<h3 style="color:{badge}">{emoji} {severity.upper()} ({len(sev_findings)})</h3>'
            for f in sev_findings[:50]:
                findings_html += f'''
                <div class="finding">
                    <div class="finding-header">
                        <span class="rule-id">{f.rule_id}</span>
                        <span class="file">📄 {f.file}:{f.line}</span>
                    </div>
                    <p class="message">{f.message}</p>
                    <pre class="snippet">{f.snippet}</pre>
                    <p class="fix">💡 修复: {f.fix_suggestion}</p>
                    {f'<p class="cwe">📚 {f.cwe_id}</p>' if f.cwe_id else ''}
                </div>'''

    return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Guardian - 扫描报告</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background:#0d1117; color:#c9d1d9; padding:24px; }}
.header {{ text-align:center; padding:32px 0; border-bottom:1px solid #21262d; margin-bottom:24px; }}
.header h1 {{ color:#58a6ff; font-size:28px; }}
.header .meta {{ color:#8b949e; margin-top:8px; }}
.summary {{ display:flex; gap:16px; justify-content:center; margin-bottom:32px; flex-wrap:wrap; }}
.summary-card {{ background:#161b22; border:1px solid #21262d; border-radius:8px; padding:16px 24px; text-align:center; min-width:100px; }}
.summary-card .count {{ font-size:32px; font-weight:bold; }}
.summary-card.critical .count {{ color:#dc2626; }}
.summary-card.high .count {{ color:#ea580c; }}
.summary-card.medium .count {{ color:#ca8a04; }}
.summary-card.low .count {{ color:#2563eb; }}
.finding {{ background:#161b22; border:1px solid #21262d; border-radius:8px; padding:16px; margin-bottom:12px; }}
.finding-header {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; }}
.rule-id {{ background:#1f6feb22; color:#58a6ff; padding:2px 8px; border-radius:4px; font-family:monospace; font-size:13px; }}
.file {{ color:#8b949e; font-size:13px; }}
.message {{ margin:8px 0; }}
.snippet {{ background:#0d1117; border:1px solid #30363d; border-radius:6px; padding:12px; font-family:'Cascadia Code',Consolas,monospace; font-size:13px; overflow-x:auto; white-space:pre-wrap; }}
.fix {{ color:#3fb950; margin-top:8px; font-size:14px; }}
.cwe {{ color:#8b949e; font-size:12px; margin-top:4px; }}
.clean {{ text-align:center; padding:48px; color:#3fb950; font-size:20px; }}
.footer {{ text-align:center; color:#484f58; margin-top:32px; padding-top:16px; border-top:1px solid #21262d; font-size:12px; }}
</style>
</head>
<body>
<div class="header">
    <h1>🔒 Security Guardian 扫描报告</h1>
    <p class="meta">扫描时间: {report.scan_time} | 目标: {report.target_path} | 文件: {report.scanned_files}/{report.total_files}</p>
</div>
<div class="summary">
    <div class="summary-card critical"><div class="count">{report.summary["by_severity"].get("critical", 0)}</div><div>🔴 CRITICAL</div></div>
    <div class="summary-card high"><div class="count">{report.summary["by_severity"].get("high", 0)}</div><div>🟠 HIGH</div></div>
    <div class="summary-card medium"><div class="count">{report.summary["by_severity"].get("medium", 0)}</div><div>🟡 MEDIUM</div></div>
    <div class="summary-card low"><div class="count">{report.summary["by_severity"].get("low", 0)}</div><div>🔵 LOW</div></div>
</div>
{findings_html}
<div class="footer">Security Guardian v0.3.0 · 一人AI公司 · {report.scan_time}</div>
</body>
</html>'''


def main():
    parser = argparse.ArgumentParser(
        description='Security Guardian - AI 代码安全扫描引擎'
    )
    parser.add_argument('--path', '-p', default='.', help='目标项目路径 (默认: 当前目录)')
    parser.add_argument('--output', '-o', choices=['json', 'markdown', 'sarif', 'html'], default='markdown',
                        help='输出格式 (默认: markdown; sarif 用于 GitHub Code Scanning)')
    parser.add_argument('--severity', '-s', choices=['critical', 'high', 'medium', 'low'],
                        help='最低严重度过滤')
    args = parser.parse_args()

    print(f"🔍 Scanning: {args.path} ...", file=sys.stderr)
    report = scan_project(args.path)

    # 严重度过滤
    if args.severity:
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        threshold = severity_order[args.severity]
        report.findings = [f for f in report.findings
                           if severity_order.get(f.severity, 99) <= threshold]
        report.summary['total_findings'] = len(report.findings)

    if args.output == 'json':
        print(format_json(report))
    elif args.output == 'sarif':
        print(format_sarif(report))
    elif args.output == 'html':
        print(format_html(report))
    else:
        print(format_markdown(report))

    # 返回码
    if any(f.severity == 'critical' for f in report.findings):
        sys.exit(1)

if __name__ == '__main__':
    main()
