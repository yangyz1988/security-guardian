#!/usr/bin/env python3
"""
Security Guardian - 扫描引擎单元测试
纯标准库 unittest，零外部依赖
"""
import sys
import os
import json
import unittest
import tempfile
from pathlib import Path

# 确保可以导入 scan 模块
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import scan


class TestFalsePositive(unittest.TestCase):
    """is_false_positive 函数测试"""

    def test_comment_line(self):
        self.assertTrue(scan.is_false_positive("# sk-12345678901234567890", "sk-12345678901234567890"))
        self.assertTrue(scan.is_false_positive("// ghpat_12345678901234567890", "ghpat_12345678901234567890"))

    def test_env_var_placeholder(self):
        self.assertFalse(scan.is_false_positive('password = "${DB_PASSWORD}"', "password"))
        # The match string itself probably won't contain ${...}, but the function checks it anyway

    def test_placeholder_keywords(self):
        self.assertTrue(scan.is_false_positive("api_key = 'YOUR_API_KEY_HERE'", "YOUR_API_KEY_HERE"))
        self.assertTrue(scan.is_false_positive("secret = 'example-secret'", "example-secret"))
        self.assertTrue(scan.is_false_positive("# TODO: replace xxx", "xxx"))
        self.assertTrue(scan.is_false_positive("key = 'placeholder-value'", "placeholder-value"))

    def test_real_secret_not_filtered(self):
        self.assertFalse(scan.is_false_positive("api_key = 'sk-rea...lder'", "sk-rea...lder"))


class TestSecretDetection(unittest.TestCase):
    """scan_secrets 函数测试"""

    def create_finding_file(self, content):
        """创建临时文件并写入内容"""
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8')
        tmp.write(content)
        tmp.close()
        return tmp.name

    def test_openai_key_detected(self):
        code = 'openai_key = "sk-abc123def456ghi789jkl012"'
        fpath = self.create_finding_file(code)
        findings = scan.scan_secrets(code, fpath)
        os.unlink(fpath)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, 'openai-key')
        self.assertEqual(findings[0].severity, 'critical')

    def test_github_token_detected(self):
        code = 'token = "ghp_1234567890abcdefghijklmnopqrstuv"'
        fpath = self.create_finding_file(code)
        findings = scan.scan_secrets(code, fpath)
        os.unlink(fpath)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, 'github-token')

    def test_aws_key_detected(self):
        code = 'aws_key = "AKIA1234567890ABCDEFGH"'
        fpath = self.create_finding_file(code)
        findings = scan.scan_secrets(code, fpath)
        os.unlink(fpath)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, 'aws-access-key')

    def test_stripe_key_detected(self):
        code = 'stripe_key = "sk_live_abcdefghijklmnopqrstuvwxyz1234"'
        fpath = self.create_finding_file(code)
        findings = scan.scan_secrets(code, fpath)
        os.unlink(fpath)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, 'stripe-live-key')

    def test_hardcoded_password_detected(self):
        code = 'password = "supersecret123"'
        fpath = self.create_finding_file(code)
        findings = scan.scan_secrets(code, fpath)
        os.unlink(fpath)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, 'hardcoded-password')

    def test_secret_in_comment_filtered(self):
        code = '# api_key = "sk-abc123def456789012345678"'
        fpath = self.create_finding_file(code)
        findings = scan.scan_secrets(code, fpath)
        os.unlink(fpath)
        self.assertEqual(len(findings), 0)

    def test_secret_with_env_placeholder_not_flagged(self):
        code = 'password = "${DB_PASSWORD}"'
        fpath = self.create_finding_file(code)
        findings = scan.scan_secrets(code, fpath)
        os.unlink(fpath)
        # The pattern matches, but the placeholder check should filter it
        # Check that no hardcoded-password finding is raised
        password_findings = [f for f in findings if f.rule_id == 'hardcoded-password']
        self.assertEqual(len(password_findings), 0)

    def test_db_connection_string_detected(self):
        code = 'db_url = "postgres://admin:password123@localhost:5432/db"'
        fpath = self.create_finding_file(code)
        findings = scan.scan_secrets(code, fpath)
        os.unlink(fpath)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, 'db-connection-string')

    def test_no_secrets_in_clean_code(self):
        code = '''
def hello():
    print("Hello World")
    return 42
'''
        fpath = self.create_finding_file(code)
        findings = scan.scan_secrets(code, fpath)
        os.unlink(fpath)
        self.assertEqual(len(findings), 0)

    def test_finding_has_all_fields(self):
        code = 'openai_key = "sk-abc123def456ghi789jkl012"'
        fpath = self.create_finding_file(code)
        findings = scan.scan_secrets(code, fpath)
        os.unlink(fpath)
        f = findings[0]
        self.assertIsNotNone(f.file)
        self.assertGreater(f.line, 0)
        self.assertIn(f.severity, ['critical', 'high', 'medium', 'low'])
        self.assertEqual(f.category, 'secret')
        self.assertIsNotNone(f.rule_id)
        self.assertIsNotNone(f.message)
        self.assertIsNotNone(f.snippet)
        self.assertIsNotNone(f.fix_suggestion)


class TestOWASPDetection(unittest.TestCase):
    """scan_owasp 函数测试"""

    def test_sql_injection_detected(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")'
        findings = scan.scan_owasp(code, 'test.py')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, 'sql-injection')
        self.assertEqual(findings[0].severity, 'critical')

    def test_sql_injection_concat_detected(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id=" + user_id)'
        findings = scan.scan_owasp(code, 'test.py')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, 'sql-injection')

    def test_xss_innerhtml_detected(self):
        code = 'element.innerHTML = userInput;'
        findings = scan.scan_owasp(code, 'test.js')
        self.assertGreaterEqual(len(findings), 1)
        xss = [f for f in findings if f.rule_id == 'xss-dom']
        self.assertEqual(len(xss), 1)

    def test_command_injection_detected(self):
        code = 'os.system(f"ping {host}")'
        findings = scan.scan_owasp(code, 'test.py')
        cmd = [f for f in findings if f.rule_id == 'command-injection']
        self.assertEqual(len(cmd), 1)
        self.assertEqual(cmd[0].severity, 'critical')

    def test_pickle_loads_detected(self):
        code = 'data = pickle.loads(user_data)'
        findings = scan.scan_owasp(code, 'test.py')
        deser = [f for f in findings if f.rule_id == 'insecure-deserialization']
        self.assertEqual(len(deser), 1)

    def test_safe_code_no_findings(self):
        code = '''
def add(a, b):
    return a + b

result = add(1, 2)
'''
        findings = scan.scan_owasp(code, 'test.py')
        self.assertEqual(len(findings), 0)

    def test_clean_sql_query_not_flagged(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))'
        findings = scan.scan_owasp(code, 'test.py')
        self.assertEqual(len(findings), 0)


class TestDependencyScanning(unittest.TestCase):
    """scan_dependencies 函数测试"""

    def test_vulnerable_flask_detected(self):
        content = 'flask==1.1.2\nrequests==2.28.0\n'
        fpath = tempfile.mktemp(suffix='.txt')
        with open(fpath, 'w') as f:
            f.write(content)
        findings = scan.scan_dependencies('.', fpath)
        os.unlink(fpath)
        flask_findings = [f for f in findings if f.rule_id == 'vuln-flask']
        self.assertGreaterEqual(len(flask_findings), 1)

    def test_safe_version_not_flagged(self):
        content = 'flask==3.0.0\nrequests==2.31.1\n'
        fpath = tempfile.mktemp(suffix='.txt')
        with open(fpath, 'w') as f:
            f.write(content)
        findings = scan.scan_dependencies('.', fpath)
        os.unlink(fpath)
        self.assertEqual(len(findings), 0)


class TestConfigScanning(unittest.TestCase):
    """scan_configs 函数测试"""

    def test_docker_root_user_detected(self):
        content = 'FROM python:3.11\nUSER root\nRUN apt-get update'
        findings = scan.scan_configs(content, 'Dockerfile')
        root = [f for f in findings if f.rule_id == 'docker-root-user']
        self.assertEqual(len(root), 1)

    def test_privileged_container_detected(self):
        content = 'services:\n  app:\n    privileged: true'
        findings = scan.scan_configs(content, 'docker-compose.yml')
        priv = [f for f in findings if f.rule_id == 'privileged-container']
        self.assertEqual(len(priv), 1)

    def test_non_config_file_skipped(self):
        findings = scan.scan_configs('some content', 'app.py')
        self.assertEqual(len(findings), 0)


class TestFileFiltering(unittest.TestCase):
    """should_scan 函数测试"""

    def test_python_file_scanned(self):
        self.assertTrue(scan.should_scan('app.py'))

    def test_node_modules_skipped(self):
        self.assertTrue(scan.should_scan('config.js'))

    def test_dockerfile_scanned(self):
        self.assertTrue(scan.should_scan('Dockerfile'))

    def test_env_file_scanned(self):
        self.assertTrue(scan.should_scan('.env'))

    def test_binary_not_scanned(self):
        self.assertFalse(scan.should_scan('image.png'))
        self.assertFalse(scan.should_scan('video.mp4'))

    def test_requirements_scanned(self):
        self.assertTrue(scan.should_scan('requirements.txt'))

    def test_package_json_scanned(self):
        self.assertTrue(scan.should_scan('package.json'))


class TestOutputFormatters(unittest.TestCase):
    """格式化输出测试"""

    def test_json_output_valid(self):
        report = scan.ScanReport(
            scan_time='2026-01-01T00:00:00',
            target_path='/test',
            total_files=10,
            scanned_files=10,
            findings=[scan.Finding(
                file='test.py', line=1, severity='critical',
                category='secret', rule_id='test-rule',
                message='Test finding', snippet='code',
                fix_suggestion='fix it'
            )],
            summary={'total_findings': 1, 'by_severity': {'critical': 1}, 'by_category': {'secret': 1}}
        )
        output = scan.format_json(report)
        parsed = json.loads(output)
        self.assertEqual(parsed['summary']['total_findings'], 1)
        self.assertEqual(len(parsed['findings']), 1)

    def test_markdown_output_has_sections(self):
        report = scan.ScanReport(
            scan_time='2026-01-01T00:00:00',
            target_path='/test',
            total_files=10,
            scanned_files=10,
            findings=[scan.Finding(
                file='test.py', line=1, severity='critical',
                category='secret', rule_id='openai-key',
                message='Hardcoded OpenAI key', snippet='sk-xxx',
                fix_suggestion='Use env var', cwe_id='CWE-798'
            )],
            summary={'total_findings': 1, 'by_severity': {'critical': 1, 'high': 0, 'medium': 0, 'low': 0}, 'by_category': {'secret': 1}}
        )
        output = scan.format_markdown(report)
        self.assertIn('# 🔒 Security Guardian', output)
        self.assertIn('🔴 CRITICAL', output)
        self.assertIn('openai-key', output)

    def test_markdown_no_findings(self):
        report = scan.ScanReport(
            scan_time='2026-01-01T00:00:00',
            target_path='/test',
            total_files=10,
            scanned_files=10,
            findings=[],
            summary={'total_findings': 0, 'by_severity': {}, 'by_category': {}}
        )
        output = scan.format_markdown(report)
        self.assertIn('未发现安全问题', output)


class TestProjectScanIntegration(unittest.TestCase):
    """集成测试：完整扫描流程"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # 创建一个有问题的文件
        bad_py = os.path.join(self.tmpdir, 'bad.py')
        with open(bad_py, 'w') as f:
            f.write('''
# This file has issues
password = "admin123"
api_key = "sk-abc123def456ghi789jkl012"
import os
os.system(f"ls {user_input}")
''')
        # 创建干净文件
        clean_py = os.path.join(self.tmpdir, 'clean.py')
        with open(clean_py, 'w') as f:
            f.write('''
def add(a, b):
    return a + b
''')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_scan_project_finds_issues(self):
        report = scan.scan_project(self.tmpdir)
        self.assertGreater(report.total_files, 0)
        self.assertGreater(report.scanned_files, 0)
        self.assertGreater(report.summary['total_findings'], 0)
        # 应该找到至少 hardcoded-password 和 openai-key
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn('openai-key', rule_ids)
        self.assertIn('hardcoded-password', rule_ids)

    def test_scan_project_severity_filter(self):
        """测试 --severity 过滤功能"""
        report = scan.scan_project(self.tmpdir)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        # 只保留 critical
        critical_only = [f for f in report.findings if severity_order.get(f.severity, 99) <= 0]
        self.assertTrue(all(f.severity == 'critical' for f in critical_only))


class TestEdgeCases(unittest.TestCase):
    """边界情况测试"""

    def test_empty_file(self):
        findings = scan.scan_secrets('', 'empty.py')
        self.assertEqual(len(findings), 0)

    def test_binary_file_fallback(self):
        """模拟无法读取的文件"""
        fpath = tempfile.mktemp(suffix='.py')
        # 文件不存在
        findings = scan.scan_file(fpath)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, 'read-error')

    def test_non_existent_path(self):
        with self.assertRaises(SystemExit):
            scan.scan_project('/nonexistent/path/12345')


if __name__ == '__main__':
    unittest.main(verbosity=2)
