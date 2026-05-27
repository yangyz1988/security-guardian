#!/usr/bin/env python3
"""Security Guardian — PDF 合规报告生成器

生成专业的 PDF 安全审计/合规报告，面向：
- 客户交付（$99/次 合规报告）
- 内部安全审计
- SOC2 / ISO 27001 / PCI-DSS 合规映射

依赖: reportlab (pip install reportlab)
Pro 功能: 需要 License Key 激活
"""
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# reportlab 导入
from reportlab.lib import colors


def _rgb_to_hex(rgb: tuple) -> str:
    """将 (R,G,B) 0-1 浮点元组转为 #RRGGBB 十六进制"""
    return "#{:02x}{:02x}{:02x}".format(
        int(rgb[0] * 255), int(rgb[1] * 255), int(rgb[2] * 255)
    )
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm, cm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, PageBreak,
    Paragraph, Spacer, Table, TableStyle, KeepTogether,
    ListFlowable, ListItem,
)
from reportlab.platypus.frames import Frame
from reportlab.platypus.doctemplate import PageTemplate

# 确保可导入
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from scan import Finding, ScanReport, format_markdown

# ──────────────────────────────────────────────
# 合规框架映射
# ──────────────────────────────────────────────

COMPLIANCE_FRAMEWORKS = {
    "owasp": {
        "name": "OWASP Top 10 (2021)",
        "description": "Open Web Application Security Project Top 10 — 业界最广泛采纳的 Web 应用安全标准。",
        "standards": {
            "sql-injection": {"id": "A03:2021", "name": "Injection"},
            "xss-dom": {"id": "A03:2021", "name": "Injection (XSS)"},
            "command-injection": {"id": "A03:2021", "name": "Injection"},
            "path-traversal": {"id": "A01:2021", "name": "Broken Access Control"},
            "insecure-deserialization": {"id": "A08:2021", "name": "Software and Data Integrity Failures"},
            "xxe": {"id": "A05:2021", "name": "Security Misconfiguration"},
            "nosql-injection": {"id": "A03:2021", "name": "Injection"},
            "open-redirect": {"id": "A01:2021", "name": "Broken Access Control"},
            "ldap-injection": {"id": "A03:2021", "name": "Injection"},
            "ssrf-risk": {"id": "A10:2021", "name": "Server-Side Request Forgery"},
            "openai-key": {"id": "A05:2021", "name": "Security Misconfiguration (Secrets)"},
            "github-token": {"id": "A05:2021", "name": "Security Misconfiguration (Secrets)"},
            "aws-access-key": {"id": "A05:2021", "name": "Security Misconfiguration (Secrets)"},
            "private-key": {"id": "A05:2021", "name": "Security Misconfiguration (Secrets)"},
            "stripe-live-key": {"id": "A05:2021", "name": "Security Misconfiguration (Secrets)"},
            "db-connection-string": {"id": "A05:2021", "name": "Security Misconfiguration (Secrets)"},
        },
    },
    "soc2": {
        "name": "SOC 2 (Trust Services Criteria)",
        "description": "Service Organization Control 2 — 面向服务组织的安全、可用性、处理完整性、保密性和隐私标准。",
        "standards": {
            "openai-key": {"id": "CC6.1", "name": "Logical and Physical Access Controls"},
            "github-token": {"id": "CC6.1", "name": "Logical and Physical Access Controls"},
            "aws-access-key": {"id": "CC6.1", "name": "Logical and Physical Access Controls"},
            "private-key": {"id": "CC6.1", "name": "Logical and Physical Access Controls"},
            "stripe-live-key": {"id": "CC6.1", "name": "Logical and Physical Access Controls"},
            "db-connection-string": {"id": "CC6.1", "name": "Logical and Physical Access Controls"},
            "slack-token": {"id": "CC6.1", "name": "Logical and Physical Access Controls"},
            "gitlab-token": {"id": "CC6.1", "name": "Logical and Physical Access Controls"},
            "generic-api-key": {"id": "CC6.1", "name": "Logical and Physical Access Controls"},
            "hardcoded-password": {"id": "CC6.1", "name": "Logical and Physical Access Controls"},
            "jwt-token": {"id": "CC6.1", "name": "Logical and Physical Access Controls"},
            "sql-injection": {"id": "CC7.1", "name": "System Operations — Change Management"},
            "command-injection": {"id": "CC7.1", "name": "System Operations — Change Management"},
            "xxe": {"id": "CC7.1", "name": "System Operations — Change Management"},
            "insecure-deserialization": {"id": "CC7.1", "name": "System Operations — Change Management"},
            "nosql-injection": {"id": "CC7.1", "name": "System Operations — Change Management"},
            "ldap-injection": {"id": "CC7.1", "name": "System Operations — Change Management"},
            "docker-root": {"id": "CC6.3", "name": "Risk Mitigation — Configuration"},
        },
    },
    "iso27001": {
        "name": "ISO/IEC 27001:2022",
        "description": "信息安全管理体系 (ISMS) — 国际标准，覆盖组织的信息安全风险管理。",
        "standards": {
            "openai-key": {"id": "A.8.24", "name": "Use of cryptography"},
            "github-token": {"id": "A.8.24", "name": "Use of cryptography"},
            "aws-access-key": {"id": "A.8.24", "name": "Use of cryptography"},
            "private-key": {"id": "A.8.24", "name": "Use of cryptography"},
            "db-connection-string": {"id": "A.8.24", "name": "Use of cryptography"},
            "generic-api-key": {"id": "A.8.24", "name": "Use of cryptography"},
            "hardcoded-password": {"id": "A.9.4.3", "name": "Access control — Password management"},
            "sql-injection": {"id": "A.8.25", "name": "Secure development lifecycle"},
            "xss-dom": {"id": "A.8.25", "name": "Secure development lifecycle"},
            "command-injection": {"id": "A.8.25", "name": "Secure development lifecycle"},
            "path-traversal": {"id": "A.8.25", "name": "Secure development lifecycle"},
            "xxe": {"id": "A.8.25", "name": "Secure development lifecycle"},
            "insecure-deserialization": {"id": "A.8.25", "name": "Secure development lifecycle"},
            "docker-root": {"id": "A.8.9", "name": "Configuration management"},
        },
    },
    "pci": {
        "name": "PCI DSS v4.0",
        "description": "支付卡行业数据安全标准 — 面向处理信用卡支付的组织。",
        "standards": {
            "openai-key": {"id": "Req 3", "name": "Protect stored cardholder data"},
            "github-token": {"id": "Req 7", "name": "Restrict access by need-to-know"},
            "aws-access-key": {"id": "Req 7", "name": "Restrict access by need-to-know"},
            "private-key": {"id": "Req 3", "name": "Protect stored cardholder data"},
            "db-connection-string": {"id": "Req 3", "name": "Protect stored cardholder data"},
            "hardcoded-password": {"id": "Req 8", "name": "Identify and authenticate access"},
            "sql-injection": {"id": "Req 6", "name": "Develop and maintain secure systems"},
            "xss-dom": {"id": "Req 6", "name": "Develop and maintain secure systems"},
            "command-injection": {"id": "Req 6", "name": "Develop and maintain secure systems"},
            "path-traversal": {"id": "Req 6", "name": "Develop and maintain secure systems"},
        },
    },
}

SEVERITY_COLORS = {
    "critical": (0.86, 0.15, 0.15),   # #dc2626
    "high": (0.92, 0.34, 0.05),       # #ea580c
    "medium": (0.79, 0.62, 0.02),     # #ca8a04
    "low": (0.15, 0.39, 0.92),        # #2563eb
}

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

# 需 license 才可以使用的功能
REQUIRES_PRO = True  # PDF 合规报告是 Pro 功能


def _check_license():
    """检查是否有 Pro License。返回 (可以继续, 提示消息)"""
    try:
        from license import require_license
        if not require_license("pdf_compliance"):
            return False, (
                "PDF Compliance Report 是 Pro 功能。\n"
                "请设置 License Key 激活:\n"
                "  python middleware/mcp_proxy.py --license SG-XXX-XXX"
            )
    except ImportError:
        pass  # 开发环境跳过
    return True, None


# ═══════════════════════════════════════════
# 样式定义
# ═══════════════════════════════════════════

_styles = getSampleStyleSheet()


class ReportStyles:
    """PDF 报告中使用的所有样式"""

    cover_title = ParagraphStyle(
        "CoverTitle", fontSize=28, leading=36,
        textColor=colors.HexColor("#0ea5e9"),
        spaceAfter=12, alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    )
    cover_subtitle = ParagraphStyle(
        "CoverSubtitle", fontSize=14, leading=20,
        textColor=colors.HexColor("#94a3b8"),
        spaceAfter=40, alignment=TA_CENTER,
        fontName="Helvetica",
    )
    cover_meta = ParagraphStyle(
        "CoverMeta", fontSize=10, leading=14,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=6, alignment=TA_CENTER,
        fontName="Helvetica",
    )
    section_header = ParagraphStyle(
        "SectionHeader", fontSize=16, leading=22,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=20, spaceAfter=10,
        fontName="Helvetica-Bold",
        borderWidth=0, borderPadding=0,
        borderColor=colors.HexColor("#0ea5e9"),
    )
    subsection_header = ParagraphStyle(
        "SubsectionHeader", fontSize=12, leading=16,
        textColor=colors.HexColor("#334155"),
        spaceBefore=12, spaceAfter=6,
        fontName="Helvetica-Bold",
    )
    body = ParagraphStyle(
        "BodyCustom", fontSize=9, leading=13,
        textColor=colors.HexColor("#475569"),
        spaceAfter=6, alignment=TA_JUSTIFY,
        fontName="Helvetica",
    )
    body_bold = ParagraphStyle(
        "BodyBold", fontSize=9, leading=13,
        textColor=colors.HexColor("#1e293b"),
        fontName="Helvetica-Bold",
    )
    finding_title = ParagraphStyle(
        "FindingTitle", fontSize=10, leading=14,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=4, spaceAfter=2,
        fontName="Helvetica-Bold",
    )
    finding_meta = ParagraphStyle(
        "FindingMeta", fontSize=8, leading=11,
        textColor=colors.HexColor("#64748b"),
        fontName="Helvetica",
    )
    code = ParagraphStyle(
        "Code", fontSize=7, leading=10,
        textColor=colors.HexColor("#334155"),
        backColor=colors.HexColor("#f1f5f9"),
        borderPadding=6, fontName="Courier",
        spaceAfter=4,
    )
    footer = ParagraphStyle(
        "Footer", fontSize=7, leading=10,
        textColor=colors.HexColor("#94a3b8"),
        alignment=TA_CENTER,
        fontName="Helvetica",
    )
    disclaimer = ParagraphStyle(
        "Disclaimer", fontSize=7, leading=10,
        textColor=colors.HexColor("#94a3b8"),
        alignment=TA_CENTER,
        fontName="Helvetica-Oblique",
        spaceBefore=20,
    )
    compliance_tag = ParagraphStyle(
        "ComplianceTag", fontSize=7, leading=10,
        textColor=colors.HexColor("#0ea5e9"),
        fontName="Helvetica-Bold",
    )
    summary_number = ParagraphStyle(
        "SummaryNumber", fontSize=22, leading=28,
        textColor=colors.HexColor("#1e293b"),
        alignment=TA_CENTER, fontName="Helvetica-Bold",
    )
    summary_label = ParagraphStyle(
        "SummaryLabel", fontSize=8, leading=11,
        textColor=colors.HexColor("#64748b"),
        alignment=TA_CENTER, fontName="Helvetica",
    )
    severity_label = ParagraphStyle(
        "SeverityLabel", fontSize=8, leading=11,
        alignment=TA_CENTER, fontName="Helvetica-Bold",
        textColor=colors.white,
    )


S = ReportStyles()


# ═══════════════════════════════════════════
# 构建器
# ═══════════════════════════════════════════

def _compliance_tags(findings: list[Finding], framework: str) -> list[tuple[Finding, Optional[dict]]]:
    """将发现映射到合规框架标准。返回 (finding, mapped_standard) 列表"""
    framework_data = COMPLIANCE_FRAMEWORKS.get(framework, {})
    standards = framework_data.get("standards", {})

    result = []
    for f in findings:
        mapping = standards.get(f.rule_id)
        result.append((f, mapping))
    return result


def build_pdf_report(
    report: ScanReport,
    output_path: str,
    framework: Optional[str] = None,
    company_name: str = "",
    project_name: str = "",
) -> str:
    """生成 PDF 合规报告。

    参数:
        report: ScanReport 对象
        output_path: 输出文件路径
        framework: 合规框架缩写 (owasp / soc2 / iso27001 / pci)
        company_name: 公司名称
        project_name: 项目名称

    返回:
        生成的 PDF 文件路径
    """
    # ── License check ──
    ok, msg = _check_license()
    if not ok:
        print(f"❌ {msg}", file=sys.stderr)
        sys.exit(1)

    doc = BaseDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
        title=f"Security Guardian — Security Audit Report",
        author="Security Guardian",
    )

    frame = Frame(
        doc.leftMargin, doc.bottomMargin,
        doc.width, doc.height,
        id="normal",
    )
    doc.addPageTemplates([PageTemplate(id="main", frames=frame)])

    # 收集元素
    story = []

    # ── COVER PAGE ──
    story.append(Spacer(1, 80))
    story.append(Paragraph("🛡️ Security Guardian", S.cover_title))
    story.append(Paragraph("Compliance Security Audit Report", S.cover_subtitle))
    story.append(Spacer(1, 30))

    # 报表元信息
    meta_lines = [
        f"生成日期: {report.scan_time}",
        f"扫描目标: {report.target_path}",
        f"扫描文件: {report.scanned_files} / {report.total_files}",
    ]
    if company_name:
        meta_lines.insert(0, f"公司: {company_name}")
    if project_name:
        meta_lines.insert(0, f"项目: {project_name}")
    if framework:
        fw = COMPLIANCE_FRAMEWORKS.get(framework, {})
        meta_lines.append(f"合规框架: {fw.get('name', framework.upper())}")

    for line in meta_lines:
        story.append(Paragraph(line, S.cover_meta))

    story.append(Spacer(1, 40))

    # 合规框架说明
    if framework and framework in COMPLIANCE_FRAMEWORKS:
        fw = COMPLIANCE_FRAMEWORKS[framework]
        story.append(Paragraph(
            f"<b>{fw['name']}</b><br/>{fw['description']}",
            ParagraphStyle("FWDesc", parent=S.body, fontSize=9, alignment=TA_CENTER,
                           textColor=colors.HexColor("#64748b")),
        ))

    story.append(Spacer(1, 60))
    story.append(Paragraph(
        "<i>This report is auto-generated by Security Guardian. "
        "It is not a substitute for a professional security audit.</i>",
        ParagraphStyle("Disclaimer", parent=S.disclaimer),
    ))
    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ──
    story.append(Paragraph("1. Executive Summary", S.section_header))
    story.append(Spacer(1, 6))

    # 评分卡
    total = report.summary["total_findings"]
    by_severity = report.summary["by_severity"]
    score = _calculate_security_score(report)

    summary_data = [
        [Paragraph("Security Score", S.summary_label),
         Paragraph("Total Findings", S.summary_label),
         Paragraph("Files Scanned", S.summary_label)],
        [Paragraph(f"{score}/100", S.summary_number),
         Paragraph(str(total), S.summary_number),
         Paragraph(str(report.scanned_files), S.summary_number)],
    ]
    if framework:
        summary_data[0].append(Paragraph("Framework", S.summary_label))
        fw = COMPLIANCE_FRAMEWORKS.get(framework, {})
        summary_data[1].append(Paragraph(fw.get("name", framework.upper()), ParagraphStyle(
            "FWLabel", fontSize=9, leading=12, alignment=TA_CENTER, textColor=colors.HexColor("#0ea5e9"),
            fontName="Helvetica-Bold",
        )))

    col_widths = [doc.width / len(summary_data[0])] * len(summary_data[0])
    t = Table(summary_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # 严重度分布
    story.append(Paragraph("Severity Distribution", S.subsection_header))

    sev_data = [[Paragraph("Severity", S.body_bold),
                 Paragraph("Count", S.body_bold),
                 Paragraph("Percentage", S.body_bold)]]
    for sev in SEVERITY_ORDER:
        count = by_severity.get(sev, 0)
        pct = f"{count/total*100:.0f}%" if total > 0 else "0%"
        color = SEVERITY_COLORS.get(sev, (0.5, 0.5, 0.5))
        sev_data.append([
            Paragraph(
                f'<font color="{_rgb_to_hex(color)}">{"●"}</font> {sev.upper()}',
                ParagraphStyle("SevLabel", parent=S.body, fontName="Helvetica-Bold"),
            ),
            Paragraph(str(count), S.body),
            Paragraph(pct, S.body),
        ])

    sev_widths = [doc.width * 0.4, doc.width * 0.3, doc.width * 0.3]
    t = Table(sev_data, colWidths=sev_widths)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # 风险摘要描述
    if total == 0:
        story.append(Paragraph(
            "✅ <b>No security issues found.</b> The codebase passes all 65+ security checks.",
            ParagraphStyle("NoFindings", parent=S.body, textColor=colors.HexColor("#16a34a"),
                           fontSize=11, spaceBefore=10),
        ))
    else:
        critical = by_severity.get("critical", 0)
        high = by_severity.get("high", 0)
        medium = by_severity.get("medium", 0)
        parts = []
        if critical:
            parts.append(f"<b>{critical} critical</b>")
        if high:
            parts.append(f"<b>{high} high</b>")
        if medium:
            parts.append(f"<b>{medium} medium</b>")
        sev_str = ", ".join(parts) + " severity issues" if parts else "low severity issues"
        story.append(Paragraph(
            f"The scan identified <b>{total}</b> potential security findings, including {sev_str}. "
            f"Addressing the critical and high severity items is recommended before production deployment.",
            S.body,
        ))
    story.append(PageBreak())

    # ── COMPLIANCE MAPPING ──
    if framework and framework in COMPLIANCE_FRAMEWORKS:
        story.append(Paragraph(f"2. {COMPLIANCE_FRAMEWORKS[framework]['name']} Compliance Mapping", S.section_header))
        story.append(Spacer(1, 6))

        tagged = _compliance_tags(report.findings, framework)
        mapped = [(f, m) for f, m in tagged if m is not None]
        unmapped = [(f, m) for f, m in tagged if m is None]

        if mapped:
            comp_data = [[Paragraph("Standard", S.body_bold),
                          Paragraph("Finding", S.body_bold),
                          Paragraph("Severity", S.body_bold)]]
            for f, m in mapped:
                comp_data.append([
                    Paragraph(f"<b>{m['id']}</b><br/>{m['name']}", ParagraphStyle(
                        "CompCell", parent=S.body, fontSize=8, leading=11,
                    )),
                    Paragraph(f"{f.rule_id}: {f.message[:50]}...", ParagraphStyle(
                        "FindCell", parent=S.body, fontSize=8, leading=11,
                    )),
                    Paragraph(
                        f'<font color="{_rgb_to_hex(SEVERITY_COLORS.get(f.severity, (0.5,0.5,0.5)))}">'
                        f'{f.severity.upper()}</font>',
                        ParagraphStyle("SevCell", parent=S.body, fontSize=8, fontName="Helvetica-Bold"),
                    ),
                ])

            comp_widths = [doc.width * 0.25, doc.width * 0.55, doc.width * 0.2]
            t = Table(comp_data, colWidths=comp_widths, repeatRows=1)
            t.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0ea5e9")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t)

            if unmapped:
                story.append(Spacer(1, 8))
                story.append(Paragraph(
                    f"<i>Note: {len(unmapped)} finding(s) do not directly map to this framework.</i>",
                    S.disclaimer,
                ))
        else:
            story.append(Paragraph(
                "No findings directly map to this compliance framework.",
                S.body,
            ))
        story.append(PageBreak())

    # ── DETAILED FINDINGS ──
    section_num = "2" if not framework else "3"
    story.append(Paragraph(f"{section_num}. Detailed Findings", S.section_header))
    story.append(Spacer(1, 6))

    if not report.findings:
        story.append(Paragraph("✅ No issues detected.", S.body))
    else:
        for sev in SEVERITY_ORDER:
            sev_findings = [f for f in report.findings if f.severity == sev]
            if not sev_findings:
                continue

            color = SEVERITY_COLORS.get(sev, (0.5, 0.5, 0.5))
            hex_color = _rgb_to_hex(color)
            story.append(Paragraph(
                f'<font color="{hex_color}">{"●"}</font> '
                f'<font color="{hex_color}"><b>{sev.upper()}</b></font> '
                f'({len(sev_findings)} findings)',
                ParagraphStyle("SevSection", parent=S.subsection_header, fontSize=13,
                               spaceBefore=16, spaceAfter=6),
            ))

            for i, f in enumerate(sev_findings[:30]):
                # 合规标签
                comp_tag = ""
                if framework:
                    _, mapping = _compliance_tags([f], framework)[0]
                    if mapping:
                        comp_tag = f'<font color="#0ea5e9"> [{mapping["id"]}]</font>'

                story.append(Paragraph(
                    f'<b>{i+1}. {f.rule_id}</b>{comp_tag}',
                    S.finding_title,
                ))
                story.append(Paragraph(
                    f"<b>File:</b> <font face='Courier'>{f.file}:{f.line}</font> &nbsp;|&nbsp; "
                    f"<b>Category:</b> {f.category} &nbsp;|&nbsp; "
                    f"{'<b>CWE:</b> ' + f.cwe_id if f.cwe_id else ''}",
                    S.finding_meta,
                ))
                story.append(Paragraph(f"<b>Issue:</b> {f.message}", S.body))

                # 代码片段
                if f.snippet:
                    snippet_text = f.snippet.replace("\n", "<br/>")
                    story.append(Paragraph(
                        f"<font face='Courier' size='7'>{snippet_text}</font>",
                        S.code,
                    ))

                story.append(Paragraph(f"<b>Recommendation:</b> {f.fix_suggestion}", S.body))
                story.append(Spacer(1, 4))

    # ── APPENDIX ──
    story.append(PageBreak())
    section_num = str(int(section_num) + 1)
    story.append(Paragraph(f"{section_num}. Scan Methodology & Limitations", S.section_header))
    story.append(Spacer(1, 6))

    story.append(Paragraph(
        "<b>Scan Engine:</b> Security Guardian v0.6.0 — regex-based static analysis. "
        "65+ rules covering secrets, OWASP Top 10, dependency vulnerabilities, and "
        "configuration risks.",
        S.body,
    ))
    story.append(Paragraph(
        "<b>Scope:</b> The scan examines source code files for hardcoded secrets, "
        "insecure patterns, known vulnerable dependency versions, and risky configurations. "
        "It does not execute code or perform dynamic analysis.",
        S.body,
    ))
    story.append(Paragraph(
        "<b>Limitations:</b>",
        S.body_bold,
    ))
    for limitation in [
        "Regex-based detection may produce false positives.",
        "Dynamic vulnerabilities (runtime) are not covered.",
        "Business logic flaws are outside scope.",
        "This report is auto-generated and is not a certified security audit.",
    ]:
        story.append(Paragraph(f"• {limitation}", ParagraphStyle(
            "Bullet", parent=S.body, leftIndent=12, bulletIndent=0,
        )))

    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "<i>Report generated by Security Guardian — your AI coding agent's security layer. "
        f"Scan date: {report.scan_time}. This report is for informational purposes only.</i>",
        S.disclaimer,
    ))

    # 构建
    doc.build(story)
    return output_path


def _calculate_security_score(report: ScanReport) -> int:
    """计算安全分数 (0-100)"""
    by_severity = report.summary["by_severity"]
    total = report.summary["total_findings"]

    if total == 0:
        return 100

    weights = {"critical": 25, "high": 10, "medium": 3, "low": 1}
    weighted_sum = sum(by_severity.get(sev, 0) * weights.get(sev, 1) for sev in SEVERITY_ORDER)

    score = max(0, 100 - min(weighted_sum, 100))
    return score


# ═══════════════════════════════════════════
# CLI 入口
# ═══════════════════════════════════════════

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Security Guardian — PDF Compliance Report Generator")
    parser.add_argument("--input", "-i", type=str, default="-",
                        help="扫描结果 JSON 文件（默认从 stdin 读取）")
    parser.add_argument("--output", "-o", type=str, default="security-guardian-report.pdf",
                        help="输出 PDF 路径")
    parser.add_argument("--framework", "-f", choices=list(COMPLIANCE_FRAMEWORKS.keys()),
                        help="合规框架映射（可选）")
    parser.add_argument("--company", type=str, default="",
                        help="公司名称")
    parser.add_argument("--project", type=str, default="",
                        help="项目名称")

    args = parser.parse_args()

    # 读取扫描数据
    if args.input == "-":
        raw = sys.stdin.read()
    else:
        with open(args.input, "r") as f:
            raw = f.read()

    try:
        report_data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"❌ JSON 解析失败: {e}", file=sys.stderr)
        print("请先运行 scan.py 并输出 JSON 格式。", file=sys.stderr)
        print("  python scripts/scan.py --path . --output json > report.json", file=sys.stderr)
        print(f"  python scripts/pdf_report.py --input report.json --output report.pdf", file=sys.stderr)
        sys.exit(1)

    # 重建 ScanReport
    report = ScanReport(
        scan_time=report_data.get("scan_time", datetime.now().isoformat()),
        target_path=report_data.get("target_path", ""),
        total_files=report_data.get("total_files", 0),
        scanned_files=report_data.get("scanned_files", 0),
        findings=[
            Finding(**f) if isinstance(f, dict) else f
            for f in report_data.get("findings", [])
        ],
        summary=report_data.get("summary", {}),
    )

    # 生成 PDF
    pdf_path = build_pdf_report(
        report, args.output,
        framework=args.framework,
        company_name=args.company,
        project_name=args.project,
    )
    print(f"✅ PDF 合规报告已生成: {pdf_path}")
    print(f"   文件大小: {os.path.getsize(pdf_path) / 1024:.1f} KB")


if __name__ == "__main__":
    main()
