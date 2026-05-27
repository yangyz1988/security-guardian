#!/usr/bin/env python3
"""Security Guardian — Product Screenshot Generator

为 Product Hunt / HN / Twitter 生成产品截图。
"""
import os
import sys
from PIL import Image, ImageDraw, ImageFont

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "docs", "screenshots")
os.makedirs(OUTPUT_DIR, exist_ok=True)

WIDTH = 900
HEIGHT = 540
BG = "#1e1e2e"
TEXT = "#cdd6f4"
GREEN = "#a6e3a1"
BLUE = "#89b4fa"
YELLOW = "#f9e2af"
CYAN = "#94e2d5"
RED_CRIT = "#f38ba8"
ORANGE = "#fab387"
HEADER_BG = "#11111b"
HEADER_TEXT = "#6c7086"
BORDER = "#313244"

TITLE_BAR_H = 28
PAD = 20


def get_font(size=13):
    try:
        return ImageFont.truetype("Consolas", size)
    except:
        try:
            return ImageFont.truetype("Courier New", size)
        except:
            return ImageFont.load_default()


def draw_title_bar(draw, font):
    draw.rectangle([(0, 0), (WIDTH, TITLE_BAR_H)], fill=HEADER_BG)
    for x, c in [(10, RED_CRIT), (24, YELLOW), (38, GREEN)]:
        draw.ellipse([(x, TITLE_BAR_H // 2 - 4), (x + 8, TITLE_BAR_H // 2 + 4)], fill=c)
    txt = "Security Guardian — Compliance Scan Report"
    tw = font.getbbox(txt)[2]
    draw.text(((WIDTH - tw) // 2, (TITLE_BAR_H - 14) // 2), txt, fill=HEADER_TEXT, font=font)


def generate_scan_screenshot():
    """sg scan --output pdf --compliance soc2 输出截图"""
    font = get_font(13)
    small = get_font(11)
    bold = get_font(14)
    cw = font.getbbox("W")[2] + 1  # char width
    lh = font.getbbox("W")[3] + 3  # line height

    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)
    draw_title_bar(draw, bold)

    y = TITLE_BAR_H + PAD
    x = PAD

    lines = [
        (None, ""),
        (CYAN,  "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"),
        (GREEN, "  Security Guardian — Security Audit Report"),
        (CYAN,  "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"),
        (None,  ""),
        (BLUE,  "  Target:  /home/user/project/payment-api"),
        (BLUE,  "  Scan:    2,847 files in 3.2s | 65 rules"),
        (BLUE,  "  Compliance: SOC 2 (Trust Services Criteria)"),
        (None,  ""),
        (None,  "  ┌─────────────────────────────────────────────┐"),
        (None,  "  │  📊 Executive Summary                       │"),
        (None,  "  ├──────────────────────┬──────────────────────┤"),
        (None,  "  │  Security Score      │  Total Findings      │"),
        (GREEN, "  │       85 / 100       │         7            │"),
        (None,  "  ├──────────────────────┴──────────────────────┤"),
        (None,  "  │  Severity Distribution                     │"),
        (None,  "  │                                            │"),
        (RED_CRIT, "  │    🔴 Critical  1                          │"),
        (ORANGE, "  │    🟠 High      2                          │"),
        (YELLOW, "  │    🟡 Medium    3                          │"),
        (BLUE,  "  │    🔵 Low       1                          │"),
        (None,  "  └─────────────────────────────────────────────┘"),
        (None,  ""),
        (None,  "  📄 Report: security-guardian-report-20260527.pdf"),
        (GREEN, "     Size: 16.2 KB | Generated in 1.1s"),
        (None,  ""),
        (CYAN,  "  Press any key to view report..."),
    ]

    for color, text in lines:
        if not text:
            y += lh // 2
            continue
        c = TEXT if color is None else color
        draw.text((x, y), text, fill=c, font=font)
        y += lh

    path = os.path.join(OUTPUT_DIR, "scan-report.png")
    img.save(path, "PNG")
    sz = os.path.getsize(path) / 1024
    print(f"✅ {path} ({sz:.0f} KB)")
    return path


def generate_block_screenshot():
    """Claude Code 被拦截的截图"""
    font = get_font(13)
    bold = get_font(14)
    lh = font.getbbox("W")[3] + 3

    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)
    draw_title_bar(draw, bold)

    y = TITLE_BAR_H + PAD
    x = PAD

    lines = [
        (None,     ""),
        (GREEN,    "  $ claude -p \"add OpenAI key to config.py\""),
        (None,     ""),
        (None,     "  🤖 [Claude] I'll add the API key to config.py..."),
        (None,     ""),
        (RED_CRIT, "  ⛔ BLOCKED: Security Guardian — Secret Detected"),
        (RED_CRIT, "  ───────────────────────────────────────────────"),
        (None,     "    Rule:      openai-key"),
        (None,     "    File:      config.py:15"),
        (None,     '    Pattern:   sk-proj-...found'),
        (None,     "    Severity:  CRITICAL"),
        (None,     ""),
        (YELLOW,   "    ⚠ Action: Write blocked. Secret not written to disk."),
        (YELLOW,   "    💡 Tip: Use environment variables instead."),
        (None,     ""),
        (GREEN,    "  ✅ No secrets leaked. Your codebase is safe."),
        (None,     ""),
        (BLUE,     "  ---"),
        (None,     "  [Audit Logged] openai-key | BLOCKED | config.py:15 | 2026-05-27"),
    ]

    for color, text in lines:
        if not text:
            y += lh // 2
            continue
        c = TEXT if color is None else color
        draw.text((x, y), text, fill=c, font=font)
        y += lh

    path = os.path.join(OUTPUT_DIR, "block-demo.png")
    img.save(path, "PNG")
    sz = os.path.getsize(path) / 1024
    print(f"✅ {path} ({sz:.0f} KB)")
    return path


if __name__ == "__main__":
    generate_scan_screenshot()
    generate_block_screenshot()
    print("Done.")
