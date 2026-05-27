#!/usr/bin/env python3
"""Security Guardian Demo GIF Generator

生成一个约 14 秒的终端动画演示 GIF，展示：
1. 克隆仓库 + 一键 setup.sh 配置
2. sg scan 扫描并生成 PDF 合规报告

用法:
  python tools/demo_gif.py
  # 输出: docs/demo.gif
"""
import os
import sys
from PIL import Image, ImageDraw, ImageFont

# ── 配置 ──────────────────────────────────────
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "docs", "demo.gif")
WIDTH = 780
HEIGHT = 440
BG_COLOR = "#1e1e2e"        # 暗色终端背景
TEXT_COLOR = "#cdd6f4"      # 浅灰
GREEN = "#a6e3a1"           # 成功/输出
BLUE = "#89b4fa"            # 命令/信息
YELLOW = "#f9e2af"          # 警告
RED = "#f38ba8"             # 错误（本例中不用）
CYAN = "#94e2d5"            # 文件名/路径
PROMPT_COLOR = "#a6e3a1"    # $ 符号
BORDER_COLOR = "#313244"    # 边框
HEADER_BG = "#11111b"       # 标题栏背景
HEADER_TEXT = "#6c7086"     # 标题栏文字
TITLE_BAR_H = 28
PADDING = 16

# FPS 和总帧数
FPS = 10
FRAME_DURATION = int(1000 / FPS)  # ms per frame

# ── Demo script ──────────────────────────────
# 每一段是一个 (typer, text, color) 的序列
# typer: "user" (键盘敲入), "output" (立即显示), "animation" (逐步显示)
# text: 显示的内容
# color: 文字颜色
# pause_after: 暂停几帧

SCENES = [
    # ── Scene 1: 克隆 + 进入目录 ──
    {"lines": [
        ("prompt", True, None),  # 先显示亮起的 $
        ("user", False, "git clone https://github.com/yangyz1988/security-guardian.git", None),
        ("output", False, "Cloning into 'security-guardian'...", GREEN),
        ("output", False, "Receiving objects: 100% (42/42), 12.34 KiB | 1.2 MiB/s, done.", GREEN),
        ("prompt", True, None),
        ("user", False, "cd security-guardian", None),
        ("prompt", True, None),
    ], "pause": 5},

    # ── Scene 2: 一键 setup ──
    {"lines": [
        ("prompt", True, None),
        ("user", False, "bash middleware/setup.sh", None),
        ("output", False, "", GREEN),  # empty line
        ("output", False, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", CYAN),
        ("output", False, "  Security Guardian — MCP Middleware Setup", GREEN),
        ("output", False, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", CYAN),
        ("output", False, "  🔎 Detecting AI coding agents...", None),
        ("output", False, "     ✅ Claude Code  — found at /usr/local/bin/claude", GREEN),
        ("output", False, "     ✅ Cline        — found", GREEN),
        ("output", False, "     ⚠  Cursor       — not detected (manual config available)", YELLOW),
        ("output", False, "", None),
        ("output", False, "  📝 Configuring MCP servers...", None),
        ("output", False, "     ✅ Claude Code  → settings.json configured", GREEN),
        ("output", False, "     ✅ Cline        → MCP settings updated", GREEN),
        ("output", False, "", None),
        ("output", False, "  🚀 Setup complete! Your AI agents are now protected.", CYAN),
        ("output", False, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", CYAN),
    ], "pause": 5},

    # ── Scene 3: sg scan + PDF report ──
    {"lines": [
        ("prompt", True, None),
        ("user", False, 'sg scan --path . --output pdf --compliance soc2 \\', None),
        ("user", False, '   --company "Acme Corp" --project "Payment API"', None),
        ("output", False, "", None),
        ("output", False, "🔍 Scanning: /home/user/security-guardian ...     ████████████████░░ 85%", None),
        ("output", False, "", None),
    ]},
    {"lines": [
        ("output", False, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", CYAN),
        ("output", False, "  📊 Executive Summary", GREEN),
        ("output", False, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", CYAN),
        ("output", False, "     Security Score:  85/100", None),
        ("output", False, "     Total Findings:  7", None),
        ("output", False, "", None),
        ("output", False, "     🔴 Critical  1   🟠 High  2   🟡 Medium  3   🔵 Low  1", None),
        ("output", False, "", None),
        ("output", False, "  📄 Compliance:  SOC 2 (Trust Services Criteria)", GREEN),
        ("output", False, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", CYAN),
        ("output", False, "     CC6.1  Logical Access Controls        6 findings", None),
        ("output", False, "     CC7.1  System Operations — Change Mgmt  1 finding", None),
        ("output", False, "", None),
        ("output", False, "  ✅ PDF report generated: security-guardian-report.pdf", CYAN),
        ("output", False, "     Size: 16.2 KB", GREEN),
    ], "pause": 10},
]


def get_font(size=14):
    """获取等宽字体"""
    try:
        return ImageFont.truetype("Consolas", size)
    except (IOError, OSError):
        try:
            return ImageFont.truetype("Courier New", size)
        except (IOError, OSError):
            return ImageFont.load_default()


def generate_gif():
    """生成 Demo GIF"""
    font = get_font(14)
    font_bold = get_font(16)
    char_w = font.getbbox("W")[2] + 2  # 字符宽度
    line_h = font.getbbox("W")[3] + 4  # 行高
    max_chars = (WIDTH - 2 * PADDING) // char_w  # 一行最大字符数

    frames = []

    # 终端内容缓存
    content_lines = []

    def add_content(line, color=None):
        """添加一行内容"""
        if color is None:
            color = TEXT_COLOR
        content_lines.append((line, color))

    def render_frame(prompt_blink=False, typing_pos=None):
        """渲染一帧"""
        img = Image.new("RGBA", (WIDTH, HEIGHT), BG_COLOR)
        draw = ImageDraw.Draw(img)

        # ── 标题栏 ──
        draw.rectangle([(0, 0), (WIDTH, TITLE_BAR_H)], fill=HEADER_BG)
        # 红黄绿圆点
        dot_y = TITLE_BAR_H // 2 - 4
        draw.ellipse([(10, dot_y), (18, dot_y + 8)], fill="#f38ba8")
        draw.ellipse([(24, dot_y), (32, dot_y + 8)], fill="#f9e2af")
        draw.ellipse([(38, dot_y), (46, dot_y + 8)], fill="#a6e3a1")
        # 标题
        title = "Security Guardian — Setup Demo"
        tw = font_bold.getbbox(title)[2]
        draw.text(((WIDTH - tw) // 2, (TITLE_BAR_H - 16) // 2), title,
                  fill=HEADER_TEXT, font=font_bold)

        # ── 终端内容 ──
        y = TITLE_BAR_H + PADDING
        x = PADDING

        visible_lines = content_lines[:]
        # 计算可见行数
        max_visible = (HEIGHT - TITLE_BAR_H - PADDING * 2) // line_h
        if len(visible_lines) * line_h > HEIGHT - TITLE_BAR_H - PADDING * 2:
            visible_lines = visible_lines[-(max_visible - 1):]
            # 加滚动提示
            scroll_hint = "(scroll) ↑"
            sw = font.getbbox(scroll_hint)[2]
            draw.text((WIDTH - PADDING - sw, y - line_h), scroll_hint,
                      fill=YELLOW, font=font)

        for line, color in visible_lines:
            if color is None:
                color = TEXT_COLOR
            draw.text((x, y), line, fill=color, font=font)
            y += line_h

        # ── 光标 ──
        if prompt_blink and typing_pos is not None:
            # 在最后一行的末尾画光标
            last_line = visible_lines[-1][0] if visible_lines else ""
            cursor_x = x + len(last_line) * char_w
            cursor_y = y - line_h
            draw.rectangle([(cursor_x, cursor_y), (cursor_x + 8, cursor_y + font.getbbox("W")[3])],
                           fill=TEXT_COLOR)

        return img

    # ════════════════════════════════════════════
    # 生成所有帧
    # ════════════════════════════════════════════

    for scene_idx, scene in enumerate(SCENES):
        lines = scene["lines"]
        pause = scene.get("pause", 0)

        for line_idx, line_data in enumerate(lines):
            if len(line_data) == 3:
                line_type, is_blinking, text = line_data
                color = None
            else:
                line_type, is_blinking, text, color = line_data
            if line_type == "prompt":
                # 闪烁的光标：亮/暗交替几帧
                for _ in range(3):
                    frames.append(render_frame(prompt_blink=True, typing_pos=0))
                    frames.append(render_frame(prompt_blink=False))
                continue

            if line_type == "output":
                # 立即显示整行
                add_content(text, color)
                frames.append(render_frame())
                continue

            if line_type == "user":
                # 键盘敲入效果：逐字符显示 — 每3个字符1帧加快节奏
                current_text = ""
                prefix = "$ "
                full_line = prefix + text

                for ch_idx, ch in enumerate(text):
                    current_text += ch
                    display = prefix + current_text
                    # 替换最后一行
                    new_content = []
                    for l, c in content_lines:
                        if l.startswith("$ "):
                            continue
                        if l == "":  # 跳过空行标记
                            continue
                        new_content.append((l, c))

                    add_content(display, GREEN)
                    content_lines[:] = new_content
                    content_lines.append((display, GREEN))

                    if ch_idx % 2 == 0:  # 每2个字符1帧
                        frames.append(render_frame(prompt_blink=(ch_idx % 2 == 0)))

                # 敲入完成后显示2帧
                for _ in range(2):
                    frames.append(render_frame(prompt_blink=True))

        # 场景间停顿
        for _ in range(pause):
            frames.append(render_frame())

    # 最后一帧停留
    for _ in range(20):
        frames.append(render_frame())

    # ── 保存为 GIF ──
    print(f"🔧 Generating {len(frames)} frames...")

    # 转为 RGB (Pillow GIF 不支持 RGBA)
    rgb_frames = [f.convert("P", palette=Image.ADAPTIVE, colors=256) for f in frames]

    # 写入 GIF
    rgb_frames[0].save(
        OUTPUT_PATH,
        save_all=True,
        append_images=rgb_frames[1:],
        duration=FRAME_DURATION,
        loop=0,
        optimize=True,
    )

    size_kb = os.path.getsize(OUTPUT_PATH) / 1024
    print(f"✅ GIF saved: {OUTPUT_PATH}")
    print(f"   Size: {size_kb:.1f} KB")
    print(f"   Frames: {len(frames)}")
    print(f"   Duration: {len(frames) / FPS:.1f}s")

    return OUTPUT_PATH


if __name__ == "__main__":
    generate_gif()
