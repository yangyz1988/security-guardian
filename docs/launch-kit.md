# 🚀 Security Guardian — Launch Kit

> 定位: **Your AI Coding Agent's Security Layer**
> 不使用: API 网关 / LLM 防火墙 / 凭据保险柜
> 使用场景: AI Agent 写文件时的实时安全拦截

---

## 1. Product Hunt 发布

### Listing

**Tagline (120 chars):**
```
Real-time secret & vulnerability scanning for your AI coding agent. Stop leaks before they happen — MCP middleware, not post-scan.
```

**Product Name:** Security Guardian

**Description (max 500 chars):**
```
You ask Claude Code to add an API key. It writes:

```python
api_key = "sk-proj-abc123..."   # ← leaked into your codebase
```

With Security Guardian, that write gets intercepted, scanned, and blocked — before it hits the filesystem.

**How it works:**
Security Guardian sits between your AI coding agent (Claude Code, Cline, Cursor) and its MCP servers. Every write_file, edit_file, or create_file passes through a transparent proxy that:

1. Extracts the file content
2. Scans for 65+ rule patterns (API keys, OWASP vulnerabilities, hardcoded secrets, dependency risks)
3. Blocks or warns based on policy
4. Logs everything to an audit trail

**One command setup:**
```bash
bash middleware/setup.sh
```
Auto-detects Claude Code, Cline, and Cursor. Configures them. Done.

**Why not post-scan?**
Post-scan tools catch leaks after they're committed. By then the secret is in git history forever. Security Guardian stops them at the point of write.

**Full production features:**
- 🔒 12 secret detection patterns (OpenAI, AWS, GitHub, Stripe, etc.)
- 🐛 13 OWASP vulnerability patterns (SQLi, XSS, command injection, etc.)
- 📦 npm dependency vulnerability scanning
- ⚙️ Docker/k8s config risk detection
- 📋 Real-time audit logging
- 📄 PDF compliance reports (SOC 2 / OWASP / ISO 27001 / PCI DSS mapping)
- 🧠 One-click integration for Claude Code, Cline, Cursor
- 0% cloud dependency — everything runs locally

**Free for individuals. Pro $29/mo for teams.**
```

**First comment (maker's story):**
```
I'm a solo developer who uses Claude Code every day. One day I asked it to add an API key to a config file, and it did — right into the codebase. The key was in git history. I felt sick.

I looked for tools that could prevent this. Everything was either:
- post-scan (catches leaks after they're committed)
- API gateways (protects who the agent calls, not what it writes)
- enterprise-only (requires a server, complex setup)

So I built Security Guardian. It's an MCP middleware layer that sits between your AI agent and the filesystem. Every write is intercepted, scanned, and either allowed or blocked — in real time.

Now when Claude tries to write `api_key = "sk-..." `, the write is blocked before it hits disk. No leaks. No post-facto scans.

One command to set up. Open source. Local-first. No cloud dependency.

I'd love your feedback. What AI agent security gaps have you encountered?
```

### Screenshots for PH

1. **Hero GIF** — The demo.gif (setup → scan → PDF)
2. **Architecture diagram** — docs/architecture.svg
3. **CLI screenshot** — `sg scan --output pdf --compliance soc2` output
4. **PDF report preview** — First page of the compliance report

---

## 2. Hacker News — Show HN

**Title:** Show HN: Security Guardian – Real-time secret scanning for Claude Code/Cline/Cursor

**Body:**

I use Claude Code daily. Yesterday I asked it to add an OpenAI key to a config file — and it did, right into my codebase. The key hit git. I scrambled to rotate it.

That shouldn't happen.

I looked for tools. Most are:
- Post-scan (truffleHog, Gitleaks) — catch leaks after they're committed
- API gateways (onecli, ThinkWatch) — protect who the agent calls, not what it writes
- Enterprise-only — require servers, complex deployment

**So I built an MCP middleware layer.**

How it works:
```
Claude Code/Cline/Cursor → [Security Guardian Proxy] → Filesystem MCP
                              ↓
                        65 rules check:
                        • 12 secret patterns (OpenAI, AWS, GitHub, Stripe...)
                        • 13 OWASP patterns (SQLi, XSS, injection...)
                        • npm dependency vulns
                        • Docker/k8s config risks
```

Every write_file/edit_file/create_file gets intercepted, scanned, and either allowed or blocked — in real time.

One command setup auto-detects your AI agent and configures MCP:
```bash
git clone https://github.com/yangyz1988/security-guardian.git
cd security-guardian
bash middleware/setup.sh
```

Then try: "Claude, add a hardcoded API key to config.py" — blocked before it hits disk.

Also does:
- Read file audit logging (know what your agent read)
- PDF compliance reports (SOC2, OWASP, ISO 27001, PCI DSS mapping)
- Policy modes: strict / normal / relaxed
- Zero cloud dependency — everything runs locally

It's free for individuals. Pro ($29/mo) adds team features and the compliance PDF generator.

Would love your thoughts — what security gaps have your AI agents introduced?

https://github.com/yangyz1988/security-guardian

---

## 3. Twitter/X Thread

```
1/ 🛡️ Your AI coding agent needs a security layer.

You ask Claude to add an API key. It writes:

`api_key = "sk-proj-abc..."`

Into your codebase. Into git. Forever.

I built Security Guardian to stop this at the point of write. 🧵

2/ How it works:
→ MCP Middleware between your AI agent and the filesystem
→ Every write_file/edit_file gets intercepted
→ Scanned against 65+ rules
→ Blocked before it hits disk

Not post-scan. Real-time.

3/ One command to set up:
`bash middleware/setup.sh`

Auto-detects Claude Code, Cline, Cursor. Configures MCP. Done.

Then try asking your agent to write a secret → instantly blocked.

4/ It's not just secrets:
✅ 12 secret patterns (OpenAI, AWS, GitHub, Stripe…)
✅ 13 OWASP vulns (SQLi, XSS, injection…)
✅ npm dependency scanning
✅ Docker/k8s config risks
✅ Real-time audit logging
✅ PDF compliance reports (SOC2, ISO27001, PCI DSS)

5/ The best part: zero cloud dependency.
Everything runs locally. Your data never leaves your machine.

Free for individuals. Pro $29/mo for teams.

https://github.com/yangyz1988/security-guardian

What security gaps have YOUR AI agents introduced? 👇
```

---

## 4. Reddit Posts

### r/programming

**Title:** I built a real-time security scanner that sits between Claude Code/Cline and your filesystem

**Body:**

[link to repo]

Use AI coding agents? Ever had one write an API key into a config file and commit it?

I did. Which is why I built Security Guardian — an MCP middleware layer that intercepts every write_file/edit_file and scans it in real-time before it hits the filesystem.

65+ rules covering:
- API keys (OpenAI, AWS, GitHub, Stripe, Slack, etc.)
- OWASP vulnerabilities (SQLi, XSS, command injection, path traversal)
- npm dependency vulnerabilities
- Docker/k8s misconfigurations

One command auto-configure for Claude Code, Cline, and Cursor.

Local-first, no cloud dependency. Open source (MIT).

### r/MachineLearning

**Title:** Security Guardian — open-source real-time write protection for AI coding agents

**Body:**

Similar content, focused on the AI agent aspect.

---

## 5. Hacker Newsletter / Indie Hackers

**Title:** How I built a $29/mo security tool for AI coding agents as a solo dev

[Long-form maker story — 500-800 words]

---

## Usage Instructions

1. Open https://www.producthunt.com/posts/new and fill in the listing
2. On Hacker News: https://news.ycombinator.com/submit
3. Twitter: compose a thread
4. Reddit: submit to appropriate subreddits

**Best timing:**
- Product Hunt: Tuesday or Thursday, 12:01 AM PT
- HN: Early morning (US) for maximum traction
- Twitter: Tuesday-Thursday morning
