# contractguard — DeepSeek Audit

**Date:** 2026-07-13
**Path:** `C:\Users\TATI\Desktop\DEV\contractguard\`
**Stack:** Python — Smart contract security auditor (Slither + Mythril wrapper)
**Tier:** 2 — High
**Dependencies:** Partial (`__pycache__` only, no venv)

---

## 🔴 Security Vulnerabilities

| Severity | File | Line(s) | Vulnerability | Exact Fix |
|----------|------|---------|---------------|-----------|
| 🟠 HIGH | `slither_wrapper.py` | 42 | `subprocess.run(["slither", contract_path, "--json", "-"], ...)` — binary `"slither"` resolved from PATH. Attacker with PATH control substitutes malicious binary. | Use absolute path: `shutil.which("slither")` and validate it's in an expected location (e.g., `/usr/local/bin/slither` or venv path). Or resolve to `sys.prefix/bin/slither`. |
| 🟠 HIGH | `mythril_wrapper.py` | 40 | `subprocess.run(["myth", "analyze", contract_path, "-o", "json"], ...)` — same PATH-based resolution for `"myth"`. | Same fix: resolve absolute path via `shutil.which("myth")` and validate. |
| 🟡 MEDIUM | `slither_wrapper.py` | 28-30 | `contract_path` validated via `os.path.abspath()` and basename check for dashes — good validation but not exhaustive. | Add `os.path.realpath()` to resolve symlinks. Validate file extension is `.sol`. Add file size limit. |
| ✅ | `economic_logic_judge.py` | 25-26 | API keys read from `os.environ.get()` — safe pattern. | — |

---

## 🟠 Performance Issues

| Severity | File | Line(s) | Issue | Exact Fix |
|----------|------|---------|-------|-----------|
| 🟡 MEDIUM | `slither_wrapper.py` | 42 | Slither analysis can take 30-60s for complex contracts — no timeout set on subprocess. | Add `timeout=120` to `subprocess.run()`. |
| 🟡 MEDIUM | `mythril_wrapper.py` | 40 | Has `timeout=15` — good. | — |

---

## 🟡 UI/UX

CLI tool — no UI to audit. Output is JSON data for programmatic consumption.

---

## 🔧 Session: 2026-07-14 — Multi-Agent Deep Audit Sweep (Round 1)

**Status:** Not audited in this round. Previously noted (July 5): LLM judge should emit agentscope-compatible enum severity schema for FINDINGS.json interop. Sweep Round 2 will cover Tier 3.

| Category | Package | Issue | Fix |
|----------|---------|-------|-----|
| 🟡 MEDIUM | Dependencies | No `requirements.txt` found in root. Slither and Mythril are external system dependencies. | Add `requirements.txt` listing slither-analyzer, mythril, and any Python deps. Pin versions. |
| 🟡 MEDIUM | `slither`, `myth` | System binaries — no version pinning, no containerization. | Add Dockerfile pinning slither and mythril versions by digest. |

### Missing Dev Tooling
- No `.python-version`
- No `requirements.txt` (or it's in a subdirectory)
- No Dockerfile for reproducible analysis environment
- No `pytest` tests for wrapper logic

---

## 📋 Priority Fix Queue

1. **[HIGH — Command Injection]** `slither_wrapper.py:42` — Replace `"slither"` with absolute path: `shutil.which("slither")` + validate it's not in a world-writable directory.
2. **[HIGH — Command Injection]** `mythril_wrapper.py:40` — Same: resolve `"myth"` to absolute path via `shutil.which()`.
3. **[MEDIUM — Path Validation]** `slither_wrapper.py:28-30` — Add `os.path.realpath()`, extension check (`.sol`), and file size limit.
4. **[MEDIUM — Timeout]** `slither_wrapper.py:42` — Add `timeout=120` to subprocess.
5. **[MEDIUM — Dev Tooling]** Add Dockerfile pinning slither/mythril versions, `requirements.txt`, `.python-version`.
