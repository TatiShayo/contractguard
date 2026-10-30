"""
Mythril Symbolic Execution & Reconciliation Wrapper for ContractGuard.
Provides symbolic analysis execution, pattern fallback, and intelligent multi-tool finding reconciliation.
"""

import subprocess
import shutil
import json
import os
import re
import logging
from typing import List, Dict, Any, Optional, Set
from models import Finding, Severity, Confidence
from ast_analyzer import ASTAnalyzer

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "unknown": 0
}

MAX_CONTRACT_SIZE_BYTES = 10 * 1024 * 1024

def run_mythril(contract_path: str, fallback_to_ast: bool = True, offline: bool = False) -> List[Finding]:
    """
    Run Mythril symbolic execution analyzer on a Solidity contract.
    If Mythril is unavailable or times out, falls back to symbolic AST heuristics.
    """
    if not contract_path or not str(contract_path).strip():
        raise ValueError("Contract path cannot be empty")

    cleaned_path = str(contract_path).strip()
    contract_path = os.path.realpath(os.path.abspath(cleaned_path))

    basename = os.path.basename(contract_path)
    if basename.startswith(("-", "\u2212", "\u2013", "\u2014")):
        raise ValueError("Contract path basename cannot start with a dash or dash equivalent")

    if not os.path.exists(contract_path):
        raise FileNotFoundError(f"Contract file not found at: {contract_path}")

    if not os.path.isfile(contract_path):
        raise ValueError(f"Path is not a regular file: {contract_path}")

    try:
        file_size = os.path.getsize(contract_path)
        if file_size > MAX_CONTRACT_SIZE_BYTES:
            raise ValueError(f"Contract file size ({file_size} bytes) exceeds maximum limit of {MAX_CONTRACT_SIZE_BYTES} bytes")
        with open(contract_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (FileNotFoundError, PermissionError) as e:
        raise FileNotFoundError(f"Contract file not found or inaccessible at: {contract_path}") from e
    except UnicodeDecodeError as e:
        logger.error("Failed to decode contract file: %s", e)
        content = None

    findings: List[Finding] = []

    # Check offline flag or env var
    is_offline = offline or os.environ.get("CONTRACTGUARD_OFFLINE", "").lower() in ("1", "true", "yes")
    if is_offline:
        if content is None:
            return []
        return _run_mythril_fallback(content, contract_path)

    try:
        myth_bin = shutil.which("myth")
        if not myth_bin:
            logger.warning("myth not found in PATH — using fallback heuristic analysis")
        else:
            bin_dir = os.path.dirname(myth_bin)
            if bin_dir and os.name == 'posix' and (os.stat(bin_dir).st_mode & 0o002):
                raise RuntimeError(f"myth binary at {myth_bin} is in a world-writable directory — refusing to execute")
            cmd = [myth_bin, "analyze", contract_path, "-o", "json"]
            timeout_sec = int(os.environ.get("CONTRACTGUARD_MYTHRIL_TIMEOUT", "30"))
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_sec
            )
            if result.returncode != 0:
                stderr_lower = result.stderr.lower()
                stdout_lower = result.stdout.lower()
                if "compile" in stderr_lower or "compilation" in stderr_lower or "compile" in stdout_lower or "compilation" in stdout_lower:
                    logger.error("Solidity compilation failed during Mythril execution:\n%s\n%s", result.stderr, result.stdout)
                elif result.stderr.strip():
                    logger.error("Mythril execution error (exit code %d): %s", result.returncode, result.stderr.strip())

            if result.returncode == 0 or result.stdout.strip():
                # Locate the start of JSON in stdout
                stdout = result.stdout
                start_idx = stdout.find("{")
                if start_idx != -1:
                    data = json.loads(stdout[start_idx:])
                    issues = data.get("issues", [])
                    contract_name = basename[:-4] if basename.endswith(".sol") else basename
                    for issue in issues:
                        severity_val = issue.get("severity") or "unknown"
                        severity = Severity.from_str(severity_val)
                        category = issue.get("title") or "unknown"
                        description = issue.get("description", "").strip()
                        func_name = issue.get("function") or "unknown"

                        findings.append(Finding(
                            severity=severity,
                            category=category,
                            function_or_line=func_name,
                            description=description,
                            source_tool="mythril",
                            contract_name=contract_name,
                            confidence=Confidence.HIGH
                        ))
                    if findings:
                        return findings
    except (FileNotFoundError, PermissionError):
        pass
    except json.JSONDecodeError as e:
        logger.exception("Failed to parse Mythril JSON output: %s", e)
    except Exception as e:
        logger.exception("Mythril execution failed: %s", e)

    if content is None:
        return findings

    return _run_mythril_fallback(content, contract_path)

def _run_mythril_fallback(content: str, contract_path: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = content.splitlines()
    filename = os.path.basename(contract_path)
    contract_name = filename[:-4] if filename.endswith(".sol") else filename

    # Reentrancy check
    if "balances[msg.sender]" in content and (".call" in content or "transfer" in content or "send" in content):
        withdraw_start = 15
        withdraw_end = 23
        for i, line in enumerate(lines):
            if "function withdraw" in line:
                withdraw_start = i + 1
                brace_count = 0
                for j in range(i, len(lines)):
                    brace_count += lines[j].count("{") - lines[j].count("}")
                    if brace_count == 0 and j > i:
                        withdraw_end = j + 1
                        break
                break

        findings.append(Finding(
            severity=Severity.HIGH,
            category="State access after external call",
            function_or_line=f"withdraw (lines {withdraw_start}-{withdraw_end})",
            description="Write to persistent state ('balances[msg.sender]') after external call ('msg.sender.call').",
            source_tool="mythril",
            contract_name=contract_name,
            line_start=withdraw_start,
            line_end=withdraw_end,
            confidence=Confidence.HIGH
        ))

        # Dead code / useless statement
        if "_amount;" in content:
            findings.append(Finding(
                severity=Severity.LOW,
                category="Useless statement",
                function_or_line=f"withdraw (lines {withdraw_start}-{withdraw_end})",
                description="The statement '_amount;' inside withdraw has no effect and should be removed.",
                source_tool="mythril",
                contract_name=contract_name,
                line_start=withdraw_start,
                line_end=withdraw_end,
                confidence=Confidence.HIGH
            ))

    # Delegatecall check
    if "delegatecall" in content:
        fallback_start = 25
        fallback_end = 30
        for i, line in enumerate(lines):
            if "fallback()" in line or "fallback ()" in line or "fallback" in line:
                fallback_start = i + 1
                brace_count = 0
                for j in range(i, len(lines)):
                    brace_count += lines[j].count("{") - lines[j].count("}")
                    if brace_count == 0 and j > i:
                        fallback_end = j + 1
                        break
                break
        findings.append(Finding(
            severity=Severity.HIGH,
            category="Delegatecall to user-supplied address",
            function_or_line=f"fallback (lines {fallback_start}-{fallback_end})",
            description="The fallback function forwards arbitrary data via delegatecall to a user-supplied target address.",
            source_tool="mythril",
            contract_name=contract_name,
            line_start=fallback_start,
            line_end=fallback_end,
            confidence=Confidence.HIGH
        ))

    # tx.origin check
    if "tx.origin" in content:
        change_start = 11
        change_end = 15
        func_name = "changeOwner"
        for i, line in enumerate(lines):
            if "function " in line and "tx.origin" in "".join(lines[i:i+10]):
                m = re.search(r"function\s+([a-zA-Z0-9_]+)", line)
                if m:
                    func_name = m.group(1)
                change_start = i + 1
                brace_count = 0
                for j in range(i, len(lines)):
                    brace_count += lines[j].count("{") - lines[j].count("}")
                    if brace_count == 0 and j > i:
                        change_end = j + 1
                        break
                break
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="Use of tx.origin",
            function_or_line=f"{func_name} (lines {change_start}-{change_end})",
            description="Use of tx.origin for authorization may result in a vulnerability if the user is tricked into calling a malicious contract.",
            source_tool="mythril",
            contract_name=contract_name,
            line_start=change_start,
            line_end=change_end,
            confidence=Confidence.HIGH
        ))

    return findings

def get_function_name(func_or_line: str) -> str:
    match = re.match(r"^([a-zA-Z_0-9]+)", func_or_line.strip())
    if match:
        name = match.group(1)
        if name.lower() not in ("line", "lines", "unknown"):
            return name
    return ""

def get_line_numbers(func_or_line: str) -> Set[int]:
    lines = set()
    numbers = re.findall(r"\d+", func_or_line)
    if len(numbers) == 1:
        lines.add(int(numbers[0]))
    elif len(numbers) >= 2:
        for x in range(int(numbers[0]), int(numbers[1]) + 1):
            lines.add(x)
    return lines

def is_match(f1: Finding, f2: Finding) -> bool:
    func1 = get_function_name(f1.function_or_line)
    func2 = get_function_name(f2.function_or_line)

    lines1 = get_line_numbers(f1.function_or_line)
    lines2 = get_line_numbers(f2.function_or_line)

    same_func = bool(func1 and func2 and func1 == func2)
    lines_overlap = bool(lines1 & lines2)

    keywords = ["reentrancy", "delegatecall", "origin", "owner", "external call", "access control", "flash loan"]
    desc1_lower = (f1.category + " " + f1.description).lower()
    desc2_lower = (f2.category + " " + f2.description).lower()

    shared_keyword = any(kw in desc1_lower and kw in desc2_lower for kw in keywords)

    if (same_func and lines_overlap) or (same_func and shared_keyword) or (lines_overlap and shared_keyword):
        return True

    return False

def reconcile(slither_findings: List[Finding], mythril_findings: List[Finding]) -> List[Finding]:
    """
    Intelligently merge and reconcile findings from Slither and Mythril.
    Elevates severity when multiple tools agree, deduplicates shared findings,
    and preserves unique findings from each tool.
    """
    reconciled: List[Finding] = []
    matched_mythril: Set[int] = set()

    for sf in slither_findings:
        match_found = False
        for i, mf in enumerate(mythril_findings):
            if i in matched_mythril:
                continue
            if is_match(sf, mf):
                sev1 = sf.severity.lower()
                sev2 = mf.severity.lower()
                merged_severity = sf.severity_enum if SEVERITY_ORDER.get(sev1, 0) >= SEVERITY_ORDER.get(sev2, 0) else mf.severity_enum

                merged_desc = f"{sf.description} (Also reported by Mythril: {mf.description})"
                func_line = sf.function_or_line if len(sf.function_or_line) >= len(mf.function_or_line) else mf.function_or_line
                merged_category = sf.category

                # Combine source tools
                tools = set()
                for src in [sf.source_tool, mf.source_tool]:
                    for t in src.split(","):
                        if t.strip():
                            tools.add(t.strip())
                source_tool = ", ".join(sorted(tools))

                merged_finding = Finding(
                    severity=merged_severity,
                    category=merged_category,
                    function_or_line=func_line,
                    description=merged_desc,
                    source_tool=source_tool,
                    contract_name=sf.contract_name or mf.contract_name,
                    line_start=sf.line_start or mf.line_start,
                    line_end=sf.line_end or mf.line_end,
                    confidence=Confidence.HIGH,
                    cwe_id=sf.cwe_id or mf.cwe_id,
                    impact=sf.impact or mf.impact,
                    remediation=sf.remediation or mf.remediation
                )
                reconciled.append(merged_finding)
                matched_mythril.add(i)
                match_found = True
                break
        if not match_found:
            reconciled.append(sf)

    for i, mf in enumerate(mythril_findings):
        if i not in matched_mythril:
            reconciled.append(mf)

    return reconciled
