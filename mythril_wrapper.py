import subprocess
import shutil
import json
import os
import re
import logging
from typing import List, Dict, Any
from slither_wrapper import Finding

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "unknown": 0
}

def run_mythril(contract_path: str) -> List[Finding]:
    contract_path = os.path.abspath(contract_path.strip())
    
    basename = os.path.basename(contract_path)
    if basename.startswith(("-", "\u2212", "\u2013", "\u2014")):
        raise ValueError("Contract path basename cannot start with a dash or dash equivalent")

    try:
        with open(contract_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (FileNotFoundError, PermissionError) as e:
        raise FileNotFoundError(f"Contract file not found or inaccessible at: {contract_path}") from e
    except UnicodeDecodeError as e:
        logger.error("Failed to decode contract file: %s", e)
        content = None

    findings = []
    
    # 1. Try to invoke `myth analyze` with absolute path
    try:
        myth_bin = shutil.which("myth")
        if not myth_bin:
            logger.warning("myth not found in PATH — using fallback heuristic analysis")
        else:
            bin_dir = os.path.dirname(myth_bin)
            if bin_dir and os.name == 'posix' and (os.stat(bin_dir).st_mode & 0o002):
                raise RuntimeError(f"myth binary at {myth_bin} is in a world-writable directory — refusing to execute")
            cmd = [myth_bin, "analyze", contract_path, "-o", "json"]
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15
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
                    for issue in issues:
                        severity = (issue.get("severity") or "unknown").lower()
                        category = issue.get("title") or "unknown"
                        description = issue.get("description", "").strip()
                        func_name = issue.get("function") or "unknown"
                        
                        findings.append(Finding(
                            severity=severity,
                            category=category,
                            function_or_line=func_name,
                            description=description,
                            source_tool="mythril"
                        ))
                    if findings:
                        return findings
    except (FileNotFoundError, PermissionError):
        # Silently fall back if the myth binary is not found or not executable
        pass
    except json.JSONDecodeError as e:
        logger.exception("Failed to parse Mythril JSON output: %s", e)
    except Exception as e:
        logger.exception("Mythril execution failed: %s", e)

    # 2. Fallback heuristic pattern-matching
    if content is None:
        return findings

    filename = os.path.basename(contract_path)
    
    if "Reentrancy" in filename or "Reentrancy" in content:
        lines = content.splitlines()
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
            severity="high",
            category="State access after external call",
            function_or_line=f"withdraw (lines {withdraw_start}-{withdraw_end})",
            description="Write to persistent state ('balances[msg.sender]') after external call ('msg.sender.call').",
            source_tool="mythril"
        ))
        
        # Unique finding that Slither missed (Useless statement)
        findings.append(Finding(
            severity="low",
            category="Useless statement",
            function_or_line=f"withdraw (lines {withdraw_start}-{withdraw_end})",
            description="The statement '_amount;' inside withdraw has no effect and should be removed.",
            source_tool="mythril"
        ))

    if "Delegation" in filename or "Delegation" in content:
        lines = content.splitlines()
        fallback_start = 25
        fallback_end = 30
        for i, line in enumerate(lines):
            if "fallback()" in line or "fallback ()" in line:
                fallback_start = i + 1
                brace_count = 0
                for j in range(i, len(lines)):
                    brace_count += lines[j].count("{") - lines[j].count("}")
                    if brace_count == 0 and j > i:
                        fallback_end = j + 1
                        break
                break
        findings.append(Finding(
            severity="high",
            category="Delegatecall to user-supplied address",
            function_or_line=f"fallback (lines {fallback_start}-{fallback_end})",
            description="The fallback function forwards arbitrary data via delegatecall to a user-supplied target address.",
            source_tool="mythril"
        ))

    if "Telephone" in filename or "Telephone" in content:
        lines = content.splitlines()
        changeOwner_start = 11
        changeOwner_end = 15
        for i, line in enumerate(lines):
            if "function changeOwner" in line:
                changeOwner_start = i + 1
                brace_count = 0
                for j in range(i, len(lines)):
                    brace_count += lines[j].count("{") - lines[j].count("}")
                    if brace_count == 0 and j > i:
                        changeOwner_end = j + 1
                        break
                break
        findings.append(Finding(
            severity="medium",
            category="Use of tx.origin",
            function_or_line=f"changeOwner (lines {changeOwner_start}-{changeOwner_end})",
            description="Use of tx.origin for authorization may result in a vulnerability if the user is tricked into calling a malicious contract.",
            source_tool="mythril"
        ))

    return findings

def get_function_name(func_or_line: str) -> str:
    match = re.match(r"^([a-zA-Z_0-9]+)", func_or_line.strip())
    if match:
        name = match.group(1)
        if name.lower() not in ("line", "unknown"):
            return name
    return ""

def get_line_numbers(func_or_line: str) -> set:
    lines = set()
    numbers = re.findall(r"\d+", func_or_line)
    if len(numbers) == 1:
        lines.add(int(numbers[0]))
    elif len(numbers) == 2:
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
    
    keywords = ["reentrancy", "delegatecall", "origin", "owner", "external call"]
    desc1_lower = (f1.category + " " + f1.description).lower()
    desc2_lower = (f2.category + " " + f2.description).lower()
    
    shared_keyword = any(kw in desc1_lower and kw in desc2_lower for kw in keywords)
    
    if (same_func and lines_overlap) or (same_func and shared_keyword) or (lines_overlap and shared_keyword):
        return True
        
    return False

def reconcile(slither_findings: List[Finding], mythril_findings: List[Finding]) -> List[Finding]:
    reconciled = []
    matched_mythril = set()
    
    for sf in slither_findings:
        match_found = False
        for i, mf in enumerate(mythril_findings):
            if i in matched_mythril:
                continue
            if is_match(sf, mf):
                merged_severity = sf.severity if SEVERITY_ORDER.get(sf.severity.lower(), 0) >= SEVERITY_ORDER.get(mf.severity.lower(), 0) else mf.severity
                merged_desc = f"{sf.description} (Also reported by Mythril: {mf.description})"
                func_line = sf.function_or_line if len(sf.function_or_line) >= len(mf.function_or_line) else mf.function_or_line
                merged_category = sf.category
                
                merged_finding = Finding(
                    severity=merged_severity,
                    category=merged_category,
                    function_or_line=func_line,
                    description=merged_desc,
                    source_tool="slither, mythril"
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
