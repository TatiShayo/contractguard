"""
Slither Static Analysis Wrapper for ContractGuard.
Provides standardized execution, timeout resilience, and seamless AST fallback.
"""

import subprocess
import shutil
import json
import os
import logging
from typing import List, Dict, Any, Optional
from models import Finding, Severity, Confidence
from ast_analyzer import ASTAnalyzer

logger = logging.getLogger(__name__)

# Max contract source size (10 MB)
MAX_CONTRACT_SIZE_BYTES = 10 * 1024 * 1024


def run_slither(contract_path: str, fallback_to_ast: bool = True, offline: bool = False) -> List[Finding]:
    """
    Run Slither static analyzer on a Solidity contract.
    If Slither is unavailable or compilation fails, falls back gracefully to the built-in AST Analyzer.
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
            source_content = f.read()
    except (FileNotFoundError, PermissionError) as e:
        raise FileNotFoundError(f"Contract file not found or inaccessible at: {contract_path}") from e

    # Check offline flag or env var
    is_offline = offline or os.environ.get("CONTRACTGUARD_OFFLINE", "").lower() in ("1", "true", "yes")
    if is_offline:
        if fallback_to_ast:
            return ASTAnalyzer().analyze_source(source_content, contract_path)
        return []

    # Invoke slither with absolute path
    slither_bin = shutil.which("slither")
    if not slither_bin:
        logger.warning("slither not found in PATH — using built-in AST analyzer fallback")
        if fallback_to_ast:
            return ASTAnalyzer().analyze_source(source_content, contract_path)
        raise RuntimeError("slither not found in PATH. Install with: pip install slither-analyzer")

    bin_dir = os.path.dirname(slither_bin)
    if bin_dir and os.name == 'posix' and (os.stat(bin_dir).st_mode & 0o002):
        raise RuntimeError(f"slither binary at {slither_bin} is in a world-writable directory — refusing to execute")

    cmd = [slither_bin, contract_path, "--json", "-"]
    timeout_sec = int(os.environ.get("CONTRACTGUARD_SLITHER_TIMEOUT", "120"))
    
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec
        )
    except subprocess.TimeoutExpired:
        logger.error("Slither execution timed out after %d seconds — falling back to AST analyzer", timeout_sec)
        if fallback_to_ast:
            return ASTAnalyzer().analyze_source(source_content, contract_path)
        return []
    except Exception as e:
        logger.error("Slither invocation failed: %s — falling back to AST analyzer", e)
        if fallback_to_ast:
            return ASTAnalyzer().analyze_source(source_content, contract_path)
        return []
        
    stdout = result.stdout
    stderr = result.stderr
    
    # Locate the JSON block in stdout or stderr
    start_idx = stdout.find("{")
    if start_idx == -1:
        start_idx = stderr.find("{")
        if start_idx == -1:
            if "Compilation failed" in stderr or "Compilation failed" in stdout or result.returncode != 0:
                logger.info("Solidity compilation failed during Slither execution — using AST analyzer fallback")
                if fallback_to_ast:
                    return ASTAnalyzer().analyze_source(source_content, contract_path)
                return []
            return []
        else:
            json_str = stderr[start_idx:]
    else:
        json_str = stdout[start_idx:]
        
    data = None
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        end_idx = json_str.rfind("}")
        if end_idx != -1:
            try:
                data = json.loads(json_str[:end_idx + 1])
            except json.JSONDecodeError:
                if fallback_to_ast:
                    return ASTAnalyzer().analyze_source(source_content, contract_path)
                return []
        else:
            if fallback_to_ast:
                return ASTAnalyzer().analyze_source(source_content, contract_path)
            return []
            
    findings: List[Finding] = []
    if not data or not data.get("success"):
        if data and data.get("error"):
            if not data.get("results", {}).get("detectors"):
                if fallback_to_ast:
                    return ASTAnalyzer().analyze_source(source_content, contract_path)
                return []
                
    detectors = data.get("results", {}).get("detectors", [])
    for detector in detectors:
        impact = (detector.get("impact") or "unknown").lower()
        severity = Severity.from_str(impact)
        category = detector.get("check") or "unknown"
        description = detector.get("description", "").strip()
        
        # Determine function_or_line
        func_name = None
        first_line = None
        last_line = None
        lines = []
        contract_name = basename[:-4] if basename.endswith(".sol") else basename

        for elem in detector.get("elements", []):
            if not first_line and elem.get("source_mapping", {}).get("lines"):
                lines = elem["source_mapping"]["lines"]
                if lines:
                    first_line = min(lines)
                    last_line = max(lines)
            if elem.get("type") == "function":
                func_name = elem.get("name")
            if elem.get("type") == "contract" and elem.get("name"):
                contract_name = elem.get("name")
        
        if func_name and first_line and last_line and first_line != last_line:
            function_or_line = f"{func_name} (lines {first_line}-{last_line})"
        elif func_name and first_line:
            function_or_line = f"{func_name} (lines {first_line})"
        elif func_name:
            function_or_line = func_name
        elif first_line and last_line and first_line != last_line:
            function_or_line = f"Lines {first_line}-{last_line}"
        elif first_line:
            function_or_line = f"Line {first_line}"
        else:
            function_or_line = "unknown"
            
        findings.append(Finding(
            severity=severity,
            category=category,
            function_or_line=function_or_line,
            description=description,
            source_tool="slither",
            contract_name=contract_name,
            line_start=first_line,
            line_end=last_line or first_line,
            confidence=Confidence.HIGH
        ))
        
    return findings
