import subprocess
import shutil
import json
import os
from typing import List, Dict, Any

class Finding:
    def __init__(self, severity: str, category: str, function_or_line: str, description: str, source_tool: str = "slither"):
        self.severity = severity
        self.category = category
        self.function_or_line = function_or_line
        self.description = description
        self.source_tool = source_tool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "function_or_line": self.function_or_line,
            "description": self.description,
            "source_tool": self.source_tool
        }

    def __repr__(self) -> str:
        return f"Finding(severity={self.severity}, category={self.category}, function_or_line={self.function_or_line}, source_tool={self.source_tool})"

def run_slither(contract_path: str) -> List[Finding]:
    contract_path = os.path.abspath(contract_path.strip())
    
    basename = os.path.basename(contract_path)
    if basename.startswith(("-", "\u2212", "\u2013", "\u2014")):
        raise ValueError("Contract path basename cannot start with a dash or dash equivalent")

    try:
        with open(contract_path, "r", encoding="utf-8") as f:
            pass
    except (FileNotFoundError, PermissionError) as e:
        raise FileNotFoundError(f"Contract file not found or inaccessible at: {contract_path}") from e

    # Invoke slither with absolute path
    slither_bin = shutil.which("slither")
    if not slither_bin:
        raise RuntimeError("slither not found in PATH. Install with: pip install slither-analyzer")
    bin_dir = os.path.dirname(slither_bin)
    if bin_dir and os.name == 'posix' and (os.stat(bin_dir).st_mode & 0o002):
        raise RuntimeError(f"slither binary at {slither_bin} is in a world-writable directory — refusing to execute")
    cmd = [slither_bin, contract_path, "--json", "-"]
    
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
        
    stdout = result.stdout
    stderr = result.stderr
    
    # Locate the JSON block in stdout
    start_idx = stdout.find("{")
    if start_idx == -1:
        start_idx = stderr.find("{")
        if start_idx == -1:
            if "Compilation failed" in stderr or "Compilation failed" in stdout:
                raise RuntimeError(f"Solidity compilation failed:\n{stderr}\n{stdout}")
            return []
        else:
            json_str = stderr[start_idx:]
    else:
        json_str = stdout[start_idx:]
        
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        end_idx = json_str.rfind("}")
        if end_idx != -1:
            try:
                data = json.loads(json_str[:end_idx + 1])
            except json.JSONDecodeError:
                raise RuntimeError(f"Failed to parse Slither JSON output: {e}\nRaw Output: {stdout}\nStderr: {stderr}")
        else:
            raise RuntimeError(f"Failed to parse Slither JSON output: {e}\nRaw Output: {stdout}\nStderr: {stderr}")
            
    findings = []
    if not data or not data.get("success"):
        if data and data.get("error"):
            if not data.get("results", {}).get("detectors"):
                raise RuntimeError(f"Slither execution failed: {data.get('error')}")
                
    detectors = data.get("results", {}).get("detectors", [])
    for detector in detectors:
        severity = (detector.get("impact") or "unknown").lower()
        category = detector.get("check") or "unknown"
        description = detector.get("description", "").strip()
        
        # Determine function_or_line
        func_name = None
        first_line = None
        lines = []
        for elem in detector.get("elements", []):
            if not first_line and elem.get("source_mapping", {}).get("lines"):
                lines = elem["source_mapping"]["lines"]
                first_line = lines[0] if lines else None
            if elem.get("type") == "function":
                func_name = elem.get("name")
        
        if func_name and first_line:
            # e.g. "withdraw (lines 6-12)" or lines list
            lines_str = "-".join(map(str, sorted(lines))) if len(lines) > 1 else str(first_line)
            function_or_line = f"{func_name} (lines {lines_str})"
        elif func_name:
            function_or_line = func_name
        elif first_line:
            function_or_line = f"Line {first_line}"
        else:
            function_or_line = "unknown"
            
        findings.append(Finding(
            severity=severity,
            category=category,
            function_or_line=function_or_line,
            description=description,
            source_tool="slither"
        ))
        
    return findings
