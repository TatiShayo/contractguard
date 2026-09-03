"""
ContractGuard Command Line Interface (CLI).
Provides enterprise CLI for smart contract security audits, reports, and CI/CD gates.
Hermes v6 Engineering Standard compliant.
"""

import argparse
import sys
import os
import glob
from typing import List
from models import Finding, Severity, Confidence
from slither_wrapper import run_slither
from mythril_wrapper import run_mythril, reconcile
from economic_logic_judge import review_economic_logic
from ast_analyzer import ASTAnalyzer
from report_generator import (
    generate_report,
    generate_sarif_report,
    generate_json_report,
    calculate_security_score
)

VERSION = "2.0.0"


def audit_contract(file_path: str, offline: bool = False, min_severity: Severity = Severity.INFORMATIONAL) -> List[Finding]:
    """
    Execute full multi-layer security audit on a single Solidity contract.
    """
    file_path = os.path.realpath(os.path.abspath(file_path))
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Contract not found: {file_path}")

    # 1. Slither Static Analysis
    try:
        slither_f = run_slither(file_path, offline=offline)
    except Exception:
        slither_f = []

    # 2. Mythril Symbolic Execution
    try:
        mythril_f = run_mythril(file_path, offline=offline)
    except Exception:
        mythril_f = []

    # 3. Reconcile Slither & Mythril
    reconciled_f = reconcile(slither_f, mythril_f)

    # 4. Read source code
    with open(file_path, "r", encoding="utf-8") as f:
        source = f.read()

    # 5. Economic Logic Judge (LLM or Heuristic)
    try:
        if offline:
            # Force fallback mode by temporarily unsetting keys
            old_openai = os.environ.pop("OPENAI_API_KEY", None)
            old_gemini = os.environ.pop("GEMINI_API_KEY", None)
            try:
                llm_f = review_economic_logic(source, reconciled_f)
            finally:
                if old_openai:
                    os.environ["OPENAI_API_KEY"] = old_openai
                if old_gemini:
                    os.environ["GEMINI_API_KEY"] = old_gemini
        else:
            llm_f = review_economic_logic(source, reconciled_f)
    except Exception:
        llm_f = []

    # 6. Built-in AST Analyzer
    ast_f = ASTAnalyzer().analyze_source(source, file_path)

    # Combine findings with deduplication
    all_findings = []
    seen = set()

    for f in (reconciled_f + llm_f + ast_f):
        key = (f.rule_id, f.function_or_line, f.severity)
        if key not in seen:
            seen.add(key)
            if f.severity_enum >= min_severity and not getattr(f, "suppressed", False):
                all_findings.append(f)

    return all_findings


def main():
    parser = argparse.ArgumentParser(
        prog="contractguard",
        description="ContractGuard Enterprise Smart Contract Security & Economic Logic Analysis Suite"
    )
    parser.add_argument("target", help="Solidity contract file or directory to analyze", nargs="?", default=".")
    parser.add_argument("--format", choices=["markdown", "json", "sarif", "all"], default="all", help="Report output format")
    parser.add_argument("-o", "--output", help="Output directory or file path")
    parser.add_argument("--min-severity", choices=["informational", "low", "medium", "high", "critical"], default="informational", help="Minimum severity threshold")
    parser.add_argument("--offline", action="store_true", help="Run purely offline using AST & heuristic engines without external API calls")
    parser.add_argument("--version", action="version", version=f"ContractGuard v{VERSION}")

    args = parser.parse_args()

    target_path = os.path.realpath(os.path.abspath(args.target))
    min_sev = Severity.from_str(args.min_severity)

    contracts_to_scan = []
    if os.path.isfile(target_path):
        if target_path.endswith(".sol"):
            contracts_to_scan.append(target_path)
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith(".sol"):
                    contracts_to_scan.append(os.path.join(root, file))

    if not contracts_to_scan:
        print(f"No .sol contracts found at target: {target_path}")
        sys.exit(0)

    print(f"ContractGuard v{VERSION} - Scanning {len(contracts_to_scan)} contract(s)...")

    all_findings = []
    for c_path in contracts_to_scan:
        print(f"  [+] Auditing {os.path.basename(c_path)}...")
        try:
            f_list = audit_contract(c_path, offline=args.offline, min_severity=min_sev)
            all_findings.extend(f_list)
        except Exception as e:
            print(f"  [!] Failed to audit {c_path}: {e}")

    score, grade = calculate_security_score(all_findings)
    print(f"\nAudit Complete: {len(all_findings)} finding(s) identified across {len(contracts_to_scan)} file(s).")
    print(f"Overall Security Score: {score}/100 ({grade})\n")

    # Generate Reports
    out_dir = args.output or "."
    if os.path.isfile(out_dir):
        out_dir = os.path.dirname(out_dir) or "."
    os.makedirs(out_dir, exist_ok=True)

    if args.format in ("markdown", "all"):
        md_content = generate_report(all_findings)
        md_file = os.path.join(out_dir, "UNIFIED_REPORT.md")
        with open(md_file, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"  [OK] Saved Markdown report to {md_file}")

    if args.format in ("sarif", "all"):
        sarif_content = generate_sarif_report(all_findings, tool_version=VERSION)
        sarif_file = os.path.join(out_dir, "REPORT.sarif")
        with open(sarif_file, "w", encoding="utf-8") as f:
            f.write(sarif_content)
        print(f"  [OK] Saved SARIF v2.1.0 report to {sarif_file}")

    if args.format in ("json", "all"):
        json_content = generate_json_report(all_findings)
        json_file = os.path.join(out_dir, "FINDINGS.json")
        with open(json_file, "w", encoding="utf-8") as f:
            f.write(json_content)
        print(f"  [OK] Saved JSON report to {json_file}")

    # Return non-zero if critical vulnerabilities exist
    has_critical = any(f.severity in ("critical", "high") for f in all_findings)
    if has_critical:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
