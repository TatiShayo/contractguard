"""
Unit Tests for Report Generator (Markdown, SARIF v2.1.0, and Sanitized JSON).
Hermes v6 Engineering Standard compliant.
"""

import pytest
import json
from report_generator import (
    calculate_security_score,
    get_security_grade,
    sanitize_text,
    generate_report,
    generate_sarif_report,
    generate_json_report
)
from models import Finding, Severity, Confidence
from rules import RULES_REGISTRY, get_remediation_for_rule, get_rule_by_id


def test_calculate_security_score_perfect():
    score, grade = calculate_security_score([])
    assert score == 100
    assert "A+" in grade or "A" in grade


def test_calculate_security_score_critical():
    f = Finding(severity="critical", category="Selfdestruct", function_or_line="kill", description="Selfdestruct")
    score, grade = calculate_security_score([f])
    assert score == 75
    assert "C" in grade


def test_calculate_security_score_multiple_criticals():
    findings = [
        Finding(severity="critical", category=f"Exploit {i}", function_or_line="foo", description="Crit")
        for i in range(5)
    ]
    score, grade = calculate_security_score(findings)
    assert score == 0
    assert "F" in grade


def test_calculate_security_score_mixed():
    findings = [
        Finding(severity="high", category="Reentrancy", function_or_line="withdraw", description="Reentrancy"),  # -15
        Finding(severity="medium", category="tx.origin", function_or_line="auth", description="tx.origin"),     # -8
        Finding(severity="low", category="Dead code", function_or_line="Line 5", description="Dead code"),        # -3
        Finding(severity="informational", category="Info", function_or_line="Line 1", description="Info"),        # 0
    ]
    # Total penalty: 15 + 8 + 3 = 26. Score = 100 - 26 = 74.
    score, grade = calculate_security_score(findings)
    assert score == 74
    assert "C" in grade


def test_calculate_security_score_suppressed_ignored():
    f1 = Finding(severity="critical", category="Ignored", function_or_line="foo", description="Ignored", suppressed=True)
    score, grade = calculate_security_score([f1])
    assert score == 100


def test_get_security_grade_thresholds():
    assert "A+" in get_security_grade(98)
    assert "A" in get_security_grade(92)
    assert "B" in get_security_grade(85)
    assert "C" in get_security_grade(75)
    assert "D" in get_security_grade(55)
    assert "F" in get_security_grade(40)


def test_sanitize_text_null_and_control_chars():
    dirty = "Hello\x00World\x07\x1bTest\nLine"
    clean = sanitize_text(dirty)
    assert "\x00" not in clean
    assert "\x07" not in clean
    assert "\x1b" not in clean
    assert clean == "HelloWorldTest\nLine"


def test_generate_report_markdown_structure():
    f = Finding(
        severity="high",
        category="Reentrancy / State access after external call",
        function_or_line="withdraw (lines 15-23)",
        description="Reentrancy vulnerability.",
        source_tool="slither",
        contract_name="Reentrancy.sol"
    )
    md = generate_report([f])
    assert "# ContractGuard Unified Security Audit Report" in md
    assert "## 🛡️ Security Posture Summary" in md
    assert "## 🔍 Deterministic Results" in md
    assert "withdraw (lines 15-23)" in md
    assert "Reentrancy.sol" in md


def test_generate_report_no_escaped_newlines():
    f = Finding(
        severity="high",
        category="Reentrancy",
        function_or_line="withdraw",
        description="Reentrancy detected.",
        source_tool="slither",
        contract_name="Reentrancy.sol"
    )
    md = generate_report([f])
    # Ensure there are no literal '\n' characters in the rendered markdown output
    # (i.e. double escaped backslash-n sequences)
    assert "\\n" not in md


def test_generate_report_contains_disclaimer_and_review_note():
    md = generate_report([])
    assert "Mandatory Research & Portfolio Disclaimer" in md
    assert "Confidence and Review Note" in md


def test_generate_sarif_report_valid_json():
    f = Finding(
        severity="high",
        category="Reentrancy",
        function_or_line="withdraw (lines 15-23)",
        description="Reentrancy detected.",
        source_tool="slither",
        contract_name="Reentrancy.sol",
        line_start=15,
        line_end=23
    )
    sarif_str = generate_sarif_report([f])
    sarif_obj = json.loads(sarif_str)
    assert sarif_obj["version"] == "2.1.0"
    assert len(sarif_obj["runs"]) == 1
    run = sarif_obj["runs"][0]
    assert run["tool"]["driver"]["name"] == "ContractGuard"
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 15
    assert result["locations"][0]["physicalLocation"]["region"]["endLine"] == 23


def test_generate_json_report_valid_json():
    f = Finding(
        severity="medium",
        category="Use of tx.origin",
        function_or_line="changeOwner (lines 11-15)",
        description="tx.origin authorization.",
        source_tool="slither",
        contract_name="Telephone.sol"
    )
    json_str = generate_json_report([f])
    data = json.loads(json_str)
    assert data["generator"] == "ContractGuard v2.0"
    assert data["total_findings"] == 1
    assert data["statistics"]["medium"] == 1
    assert len(data["findings"]) == 1
    assert data["findings"][0]["severity"] == "medium"


def test_get_remediation_for_rule_all_rules():
    for rule_id, rule_info in RULES_REGISTRY.items():
        remediation = get_remediation_for_rule(rule_id)
        assert len(remediation) > 0
        assert rule_info["cwe"].startswith("CWE-")


def test_generate_report_with_all_tool_sources():
    findings = [
        Finding(severity="high", category="Reentrancy", function_or_line="withdraw", description="Desc", source_tool="slither, mythril"),
        Finding(severity="high", category="Controlled delegatecall", function_or_line="fallback", description="Desc", source_tool="slither"),
        Finding(severity="medium", category="Use of tx.origin", function_or_line="changeOwner", description="Desc", source_tool="mythril"),
        Finding(severity="high", category="Arbitrary external call", function_or_line="flashLoan", description="Desc", source_tool="ast_analyzer"),
        Finding(severity="high", category="Deposit-based Flash Loan Reentrancy", function_or_line="flashLoan", description="Desc", source_tool="llm_judge"),
    ]
    md = generate_report(findings)
    assert "**Reconciled (Slither & Mythril):** 1" in md
    assert "**Slither Only:** 1" in md
    assert "**Mythril Only:** 1" in md
    assert "**Standalone AST Engine:** 1" in md
    assert "**LLM Economic Logic Judge:** 1" in md


def test_generate_report_empty_findings():
    md = generate_report([])
    assert "100 / 100" in md
    assert "A+ (Excellent)" in md
    sarif = json.loads(generate_sarif_report([]))
    assert sarif["runs"][0]["results"] == []
    j = json.loads(generate_json_report([]))
    assert j["security_score"] == 100
    assert j["total_findings"] == 0


def test_sanitize_text_unicode_and_emojis():
    text_with_emoji = "Safe Contract 🛡️ \x00\x1fPassed!"
    clean = sanitize_text(text_with_emoji)
    assert "\x00" not in clean
    assert "\x1f" not in clean
    assert "🛡️" in clean
    assert "Safe Contract 🛡️ Passed!" == clean

