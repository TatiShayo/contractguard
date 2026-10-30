"""
Unit and Property Tests for ContractGuard Data Models.
Hermes v6 Engineering Standard compliant.
"""

import pytest
from models import Severity, Confidence, Finding

def test_severity_from_str_standard():
    assert Severity.from_str("critical") == Severity.CRITICAL
    assert Severity.from_str("high") == Severity.HIGH
    assert Severity.from_str("medium") == Severity.MEDIUM
    assert Severity.from_str("low") == Severity.LOW
    assert Severity.from_str("informational") == Severity.INFORMATIONAL

def test_severity_from_str_aliases():
    assert Severity.from_str("crit") == Severity.CRITICAL
    assert Severity.from_str("h") == Severity.HIGH
    assert Severity.from_str("med") == Severity.MEDIUM
    assert Severity.from_str("m") == Severity.MEDIUM
    assert Severity.from_str("l") == Severity.LOW
    assert Severity.from_str("info") == Severity.INFORMATIONAL
    assert Severity.from_str("opt") == Severity.INFORMATIONAL
    assert Severity.from_str("optimization") == Severity.INFORMATIONAL
    assert Severity.from_str("none") == Severity.INFORMATIONAL
    assert Severity.from_str(None) == Severity.INFORMATIONAL
    assert Severity.from_str("") == Severity.INFORMATIONAL
    assert Severity.from_str("unknown_val") == Severity.INFORMATIONAL

def test_severity_from_str_already_enum():
    assert Severity.from_str(Severity.HIGH) == Severity.HIGH
    assert Severity.from_str(Severity.CRITICAL) == Severity.CRITICAL

def test_severity_score_penalties():
    assert Severity.CRITICAL.score_penalty == 25
    assert Severity.HIGH.score_penalty == 15
    assert Severity.MEDIUM.score_penalty == 8
    assert Severity.LOW.score_penalty == 3
    assert Severity.INFORMATIONAL.score_penalty == 0

def test_severity_sarif_levels():
    assert Severity.CRITICAL.sarif_level == "error"
    assert Severity.HIGH.sarif_level == "error"
    assert Severity.MEDIUM.sarif_level == "warning"
    assert Severity.LOW.sarif_level == "note"
    assert Severity.INFORMATIONAL.sarif_level == "none"

def test_severity_ordering_between_enums():
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.LOW > Severity.INFORMATIONAL
    assert Severity.INFORMATIONAL < Severity.LOW
    assert Severity.HIGH >= Severity.HIGH
    assert Severity.HIGH <= Severity.HIGH
    assert Severity.LOW <= Severity.CRITICAL

def test_severity_ordering_with_strings():
    assert Severity.CRITICAL > "high"
    assert Severity.HIGH > "medium"
    assert Severity.MEDIUM >= "medium"
    assert Severity.LOW < "high"
    assert Severity.INFORMATIONAL <= "low"

def test_confidence_from_str_variants():
    assert Confidence.from_str("high") == Confidence.HIGH
    assert Confidence.from_str("h") == Confidence.HIGH
    assert Confidence.from_str("med") == Confidence.MEDIUM
    assert Confidence.from_str("medium") == Confidence.MEDIUM
    assert Confidence.from_str("m") == Confidence.MEDIUM
    assert Confidence.from_str("low") == Confidence.LOW
    assert Confidence.from_str("l") == Confidence.LOW
    assert Confidence.from_str(None) == Confidence.HIGH
    assert Confidence.from_str(Confidence.LOW) == Confidence.LOW

def test_finding_initialization_defaults():
    f = Finding(
        severity="high",
        category="Reentrancy",
        function_or_line="withdraw",
        description="Reentrancy in withdraw"
    )
    assert f.severity == "high"
    assert f.severity_enum == Severity.HIGH
    assert f.confidence == "High"
    assert f.rule_id == "CG-001-REENTRANCY"
    assert f.cwe_id == "CWE-841"
    assert "reentrant" in f.impact.lower()
    assert f.suppressed is False
    assert f.line_start is None
    assert f.line_end is None

def test_finding_parse_line_numbers_range():
    f = Finding(
        severity="medium",
        category="tx.origin",
        function_or_line="changeOwner (lines 15-23)",
        description="tx.origin auth"
    )
    assert f.line_start == 15
    assert f.line_end == 23

def test_finding_parse_line_numbers_single():
    f = Finding(
        severity="low",
        category="Useless statement",
        function_or_line="Line 42",
        description="Dead code"
    )
    assert f.line_start == 42
    assert f.line_end == 42

def test_finding_parse_line_numbers_does_not_misparse_types():
    f = Finding(
        severity="high",
        category="reentrancy",
        function_or_line="withdrawUint256",
        description="Desc"
    )
    assert f.line_start is None
    assert f.line_end is None

def test_finding_derive_rule_id_all_categories():
    assert Finding._derive_rule_id("Reentrancy vulnerability") == "CG-001-REENTRANCY"
    assert Finding._derive_rule_id("tx.origin authorization") == "CG-002-TX-ORIGIN"
    assert Finding._derive_rule_id("Controlled delegatecall") == "CG-003-CONTROLLED-DELEGATECALL"
    assert Finding._derive_rule_id("Unchecked return value") == "CG-004-UNCHECKED-CALL"
    assert Finding._derive_rule_id("Missing access control") == "CG-005-ACCESS-CONTROL"
    assert Finding._derive_rule_id("Arbitrary external call") == "CG-006-ARBITRARY-CALL"
    assert Finding._derive_rule_id("Flash loan deposit reentrancy") == "CG-007-FLASHLOAN-DEPOSIT-REENTRANCY"
    assert Finding._derive_rule_id("Flash loan fee exploitation") == "CG-008-FLASHLOAN-ACCESS-CONTROL"
    assert Finding._derive_rule_id("Oracle spot price manipulation") == "CG-009-PRICE-ORACLE-MANIPULATION"
    assert Finding._derive_rule_id("Unprotected selfdestruct") == "CG-010-SELFDESTRUCT"
    assert Finding._derive_rule_id("Integer overflow in unchecked") == "CG-011-INTEGER-OVERFLOW"
    assert Finding._derive_rule_id("Dead code useless statement") == "CG-012-USELESS-STATEMENT"
    assert Finding._derive_rule_id("Unprotected initialize function") == "CG-013-UNPROTECTED-INITIALIZE"
    assert Finding._derive_rule_id("Missing zero-check on owner") == "CG-014-MISSING-ZERO-CHECK"
    assert Finding._derive_rule_id("Unknown novel bug") == "CG-999-GENERIC"

def test_finding_to_dict_keys():
    f = Finding(
        severity=Severity.HIGH,
        category="Reentrancy",
        function_or_line="withdraw (lines 10-15)",
        description="Reentrancy in withdraw",
        contract_name="Bank",
        line_start=10,
        line_end=15,
        confidence=Confidence.HIGH,
        code_snippet="balances[msg.sender] -= amount;"
    )
    d = f.to_dict()
    expected_keys = {
        "id", "rule_id", "severity", "category", "function_or_line", "contract_name",
        "line_start", "line_end", "column_start", "column_end", "description", "impact",
        "remediation", "cwe_id", "confidence", "source_tool", "code_snippet", "suppressed"
    }
    assert expected_keys.issubset(d.keys())
    assert d["contract_name"] == "Bank"
    assert d["severity"] == "high"
    assert d["line_start"] == 10
    assert d["line_end"] == 15

def test_finding_to_sarif_result_structure():
    f = Finding(
        severity="critical",
        category="Selfdestruct",
        function_or_line="kill (line 99)",
        description="Unprotected selfdestruct",
        contract_name="Vault.sol",
        line_start=99,
        line_end=99
    )
    sarif = f.to_sarif_result("contracts/Vault.sol")
    assert sarif["ruleId"] == "CG-010-SELFDESTRUCT"
    assert sarif["level"] == "error"
    assert sarif["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "contracts/Vault.sol"
    assert sarif["locations"][0]["physicalLocation"]["region"]["startLine"] == 99

def test_finding_equality_and_hash():
    f1 = Finding(severity="high", category="Reentrancy", function_or_line="withdraw", description="Desc")
    f2 = Finding(severity="high", category="Reentrancy", function_or_line="withdraw", description="Desc")
    f3 = Finding(severity="medium", category="Reentrancy", function_or_line="withdraw", description="Desc")

    assert f1 == f2
    assert f1 != f3
    assert f1 != "not_a_finding"
    assert hash(f1) == hash(f2)
    s = {f1, f2, f3}
    assert len(s) == 2
