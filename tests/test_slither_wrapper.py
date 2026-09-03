"""
Unit Tests for Slither Static Analysis Wrapper.
Hermes v6 Engineering Standard compliant.
"""

import pytest
import os
import tempfile
from slither_wrapper import run_slither
from models import Finding, Severity, Confidence


@pytest.fixture
def base_dir():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_run_slither_reentrancy_fixture(base_dir):
    path = os.path.join(base_dir, "fixtures", "ethernaut", "Reentrancy.sol")
    findings = run_slither(path)
    assert len(findings) > 0
    categories = [f.category for f in findings]
    assert any("reentrancy" in c.lower() for c in categories)


def test_run_slither_telephone_fixture(base_dir):
    path = os.path.join(base_dir, "fixtures", "ethernaut", "Telephone.sol")
    findings = run_slither(path)
    assert len(findings) > 0
    categories = [f.category for f in findings]
    assert any("missing-zero-check" in c.lower() or "origin" in c.lower() or "tx.origin" in c.lower() for c in categories)


def test_run_slither_delegation_fixture(base_dir):
    path = os.path.join(base_dir, "fixtures", "ethernaut", "Delegation.sol")
    findings = run_slither(path)
    assert len(findings) > 0
    categories = [f.category for f in findings]
    assert any("controlled-delegatecall" in c.lower() or "delegatecall" in c.lower() for c in categories)


def test_run_slither_clean_fixture(base_dir):
    path = os.path.join(base_dir, "fixtures", "ethernaut", "Clean.sol")
    findings = run_slither(path)
    high_or_med = [f for f in findings if f.severity in ("high", "critical", "medium")]
    assert len(high_or_med) == 0


def test_run_slither_empty_path_raises():
    with pytest.raises(ValueError, match="cannot be empty"):
        run_slither("")


def test_run_slither_nonexistent_file_raises():
    with pytest.raises(FileNotFoundError):
        run_slither("/nonexistent/contract/path/DoesNotExist.sol")


def test_run_slither_directory_raises(base_dir):
    with pytest.raises(ValueError, match="not a regular file"):
        run_slither(base_dir)


def test_run_slither_dash_basename_raises():
    with pytest.raises(ValueError, match="cannot start with a dash"):
        run_slither("-malicious.sol")


def test_run_slither_unicode_dash_basename_raises():
    with pytest.raises(ValueError, match="cannot start with a dash"):
        run_slither("\u2013malicious.sol")


def test_run_slither_fallback_when_slither_fails(base_dir):
    # Tests that fallback_to_ast operates cleanly
    path = os.path.join(base_dir, "fixtures", "dvd", "TrusterLenderPool.sol")
    findings = run_slither(path, fallback_to_ast=True)
    assert len(findings) > 0
    assert any("arbitrary" in f.category.lower() or "external call" in f.category.lower() or f.rule_id == "CG-006-ARBITRARY-CALL" for f in findings)


def test_slither_finding_attributes():
    f = Finding(
        severity="high",
        category="reentrancy-eth",
        function_or_line="withdraw (lines 15-23)",
        description="Reentrancy in withdraw function.",
        source_tool="slither",
        contract_name="Reentrancy"
    )
    assert f.severity == "high"
    assert f.severity_enum == Severity.HIGH
    assert f.category == "reentrancy-eth"
    assert f.line_start == 15
    assert f.line_end == 23
    assert f.rule_id == "CG-001-REENTRANCY"
    assert f.cwe_id == "CWE-841"


def test_slither_finding_to_dict():
    f = Finding(
        severity="medium",
        category="tx-origin",
        function_or_line="changeOwner (lines 11-15)",
        description="tx.origin auth.",
        source_tool="slither",
        contract_name="Telephone"
    )
    d = f.to_dict()
    assert d["severity"] == "medium"
    assert d["category"] == "tx-origin"
    assert d["source_tool"] == "slither"
    assert d["contract_name"] == "Telephone"
    assert d["line_start"] == 11
    assert d["line_end"] == 15


def test_slither_finding_to_sarif():
    f = Finding(
        severity="high",
        category="controlled-delegatecall",
        function_or_line="fallback (lines 25-30)",
        description="Controlled delegatecall in fallback.",
        source_tool="slither",
        contract_name="Delegation.sol"
    )
    sarif_res = f.to_sarif_result("fixtures/ethernaut/Delegation.sol")
    assert sarif_res["ruleId"] == "CG-003-CONTROLLED-DELEGATECALL"
    assert sarif_res["level"] == "error"
    loc = sarif_res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "fixtures/ethernaut/Delegation.sol"
    assert loc["region"]["startLine"] == 25
    assert loc["region"]["endLine"] == 30


def test_run_slither_offline_mode(base_dir):
    path = os.path.join(base_dir, "fixtures", "ethernaut", "Reentrancy.sol")
    findings = run_slither(path, offline=True)
    assert len(findings) > 0
    assert any("reentrancy" in f.category.lower() or f.rule_id == "CG-001-REENTRANCY" for f in findings)


def test_run_slither_oversized_file_raises(tmp_path):
    huge_file = tmp_path / "Huge.sol"
    huge_file.write_text("contract Huge {}" + ("\n// padding" * 1000000))
    if huge_file.stat().st_size > 10 * 1024 * 1024:
        with pytest.raises(ValueError, match="exceeds maximum limit"):
            run_slither(str(huge_file))

