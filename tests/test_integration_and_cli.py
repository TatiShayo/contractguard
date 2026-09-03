"""
Integration Tests and CLI Execution Validation for ContractGuard.
Hermes v6 Engineering Standard compliant.
"""

import pytest
import os
import tempfile
from cli import audit_contract
from models import Finding, Severity, Confidence


@pytest.fixture
def base_dir():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_audit_contract_on_reentrancy(base_dir):
    path = os.path.join(base_dir, "fixtures", "ethernaut", "Reentrancy.sol")
    findings = audit_contract(path, offline=True)
    assert len(findings) > 0
    assert any("reentrancy" in f.category.lower() or f.rule_id == "CG-001-REENTRANCY" for f in findings)


def test_audit_contract_on_telephone(base_dir):
    path = os.path.join(base_dir, "fixtures", "ethernaut", "Telephone.sol")
    findings = audit_contract(path, offline=True)
    assert len(findings) > 0
    assert any("tx.origin" in f.category.lower() or "origin" in f.category.lower() or f.rule_id == "CG-002-TX-ORIGIN" for f in findings)


def test_audit_contract_on_delegation(base_dir):
    path = os.path.join(base_dir, "fixtures", "ethernaut", "Delegation.sol")
    findings = audit_contract(path, offline=True)
    assert len(findings) > 0
    assert any("delegatecall" in f.category.lower() or f.rule_id == "CG-003-CONTROLLED-DELEGATECALL" for f in findings)


def test_audit_contract_on_clean_control(base_dir):
    path = os.path.join(base_dir, "fixtures", "ethernaut", "Clean.sol")
    findings = audit_contract(path, offline=True)
    high_or_crit = [f for f in findings if f.severity in ("critical", "high", "medium")]
    assert len(high_or_crit) == 0


def test_audit_contract_on_naive_receiver(base_dir):
    path = os.path.join(base_dir, "fixtures", "dvd", "NaiveReceiverLenderPool.sol")
    findings = audit_contract(path, offline=True)
    assert len(findings) > 0
    assert any("access control" in f.category.lower() or "flash loan" in f.category.lower() or f.rule_id == "CG-008-FLASHLOAN-ACCESS-CONTROL" for f in findings)


def test_audit_contract_on_truster(base_dir):
    path = os.path.join(base_dir, "fixtures", "dvd", "TrusterLenderPool.sol")
    findings = audit_contract(path, offline=True)
    assert len(findings) > 0
    assert any("arbitrary" in f.category.lower() or "external call" in f.category.lower() or f.rule_id == "CG-006-ARBITRARY-CALL" for f in findings)


def test_audit_contract_on_side_entrance(base_dir):
    path = os.path.join(base_dir, "fixtures", "dvd", "SideEntranceLenderPool.sol")
    findings = audit_contract(path, offline=True)
    assert len(findings) > 0
    assert any("reentrancy" in f.category.lower() or "deposit" in f.category.lower() or f.rule_id == "CG-007-FLASHLOAN-DEPOSIT-REENTRANCY" for f in findings)


def test_cli_min_severity_filter(base_dir):
    path = os.path.join(base_dir, "fixtures", "ethernaut", "Reentrancy.sol")
    all_findings = audit_contract(path, offline=True, min_severity=Severity.INFORMATIONAL)
    critical_only = audit_contract(path, offline=True, min_severity=Severity.CRITICAL)
    assert len(critical_only) <= len(all_findings)


def test_model_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.LOW > Severity.INFORMATIONAL
    assert Severity.HIGH >= Severity.HIGH
    assert Severity.LOW <= Severity.MEDIUM


def test_model_finding_equality_and_hashing():
    f1 = Finding(severity="high", category="Reentrancy", function_or_line="withdraw", description="Desc")
    f2 = Finding(severity="high", category="Reentrancy", function_or_line="withdraw", description="Desc")
    assert f1 == f2
    assert hash(f1) == hash(f2)
    s = {f1, f2}
    assert len(s) == 1


def test_audit_contract_nonexistent_file_raises():
    with pytest.raises(FileNotFoundError):
        audit_contract("/nonexistent/file/Fake.sol", offline=True)


def test_cli_report_generation_in_temp_dir(base_dir):
    import sys
    from unittest.mock import patch
    from cli import main

    path = os.path.join(base_dir, "fixtures", "ethernaut", "Telephone.sol")
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_args = ["contractguard", path, "--format", "all", "-o", tmp_dir, "--offline"]
        with patch.object(sys, "argv", test_args):
            try:
                main()
            except SystemExit as e:
                # sys.exit(0) or sys.exit(1) depending on finding severities
                assert e.code in (0, 1)

        assert os.path.exists(os.path.join(tmp_dir, "UNIFIED_REPORT.md"))
        assert os.path.exists(os.path.join(tmp_dir, "REPORT.sarif"))
        assert os.path.exists(os.path.join(tmp_dir, "FINDINGS.json"))


def test_cli_scan_directory_in_temp_dir(base_dir):
    import sys
    from unittest.mock import patch
    from cli import main

    dir_path = os.path.join(base_dir, "fixtures", "ethernaut")
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_args = ["contractguard", dir_path, "--format", "json", "-o", tmp_dir, "--offline"]
        with patch.object(sys, "argv", test_args):
            try:
                main()
            except SystemExit as e:
                assert e.code in (0, 1)

        assert os.path.exists(os.path.join(tmp_dir, "FINDINGS.json"))


def test_cli_no_contracts_found_graceful_exit():
    import sys
    from unittest.mock import patch
    from cli import main

    with tempfile.TemporaryDirectory() as empty_dir:
        test_args = ["contractguard", empty_dir, "--offline"]
        with patch.object(sys, "argv", test_args):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

