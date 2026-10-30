"""
Unit Tests for LLM Economic Logic Reviewer and Heuristic Engine.
Hermes v6 Engineering Standard compliant.
"""

import pytest
import json
from economic_logic_judge import (
    review_economic_logic,
    _review_economic_logic_fallback,
    _parse_llm_json,
    LLMFinding
)
from models import Finding, Severity, Confidence

def test_naive_receiver_fallback_detection():
    source = """
    contract NaiveReceiverLenderPool {
        function flashLoan(IERC3156FlashBorrower receiver, address token, uint256 amount, bytes calldata data) external {
            receiver.onFlashLoan(msg.sender, ETH, amount, FIXED_FEE, data);
        }
    }
    """
    findings = _review_economic_logic_fallback(source, [])
    assert len(findings) > 0
    f = findings[0]
    assert "access control" in f.category.lower() or "flash loan" in f.category.lower()
    assert f.function_or_line == "flashLoan"
    assert f.severity == "high"

def test_truster_fallback_detection():
    source = """
    contract TrusterLenderPool {
        function flashLoan(uint256 amount, address borrower, address target, bytes calldata data) external {
            target.functionCall(data);
        }
    }
    """
    findings = _review_economic_logic_fallback(source, [])
    assert len(findings) > 0
    f = findings[0]
    assert "arbitrary" in f.category.lower() or "external call" in f.category.lower()
    assert f.severity == "high"

def test_side_entrance_fallback_detection():
    source = """
    contract SideEntranceLenderPool {
        function flashLoan(uint256 amount) external {
            IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
        }
    }
    """
    findings = _review_economic_logic_fallback(source, [])
    assert len(findings) > 0
    f = findings[0]
    assert "reentrancy" in f.category.lower() or "deposit" in f.category.lower()
    assert f.severity == "high"

def test_generic_oracle_trust_fallback():
    source = """
    contract LendingMarket {
        IPriceFeed public priceFeed;
        function getBorrowLimit() public view returns (uint256) {
            return priceFeed.getLatestPrice();
        }
    }
    """
    findings = _review_economic_logic_fallback(source, [])
    assert any("oracle" in f.category.lower() for f in findings)

def test_generic_flash_loan_deposit_reentrancy_fallback():
    source = """
    contract CustomPool {
        function deposit() external payable {}
        function flashLoan(uint256 amount) external {
            target.call("");
            require(address(this).balance >= balance);
        }
    }
    """
    findings = _review_economic_logic_fallback(source, [])
    assert any("flash loan" in f.category.lower() or "reentrancy" in f.category.lower() for f in findings)

def test_generic_flash_loan_callback_fallback():
    source = """
    contract SimpleLender {
        function flashLoan(uint256 amount) external {
            target.call("");
        }
    }
    """
    findings = _review_economic_logic_fallback(source, [])
    assert any("flash loan" in f.category.lower() for f in findings)

def test_llm_json_parser_clean_array():
    raw_json = json.dumps([
        {
            "severity": "high",
            "category": "Oracle Price Manipulation",
            "function_or_line": "getCollateralRatio",
            "description": "Spot reserves used without TWAP.",
            "confidence": "High"
        }
    ])
    findings = _parse_llm_json(raw_json)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].category == "Oracle Price Manipulation"
    assert findings[0].confidence == "High"

def test_llm_json_parser_markdown_fences():
    raw_json = """
    ```json
    [
      {
        "severity": "critical",
        "category": "Flash Loan Drain",
        "function_or_line": "flashLoan (lines 10-20)",
        "description": "Arbitrary callback enables token approval drain.",
        "confidence": "High"
      }
    ]
    ```
    """
    findings = _parse_llm_json(raw_json)
    assert len(findings) == 1
    assert findings[0].severity == "critical"

def test_llm_json_parser_dict_wrapped_list():
    raw_json = json.dumps({
        "findings": [
            {
                "severity": "medium",
                "category": "Sandwich Attack Exposure",
                "function_or_line": "swapExactTokens",
                "description": "Missing minimum return parameter.",
                "confidence": "Medium"
            }
        ]
    })
    findings = _parse_llm_json(raw_json)
    assert len(findings) == 1
    assert findings[0].category == "Sandwich Attack Exposure"

def test_llm_json_parser_single_dict():
    raw_json = json.dumps({
        "severity": "low",
        "category": "Informational Logging",
        "function_or_line": "emitLog",
        "description": "Missing indexed parameters.",
        "confidence": "Low"
    })
    findings = _parse_llm_json(raw_json)
    assert len(findings) == 1
    assert findings[0].severity == "low"

def test_llm_json_parser_trailing_commas():
    raw_json = """
    [
      {
        "severity": "high",
        "category": "Reentrancy Risk",
        "function_or_line": "withdraw",
        "description": "State change after call.",
        "confidence": "High",
      },
    ]
    """
    findings = _parse_llm_json(raw_json)
    assert len(findings) == 1
    assert findings[0].category == "Reentrancy Risk"

def test_review_economic_logic_empty_source():
    findings = review_economic_logic("", [])
    assert findings == []

def test_review_economic_logic_large_source_truncation():
    large_source = "contract BigContract {\n" + ("// line comment\n" * 15000) + "}"
    assert len(large_source) > 100000
    # Should not raise
    findings = review_economic_logic(large_source, [])
    assert isinstance(findings, list)

def test_review_economic_logic_with_existing_findings():
    existing = [
        Finding(
            severity="high",
            category="Reentrancy",
            function_or_line="withdraw",
            description="External call before state update."
        )
    ]
    source = "contract TestContract { function flashLoan() external { target.call(''); } }"
    findings = review_economic_logic(source, existing)
    assert isinstance(findings, list)

def test_llm_finding_attributes():
    f = LLMFinding(
        severity="critical",
        category="Deposit-based Flash Loan Reentrancy",
        function_or_line="flashLoan (lines 20-30)",
        description="Borrower can deposit funds back.",
        confidence="High"
    )
    assert f.severity == "critical"
    assert f.source_tool == "llm_judge"
    assert f.confidence == "High"
    assert f.cwe_id == "CWE-841"
    assert f.line_start == 20
    assert f.line_end == 30

    d = f.to_dict()
    assert d["severity"] == "critical"
    assert d["source_tool"] == "llm_judge"
    assert d["confidence"] == "High"

def test_llm_json_parser_invalid_json_raises():
    with pytest.raises(Exception):
        _parse_llm_json("This is pure garbage text without JSON")

def test_llm_json_parser_nested_findings_key():
    raw = json.dumps({
        "result": {
            "vulnerabilities": [
                {
                    "severity": "high",
                    "category": "Price Manipulation",
                    "function_or_line": "swap",
                    "description": "Spot reserves vulnerable."
                }
            ]
        }
    })
    # If wrapped in nested dict
    findings = _parse_llm_json(raw)
    assert len(findings) == 1
    assert findings[0].category == "Price Manipulation"

def test_llm_finding_with_custom_remediation():
    f = LLMFinding(
        severity="medium",
        category="Custom Category",
        function_or_line="foo",
        description="Custom desc",
        remediation="Custom remediation instructions."
    )
    assert f.remediation == "Custom remediation instructions."
    assert f.severity_enum == Severity.MEDIUM
