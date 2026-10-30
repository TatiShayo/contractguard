"""
ContractGuard Comprehensive Test Suite (Hermes v6 Standards).
Contains high-coverage unit tests, edge-case tests, security invariant tests,
and property tests across all vulnerability detectors and engine components.
"""

import pytest
import os
import json
import tempfile
from ast_analyzer import ASTAnalyzer, _find_matching_brace, SolidityContract, SolidityFunction
from models import Finding, Severity, Confidence
from rules import RULES_REGISTRY, get_rule_by_id, get_rule_for_category, get_remediation_for_rule
from report_generator import (
    calculate_security_score,
    get_security_grade,
    sanitize_text,
    generate_report,
    generate_sarif_report,
    generate_json_report,
)
from cli import audit_contract

@pytest.fixture
def analyzer():
    return ASTAnalyzer()

def test_reentrancy_call_value_mutation(analyzer):
    code = """
    contract VulnerableCallValue {
        mapping(address => uint256) public userBalances;
        function withdraw(uint256 amount) external {
            require(userBalances[msg.sender] >= amount);
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            userBalances[msg.sender] -= amount;
        }
    }
    """
    findings = analyzer.analyze_source(code, "VulnerableCallValue.sol")
    assert any(f.rule_id == "CG-001-REENTRANCY" for f in findings)
    f = next(f for f in findings if f.rule_id == "CG-001-REENTRANCY")
    assert f.severity == "high"
    assert f.cwe_id == "CWE-841"

def test_reentrancy_array_push_mutation(analyzer):
    code = """
    contract VulnerablePush {
        address[] public rewardRecipients;
        function claimReward() external {
            (bool s, ) = msg.sender.call{value: 1 ether}("");
            require(s);
            rewardRecipients.push(msg.sender);
        }
    }
    """
    findings = analyzer.analyze_source(code, "VulnerablePush.sol")
    assert any(f.rule_id == "CG-001-REENTRANCY" for f in findings)

def test_reentrancy_delete_state_mutation(analyzer):
    code = """
    contract VulnerableDelete {
        mapping(address => uint256) public stakes;
        function unstake() external {
            uint256 amount = stakes[msg.sender];
            (bool s, ) = msg.sender.call{value: amount}("");
            require(s);
            delete stakes[msg.sender];
        }
    }
    """
    findings = analyzer.analyze_source(code, "VulnerableDelete.sol")
    assert any(f.rule_id == "CG-001-REENTRANCY" for f in findings)

def test_reentrancy_custom_lock_modifier_safe(analyzer):
    code = """
    contract SafeWithCustomLock {
        mapping(address => uint256) public balances;
        modifier mutex() {
            require(!locked, "Locked");
            locked = true;
            _;
            locked = false;
        }
        bool private locked;
        function withdraw(uint256 amount) external mutex {
            (bool s, ) = msg.sender.call{value: amount}("");
            require(s);
            balances[msg.sender] -= amount;
        }
    }
    """
    findings = analyzer.analyze_source(code, "SafeWithCustomLock.sol")
    assert not any(f.rule_id == "CG-001-REENTRANCY" for f in findings)

def test_reentrancy_cei_pattern_safe(analyzer):
    code = """
    contract SafeCEI {
        mapping(address => uint256) public balances;
        function withdraw(uint256 amount) external {
            require(balances[msg.sender] >= amount, "No balance");
            balances[msg.sender] -= amount;
            (bool s, ) = msg.sender.call{value: amount}("");
            require(s, "Transfer failed");
        }
    }
    """
    findings = analyzer.analyze_source(code, "SafeCEI.sol")
    assert not any(f.rule_id == "CG-001-REENTRANCY" for f in findings)

def test_tx_origin_in_assert(analyzer):
    code = """
    contract AssertTxOrigin {
        address public admin;
        function emergencyReset() external {
            assert(tx.origin == admin);
            admin = address(0);
        }
    }
    """
    findings = analyzer.analyze_source(code, "AssertTxOrigin.sol")
    assert any(f.rule_id == "CG-002-TX-ORIGIN" for f in findings)

def test_tx_origin_in_modifier(analyzer):
    code = """
    contract ModifierTxOrigin {
        address public owner;
        modifier onlyTxOwner() {
            require(tx.origin == owner, "Not owner");
            _;
        }
        function privilegedAction() external onlyTxOwner {
            // sensitive
        }
    }
    """
    findings = analyzer.analyze_source(code, "ModifierTxOrigin.sol")
    assert any(f.rule_id == "CG-002-TX-ORIGIN" for f in findings)

def test_tx_origin_safe_msg_sender_equality(analyzer):
    code = """
    contract SafeMsgSender {
        address public owner;
        function transferOwnership(address newOwner) external {
            require(msg.sender == owner, "Only owner");
            require(newOwner != address(0), "Zero address");
            owner = newOwner;
        }
    }
    """
    findings = analyzer.analyze_source(code, "SafeMsgSender.sol")
    assert not any(f.rule_id == "CG-002-TX-ORIGIN" for f in findings)

def test_controlled_delegatecall_public_function(analyzer):
    code = """
    contract DynamicDelegate {
        function executeCall(address target, bytes calldata data) external {
            (bool s, ) = target.delegatecall(data);
            require(s);
        }
    }
    """
    findings = analyzer.analyze_source(code, "DynamicDelegate.sol")
    assert any(f.rule_id == "CG-003-CONTROLLED-DELEGATECALL" for f in findings)
    f = next(f for f in findings if f.rule_id == "CG-003-CONTROLLED-DELEGATECALL")
    assert f.severity == "high"

def test_controlled_delegatecall_guarded_by_onlyadmin(analyzer):
    code = """
    contract GuardedDelegate {
        address public admin;
        modifier onlyAdmin() {
            require(msg.sender == admin);
            _;
        }
        function executeCall(address target, bytes calldata data) external onlyAdmin {
            (bool s, ) = target.delegatecall(data);
            require(s);
        }
    }
    """
    findings = analyzer.analyze_source(code, "GuardedDelegate.sol")
    assert not any(f.rule_id == "CG-003-CONTROLLED-DELEGATECALL" for f in findings)

def test_unchecked_send_detector(analyzer):
    code = """
    contract UncheckedSend {
        function payout(address payable recipient, uint256 amount) external {
            recipient.send(amount);
        }
    }
    """
    findings = analyzer.analyze_source(code, "UncheckedSend.sol")
    assert any(f.rule_id == "CG-004-UNCHECKED-CALL" for f in findings)

def test_unchecked_staticcall_detector(analyzer):
    code = """
    contract UncheckedStaticCall {
        function queryData(address oracle, bytes calldata data) external {
            oracle.staticcall(data);
        }
    }
    """
    findings = analyzer.analyze_source(code, "UncheckedStaticCall.sol")
    assert any(f.rule_id == "CG-004-UNCHECKED-CALL" for f in findings)

def test_unchecked_erc20_transfer_detector(analyzer):
    code = """
    contract UncheckedERC20 {
        function distribute(IERC20 token, address to, uint256 amount) external {
            token.transfer(to, amount);
        }
    }
    """
    findings = analyzer.analyze_source(code, "UncheckedERC20.sol")
    assert any(f.rule_id == "CG-021-UNCHECKED-ERC20-TRANSFER" for f in findings)

def test_checked_erc20_safe_transfer_safe(analyzer):
    code = """
    contract SafeERC20Transfer {
        using SafeERC20 for IERC20;
        function distribute(IERC20 token, address to, uint256 amount) external {
            token.safeTransfer(to, amount);
        }
    }
    """
    findings = analyzer.analyze_source(code, "SafeERC20Transfer.sol")
    assert not any(f.rule_id == "CG-021-UNCHECKED-ERC20-TRANSFER" for f in findings)

def test_missing_access_control_emergency_withdraw(analyzer):
    code = """
    contract UnprotectedEmergency {
        function emergencyWithdraw() external {
            payable(msg.sender).transfer(address(this).balance);
        }
    }
    """
    findings = analyzer.analyze_source(code, "UnprotectedEmergency.sol")
    assert any(f.rule_id == "CG-005-ACCESS-CONTROL" for f in findings)

def test_missing_access_control_set_fee(analyzer):
    code = """
    contract UnprotectedFee {
        uint256 public fee;
        function setFee(uint256 _fee) external {
            fee = _fee;
        }
    }
    """
    findings = analyzer.analyze_source(code, "UnprotectedFee.sol")
    assert any(f.rule_id == "CG-005-ACCESS-CONTROL" for f in findings)

def test_unprotected_mint_detector(analyzer):
    code = """
    contract FreeMintToken {
        mapping(address => uint256) public balanceOf;
        function mint(address to, uint256 amount) external {
            balanceOf[to] += amount;
            _mint(to, amount);
        }
    }
    """
    findings = analyzer.analyze_source(code, "FreeMintToken.sol")
    assert any(f.rule_id == "CG-022-UNPROTECTED-MINT" for f in findings)
    f = next(f for f in findings if f.rule_id == "CG-022-UNPROTECTED-MINT")
    assert f.severity == "critical"

def test_protected_mint_with_only_owner_safe(analyzer):
    code = """
    contract ProtectedMintToken {
        address public owner;
        modifier onlyOwner() {
            require(msg.sender == owner);
            _;
        }
        function mint(address to, uint256 amount) external onlyOwner {
            _mint(to, amount);
        }
    }
    """
    findings = analyzer.analyze_source(code, "ProtectedMintToken.sol")
    assert not any(f.rule_id == "CG-022-UNPROTECTED-MINT" for f in findings)

def test_signature_replay_without_nonce_detector(analyzer):
    code = """
    contract VulnerableSignatureVerifier {
        function verifyAndExecute(bytes32 messageHash, uint8 v, bytes32 r, bytes32 s) external {
            address signer = ecrecover(messageHash, v, r, s);
            require(signer != address(0), "Invalid signature");
            // executes without nonce tracking
        }
    }
    """
    findings = analyzer.analyze_source(code, "VulnerableSignatureVerifier.sol")
    assert any(f.rule_id == "CG-018-SIGNATURE-REPLAY" for f in findings)
    f = next(f for f in findings if f.rule_id == "CG-018-SIGNATURE-REPLAY")
    assert f.severity == "high"
    assert f.cwe_id == "CWE-347"

def test_signature_replay_with_nonce_and_domain_safe(analyzer):
    code = """
    contract SafePermitVerifier {
        bytes32 public DOMAIN_SEPARATOR;
        mapping(address => uint256) public nonces;
        function executeWithPermit(address owner, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
            require(nonces[owner]++ == nonce, "Invalid nonce");
            bytes32 hash = keccak256(abi.encode(DOMAIN_SEPARATOR, owner, amount, nonce));
            address signer = ecrecover(hash, v, r, s);
            require(signer == owner, "Invalid signer");
        }
    }
    """
    findings = analyzer.analyze_source(code, "SafePermitVerifier.sol")
    assert not any(f.rule_id == "CG-018-SIGNATURE-REPLAY" for f in findings)

def test_insecure_randomness_timestamp_modulo(analyzer):
    code = """
    contract Lottery {
        function pickWinner(uint256 maxPlayers) external view returns (uint256) {
            uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % maxPlayers;
            return random;
        }
    }
    """
    findings = analyzer.analyze_source(code, "Lottery.sol")
    assert any(f.rule_id == "CG-019-WEAK-PRNG" for f in findings)
    f = next(f for f in findings if f.rule_id == "CG-019-WEAK-PRNG")
    assert f.severity == "high"
    assert f.cwe_id == "CWE-330"

def test_insecure_randomness_blockhash_modulo(analyzer):
    code = """
    contract CoinFlip {
        function flip() external view returns (bool) {
            return (uint256(blockhash(block.number - 1)) % 2) == 0;
        }
    }
    """
    findings = analyzer.analyze_source(code, "CoinFlip.sol")
    assert any(f.rule_id == "CG-019-WEAK-PRNG" for f in findings)

def test_read_only_reentrancy_curve_virtual_price(analyzer):
    code = """
    contract LendingProtocol {
        ICurvePool public curvePool;
        function getCollateralValue(address user) external view returns (uint256) {
            uint256 vPrice = curvePool.get_virtual_price();
            return vPrice * balances[user];
        }
    }
    """
    findings = analyzer.analyze_source(code, "LendingProtocol.sol")
    assert any(f.rule_id == "CG-020-READ-ONLY-REENTRANCY" for f in findings)

def test_read_only_reentrancy_with_guard_safe(analyzer):
    code = """
    contract SafeLendingProtocol {
        ICurvePool public curvePool;
        function getCollateralValue(address user) external view nonReentrantView returns (uint256) {
            uint256 vPrice = curvePool.get_virtual_price();
            return vPrice * balances[user];
        }
    }
    """
    findings = analyzer.analyze_source(code, "SafeLendingProtocol.sol")
    assert not any(f.rule_id == "CG-020-READ-ONLY-REENTRANCY" for f in findings)

def test_selfdestruct_unprotected_critical(analyzer):
    code = """
    contract UnprotectedKill {
        function kill(address payable recipient) external {
            selfdestruct(recipient);
        }
    }
    """
    findings = analyzer.analyze_source(code, "UnprotectedKill.sol")
    assert any(f.rule_id == "CG-010-SELFDESTRUCT" for f in findings)
    f = next(f for f in findings if f.rule_id == "CG-010-SELFDESTRUCT")
    assert f.severity == "critical"

def test_selfdestruct_protected_only_owner_medium(analyzer):
    code = """
    contract ProtectedKill {
        address public owner;
        modifier onlyOwner() {
            require(msg.sender == owner);
            _;
        }
        function kill(address payable recipient) external onlyOwner {
            selfdestruct(recipient);
        }
    }
    """
    findings = analyzer.analyze_source(code, "ProtectedKill.sol")
    assert any(f.rule_id == "CG-010-SELFDESTRUCT" for f in findings)
    f = next(f for f in findings if f.rule_id == "CG-010-SELFDESTRUCT")
    assert f.severity == "medium"

def test_find_matching_brace_with_braces_in_strings():
    source = 'contract Test { string s = "{}{"; function foo() public {} }'
    open_brace = source.find('{')
    close_brace = _find_matching_brace(source, open_brace)
    assert close_brace == len(source) - 1

def test_find_matching_brace_with_single_line_comment():
    source = 'contract Test {\n // unmatched { }\n function bar() public {} }'
    open_brace = source.find('{')
    close_brace = _find_matching_brace(source, open_brace)
    assert close_brace == len(source) - 1

def test_find_matching_brace_with_multiline_comment():
    source = 'contract Test {\n /* unmatched { { } */\n function bar() public {} }'
    open_brace = source.find('{')
    close_brace = _find_matching_brace(source, open_brace)
    assert close_brace == len(source) - 1

def test_find_matching_brace_invalid_index():
    source = "contract Empty {}"
    assert _find_matching_brace(source, -1) == len(source)
    assert _find_matching_brace(source, 100) == len(source)

def test_rules_registry_all_rules_valid():
    for rule_id, rule in RULES_REGISTRY.items():
        assert rule_id.startswith("CG-")
        assert "name" in rule
        assert "default_severity" in rule
        assert "cwe" in rule
        assert "impact" in rule
        assert "remediation" in rule
        assert "remediation_code" in rule
        assert len(rule["remediation"].strip()) > 0

def test_get_rule_by_id_normalized_and_alias():
    assert get_rule_by_id("cg_001_reentrancy") is not None
    assert get_rule_by_id("CG-001-REENTRANCY")["name"] == "Reentrancy Vulnerability"
    assert get_rule_by_id("CG-018-SIGNATURE-REPLAY") is not None
    assert get_rule_by_id("CG-019-WEAK-PRNG") is not None
    assert get_rule_by_id("CG-020-READ-ONLY-REENTRANCY") is not None
    assert get_rule_by_id("CG-021-UNCHECKED-ERC20-TRANSFER") is not None
    assert get_rule_by_id("CG-022-UNPROTECTED-MINT") is not None
    assert get_rule_by_id("") is None
    assert get_rule_by_id(None) is None

def test_get_rule_for_category_fuzzy():
    rule = get_rule_for_category("reentrancy-eth")
    assert rule is not None
    assert rule["rule_id"] == "CG-001-REENTRANCY"

    rule_mint = get_rule_for_category("unprotected-mint")
    assert rule_mint is not None
    assert rule_mint["rule_id"] == "CG-022-UNPROTECTED-MINT"

def test_get_remediation_fallback_for_unknown():
    remed = get_remediation_for_rule("non_existent_rule_id_xyz")
    assert "Follow standard smart contract security patterns" in remed

def test_score_calculation_boundary_and_monotonicity():
    # 0 findings = 100
    score0, _ = calculate_security_score([])
    assert score0 == 100

    # 1 Low = 97
    f_low = Finding(severity="low", category="Dead code", function_or_line="foo", description="desc")
    score1, grade1 = calculate_security_score([f_low])
    assert score1 == 97
    assert "A+" in grade1

    # 1 Medium = 92
    f_med = Finding(severity="medium", category="tx.origin", function_or_line="foo", description="desc")
    score2, grade2 = calculate_security_score([f_med])
    assert score2 == 92
    assert "A" in grade2

    # 1 High = 85
    f_high = Finding(severity="high", category="Reentrancy", function_or_line="foo", description="desc")
    score3, grade3 = calculate_security_score([f_high])
    assert score3 == 85
    assert "B" in grade3

    # 1 Critical = 75
    f_crit = Finding(severity="critical", category="Selfdestruct", function_or_line="foo", description="desc")
    score4, grade4 = calculate_security_score([f_crit])
    assert score4 == 75
    assert "C" in grade4

    # 4 Criticals = 0 (clamped to 0)
    score5, grade5 = calculate_security_score([f_crit, f_crit, f_crit, f_crit])
    assert score5 == 0
    assert "F" in grade5

def test_parse_line_numbers_variations():
    assert Finding._parse_line_numbers("L15-L23") == (15, 23)
    assert Finding._parse_line_numbers("L42") == (42, 42)
    assert Finding._parse_line_numbers("15..23") == (15, 23)
    assert Finding._parse_line_numbers("withdraw (line: 88)") == (88, 88)
    assert Finding._parse_line_numbers("fallback (lines 10 to 20)") == (10, 20)
    assert Finding._parse_line_numbers("lines #5-#10") == (5, 10)
    assert Finding._parse_line_numbers("") == (None, None)
    assert Finding._parse_line_numbers(None) == (None, None)

def test_json_report_structure_and_sanitization():
    f = Finding(
        severity="high",
        category="Reentrancy\x00Exploit",
        function_or_line="withdraw\x07",
        description="Vulnerable to \x1breentrancy callback.",
        contract_name="Bank\x00.sol"
    )
    json_str = generate_json_report([f])
    data = json.loads(json_str)
    assert data["total_findings"] == 1
    assert data["security_score"] == 85
    assert "\x00" not in data["findings"][0]["category"]
    assert "\x07" not in data["findings"][0]["function_or_line"]
    assert "\x1b" not in data["findings"][0]["description"]

def test_sarif_report_with_multiple_rules_and_levels():
    findings = [
        Finding(severity="critical", category="Selfdestruct", function_or_line="kill (line 10)", description="Crit"),
        Finding(severity="high", category="Reentrancy", function_or_line="withdraw (lines 20-30)", description="High"),
        Finding(severity="medium", category="tx.origin", function_or_line="auth (line 40)", description="Med"),
        Finding(severity="low", category="Dead code", function_or_line="Line 50", description="Low"),
        Finding(severity="informational", category="Info", function_or_line="Line 1", description="Info"),
    ]
    sarif_str = generate_sarif_report(findings, tool_version="2.0.0")
    sarif = json.loads(sarif_str)

    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == 5

    levels = [r["level"] for r in results]
    assert "error" in levels
    assert "warning" in levels
    assert "note" in levels
    assert "none" in levels

def test_audit_contract_with_all_detectors_on_vulnerable_vault():
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract VulnerableVault {
        address public owner;
        mapping(address => uint256) public balances;

        function setOwner(address newOwner) external {
            owner = newOwner;
        }

        function withdraw(uint256 amount) external {
            (bool s, ) = msg.sender.call{value: amount}("");
            require(s);
            balances[msg.sender] -= amount;
        }

        function lotteryPick() external view returns (uint256) {
            return uint256(keccak256(abi.encodePacked(block.timestamp))) % 10;
        }
    }
    """
    with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        findings = audit_contract(tmp_path, offline=True)
        rule_ids = {f.rule_id for f in findings}
        assert "CG-001-REENTRANCY" in rule_ids
        assert "CG-005-ACCESS-CONTROL" in rule_ids
        assert "CG-019-WEAK-PRNG" in rule_ids
        assert "CG-017-FLOATING-PRAGMA" in rule_ids
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
