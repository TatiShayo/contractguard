"""
Unit and Property Tests for Standalone AST & Static Analysis Engine.
Hermes v6 Engineering Standard compliant.
"""

import pytest
from ast_analyzer import ASTAnalyzer, SolidityContract, SolidityFunction
from models import Finding, Severity, Confidence


@pytest.fixture
def analyzer():
    return ASTAnalyzer()


def test_reentrancy_vulnerable_pattern(analyzer):
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract VulnerableBank {
        mapping(address => uint256) public balances;

        function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount);
            (bool s, ) = msg.sender.call{value: amount}("");
            require(s);
            balances[msg.sender] -= amount;
        }
    }
    """
    findings = analyzer.analyze_source(code, "VulnerableBank.sol")
    assert any("reentrancy" in f.category.lower() or f.rule_id == "CG-001-REENTRANCY" for f in findings)
    reentrancy_f = next(f for f in findings if f.rule_id == "CG-001-REENTRANCY")
    assert reentrancy_f.severity == "high"
    assert reentrancy_f.cwe_id == "CWE-841"


def test_reentrancy_checks_effects_interactions_safe(analyzer):
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract SafeBank {
        mapping(address => uint256) public balances;

        function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount);
            balances[msg.sender] -= amount;
            (bool s, ) = msg.sender.call{value: amount}("");
            require(s);
        }
    }
    """
    findings = analyzer.analyze_source(code, "SafeBank.sol")
    reentrancy_f = [f for f in findings if f.rule_id == "CG-001-REENTRANCY"]
    assert len(reentrancy_f) == 0


def test_reentrancy_with_reentrancyguard_modifier(analyzer):
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract GuardedBank {
        mapping(address => uint256) public balances;

        function withdraw(uint256 amount) public nonReentrant {
            require(balances[msg.sender] >= amount);
            (bool s, ) = msg.sender.call{value: amount}("");
            require(s);
            balances[msg.sender] -= amount;
        }
    }
    """
    findings = analyzer.analyze_source(code, "GuardedBank.sol")
    reentrancy_f = [f for f in findings if f.rule_id == "CG-001-REENTRANCY"]
    assert len(reentrancy_f) == 0


def test_reentrancy_with_send_and_transfer(analyzer):
    code = """
    contract TransferBank {
        mapping(address => uint256) public balances;

        function withdrawTransfer(uint256 amount) public {
            payable(msg.sender).transfer(amount);
            balances[msg.sender] = 0;
        }
    }
    """
    findings = analyzer.analyze_source(code, "TransferBank.sol")
    assert any(f.rule_id == "CG-001-REENTRANCY" for f in findings)


def test_tx_origin_in_require(analyzer):
    code = """
    contract TxOriginAuth {
        address public owner;

        function setOwner(address _newOwner) public {
            require(tx.origin == owner, "Not authorized");
            owner = _newOwner;
        }
    }
    """
    findings = analyzer.analyze_source(code, "TxOriginAuth.sol")
    assert any(f.rule_id == "CG-002-TX-ORIGIN" for f in findings)
    tx_f = next(f for f in findings if f.rule_id == "CG-002-TX-ORIGIN")
    assert tx_f.severity == "medium"
    assert tx_f.cwe_id == "CWE-284"


def test_tx_origin_in_if_condition(analyzer):
    code = """
    contract Telephone {
        address public owner;

        function changeOwner(address _owner) public {
            if (tx.origin != msg.sender) {
                owner = _owner;
            }
        }
    }
    """
    findings = analyzer.analyze_source(code, "Telephone.sol")
    assert any(f.rule_id == "CG-002-TX-ORIGIN" for f in findings)


def test_tx_origin_safe_msg_sender(analyzer):
    code = """
    contract MsgSenderAuth {
        address public owner;

        function changeOwner(address _newOwner) public {
            require(msg.sender == owner, "Only owner");
            require(_newOwner != address(0), "Zero address");
            owner = _newOwner;
        }
    }
    """
    findings = analyzer.analyze_source(code, "MsgSenderAuth.sol")
    assert not any(f.rule_id == "CG-002-TX-ORIGIN" for f in findings)


def test_controlled_delegatecall_in_fallback(analyzer):
    code = """
    contract Delegation {
        address public owner;
        address public delegate;

        fallback() external {
            (bool result, ) = address(delegate).delegatecall(msg.data);
            if (result) {
                this;
            }
        }
    }
    """
    findings = analyzer.analyze_source(code, "Delegation.sol")
    assert any(f.rule_id == "CG-003-CONTROLLED-DELEGATECALL" for f in findings)
    del_f = next(f for f in findings if f.rule_id == "CG-003-CONTROLLED-DELEGATECALL")
    assert del_f.severity == "high"
    assert del_f.cwe_id == "CWE-829"


def test_controlled_delegatecall_guarded_by_onlyowner(analyzer):
    code = """
    contract SafeProxy {
        address public owner;
        address public implementation;

        modifier onlyOwner() {
            require(msg.sender == owner);
            _;
        }

        function upgradeAndCall(bytes calldata data) external onlyOwner {
            (bool s, ) = implementation.delegatecall(data);
            require(s);
        }
    }
    """
    findings = analyzer.analyze_source(code, "SafeProxy.sol")
    assert not any(f.rule_id == "CG-003-CONTROLLED-DELEGATECALL" for f in findings)


def test_unchecked_low_level_call(analyzer):
    code = """
    contract UncheckedCaller {
        function forward(address target) external {
            target.call("");
        }
    }
    """
    findings = analyzer.analyze_source(code, "UncheckedCaller.sol")
    assert any(f.rule_id == "CG-004-UNCHECKED-CALL" for f in findings)
    uncheck_f = next(f for f in findings if f.rule_id == "CG-004-UNCHECKED-CALL")
    assert uncheck_f.severity == "medium"


def test_checked_low_level_call_with_require(analyzer):
    code = """
    contract CheckedCaller {
        function forward(address target) external {
            (bool success, ) = target.call("");
            require(success, "Call failed");
        }
    }
    """
    findings = analyzer.analyze_source(code, "CheckedCaller.sol")
    assert not any(f.rule_id == "CG-004-UNCHECKED-CALL" for f in findings)


def test_missing_access_control_on_set_owner(analyzer):
    code = """
    contract UnprotectedOwner {
        address public owner;

        function setOwner(address _owner) external {
            owner = _owner;
        }
    }
    """
    findings = analyzer.analyze_source(code, "UnprotectedOwner.sol")
    assert any(f.rule_id == "CG-005-ACCESS-CONTROL" for f in findings)
    ac_f = next(f for f in findings if f.rule_id == "CG-005-ACCESS-CONTROL")
    assert ac_f.severity == "high"


def test_missing_access_control_on_pwn(analyzer):
    code = """
    contract Delegate {
        address public owner;

        function pwn() public {
            owner = msg.sender;
        }
    }
    """
    findings = analyzer.analyze_source(code, "Delegate.sol")
    assert any(f.rule_id == "CG-005-ACCESS-CONTROL" for f in findings)


def test_access_control_present_with_only_owner(analyzer):
    code = """
    contract ProtectedOwner {
        address public owner;

        modifier onlyOwner() {
            require(msg.sender == owner);
            _;
        }

        function setOwner(address _owner) external onlyOwner {
            owner = _owner;
        }
    }
    """
    findings = analyzer.analyze_source(code, "ProtectedOwner.sol")
    assert not any(f.rule_id == "CG-005-ACCESS-CONTROL" for f in findings)


def test_access_control_present_with_only_role(analyzer):
    code = """
    contract RoleProtected {
        address public owner;

        function setOwner(address _owner) external onlyRole(ADMIN_ROLE) {
            owner = _owner;
        }
    }
    """
    findings = analyzer.analyze_source(code, "RoleProtected.sol")
    assert not any(f.rule_id == "CG-005-ACCESS-CONTROL" for f in findings)


def test_arbitrary_call_truster_pattern(analyzer):
    code = """
    contract TrusterLenderPool {
        function flashLoan(
            uint256 amount,
            address borrower,
            address target,
            bytes calldata data
        ) external returns (bool) {
            target.functionCall(data);
            return true;
        }
    }
    """
    findings = analyzer.analyze_source(code, "TrusterLenderPool.sol")
    assert any(f.rule_id == "CG-006-ARBITRARY-CALL" for f in findings)
    arb_f = next(f for f in findings if f.rule_id == "CG-006-ARBITRARY-CALL")
    assert arb_f.severity == "high"


def test_arbitrary_call_safe_static_target(analyzer):
    code = """
    contract SafeCaller {
        address public immutable fixedTarget;

        constructor(address _target) {
            fixedTarget = _target;
        }

        function execute(bytes calldata data) external {
            (bool s, ) = fixedTarget.call(data);
            require(s);
        }
    }
    """
    findings = analyzer.analyze_source(code, "SafeCaller.sol")
    assert not any(f.rule_id == "CG-006-ARBITRARY-CALL" for f in findings)


def test_flashloan_deposit_reentrancy_side_entrance(analyzer):
    code = """
    contract SideEntranceLenderPool {
        mapping(address => uint256) private balances;

        function deposit() external payable {
            balances[msg.sender] += msg.value;
        }

        function withdraw() external {
            uint256 amount = balances[msg.sender];
            delete balances[msg.sender];
            payable(msg.sender).transfer(amount);
        }

        function flashLoan(uint256 amount) external {
            uint256 balanceBefore = address(this).balance;
            IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
            if (address(this).balance < balanceBefore) {
                revert();
            }
        }
    }
    """
    findings = analyzer.analyze_source(code, "SideEntranceLenderPool.sol")
    assert any(f.rule_id == "CG-007-FLASHLOAN-DEPOSIT-REENTRANCY" for f in findings)
    fl_f = next(f for f in findings if f.rule_id == "CG-007-FLASHLOAN-DEPOSIT-REENTRANCY")
    assert fl_f.severity == "high"


def test_flashloan_without_deposit_safe(analyzer):
    code = """
    contract CleanFlashLender {
        function flashLoan(uint256 amount) external {
            uint256 balanceBefore = address(this).balance;
            IFlash(msg.sender).execute{value: amount}();
            require(address(this).balance >= balanceBefore + fee);
        }
    }
    """
    findings = analyzer.analyze_source(code, "CleanFlashLender.sol")
    assert not any(f.rule_id == "CG-007-FLASHLOAN-DEPOSIT-REENTRANCY" for f in findings)


def test_flashloan_access_control_naive_receiver(analyzer):
    code = """
    contract NaiveReceiverLenderPool {
        uint256 private constant FIXED_FEE = 1 ether;

        function flashLoan(
            IERC3156FlashBorrower receiver,
            address token,
            uint256 amount,
            bytes calldata data
        ) external returns (bool) {
            payable(address(receiver)).transfer(amount);
            receiver.onFlashLoan(msg.sender, token, amount, FIXED_FEE, data);
            return true;
        }
    }
    """
    findings = analyzer.analyze_source(code, "NaiveReceiverLenderPool.sol")
    assert any(f.rule_id == "CG-008-FLASHLOAN-ACCESS-CONTROL" for f in findings)
    na_f = next(f for f in findings if f.rule_id == "CG-008-FLASHLOAN-ACCESS-CONTROL")
    assert na_f.severity == "high"


def test_flashloan_access_control_with_caller_check_safe(analyzer):
    code = """
    contract ProtectedFlashLender {
        uint256 private constant FIXED_FEE = 1 ether;

        function flashLoan(
            IERC3156FlashBorrower receiver,
            address token,
            uint256 amount,
            bytes calldata data
        ) external returns (bool) {
            require(msg.sender == address(receiver), "Caller must be receiver");
            payable(address(receiver)).transfer(amount);
            receiver.onFlashLoan(msg.sender, token, amount, FIXED_FEE, data);
            return true;
        }
    }
    """
    findings = analyzer.analyze_source(code, "ProtectedFlashLender.sol")
    assert not any(f.rule_id == "CG-008-FLASHLOAN-ACCESS-CONTROL" for f in findings)


def test_spot_price_oracle_manipulation(analyzer):
    code = """
    contract PoolConsumer {
        function getPrice(IUniswapV2Pair pair) public view returns (uint256) {
            (uint112 r0, uint112 r1, ) = pair.getReserves();
            return uint256(r0) / uint256(r1);
        }
    }
    """
    findings = analyzer.analyze_source(code, "PoolConsumer.sol")
    assert any(f.rule_id == "CG-009-PRICE-ORACLE-MANIPULATION" for f in findings)


def test_price_oracle_with_chainlink_safe(analyzer):
    code = """
    contract SafeOracleConsumer {
        function getPrice() public view returns (int256) {
            (, int256 price, , uint256 timeStamp, ) = priceFeed.latestRoundData();
            require(timeStamp > 0);
            return price;
        }
    }
    """
    findings = analyzer.analyze_source(code, "SafeOracleConsumer.sol")
    assert not any(f.rule_id == "CG-009-PRICE-ORACLE-MANIPULATION" for f in findings)


def test_selfdestruct_detector(analyzer):
    code = """
    contract Destructible {
        function kill(address payable recipient) external {
            selfdestruct(recipient);
        }
    }
    """
    findings = analyzer.analyze_source(code, "Destructible.sol")
    assert any(f.rule_id == "CG-010-SELFDESTRUCT" for f in findings)
    sd_f = next(f for f in findings if f.rule_id == "CG-010-SELFDESTRUCT")
    assert sd_f.severity == "critical" or sd_f.severity == "high"


def test_integer_overflow_unchecked_block(analyzer):
    code = """
    contract UncheckedMath {
        mapping(address => uint256) public balances;

        function deposit() external payable {
            unchecked {
                balances[msg.sender] += msg.value;
            }
        }
    }
    """
    findings = analyzer.analyze_source(code, "UncheckedMath.sol")
    assert any(f.rule_id == "CG-011-INTEGER-OVERFLOW" for f in findings)


def test_useless_statement_detector(analyzer):
    code = """
    contract DeadCodeContract {
        function dummy(uint256 _amount) public {
            _amount;
            this;
        }
    }
    """
    findings = analyzer.analyze_source(code, "DeadCodeContract.sol")
    assert any(f.rule_id == "CG-012-USELESS-STATEMENT" for f in findings)


def test_unprotected_initialize(analyzer):
    code = """
    contract MyProxyImpl {
        address public owner;

        function initialize(address _owner) external {
            owner = _owner;
        }
    }
    """
    findings = analyzer.analyze_source(code, "MyProxyImpl.sol")
    assert any(f.rule_id == "CG-013-UNPROTECTED-INITIALIZE" for f in findings)


def test_protected_initialize_with_initializer(analyzer):
    code = """
    contract ProtectedProxyImpl {
        address public owner;

        function initialize(address _owner) external initializer {
            owner = _owner;
        }
    }
    """
    findings = analyzer.analyze_source(code, "ProtectedProxyImpl.sol")
    assert not any(f.rule_id == "CG-013-UNPROTECTED-INITIALIZE" for f in findings)


def test_missing_zero_check(analyzer):
    code = """
    contract ZeroCheckContract {
        address public owner;

        function changeOwner(address _newOwner) public {
            require(msg.sender == owner);
            owner = _newOwner;
        }
    }
    """
    findings = analyzer.analyze_source(code, "ZeroCheckContract.sol")
    assert any(f.rule_id == "CG-014-MISSING-ZERO-CHECK" for f in findings)


def test_inline_suppression_disable_next_line(analyzer):
    code = """
    contract SuppressedBank {
        mapping(address => uint256) public balances;

        // contractguard:disable-next-line CG-001-REENTRANCY
        function withdraw(uint256 amount) public {
            (bool s, ) = msg.sender.call{value: amount}("");
            balances[msg.sender] -= amount;
        }
    }
    """
    findings = analyzer.analyze_source(code, "SuppressedBank.sol")
    assert not any(f.rule_id == "CG-001-REENTRANCY" for f in findings)


def test_inline_suppression_slither_disable(analyzer):
    code = """
    contract SuppressedSlitherBank {
        mapping(address => uint256) public balances;

        // slither-disable-next-line reentrancy-eth
        function withdraw(uint256 amount) public {
            (bool s, ) = msg.sender.call{value: amount}("");
            balances[msg.sender] -= amount;
        }
    }
    """
    findings = analyzer.analyze_source(code, "SuppressedSlitherBank.sol")
    assert not any(f.rule_id == "CG-001-REENTRANCY" for f in findings)


def test_ast_parser_resilience_malformed_solidity(analyzer):
    malformed_code = """
    contract Incomplete {
        function foo( {
            broken syntax (((
    """
    # Should not raise exception
    findings = analyzer.analyze_source(malformed_code, "Incomplete.sol")
    assert isinstance(findings, list)


def test_ast_parser_resilience_empty_string(analyzer):
    findings = analyzer.analyze_source("", "Empty.sol")
    assert findings == []


def test_ast_parser_resilience_comments_only(analyzer):
    comments_code = """
    // SPDX-License-Identifier: MIT
    /* Multi line
       comment without code */
    """
    findings = analyzer.analyze_source(comments_code, "Comments.sol")
    assert findings == []


def test_ast_parser_resilience_unicode_and_huge_source(analyzer):
    unicode_source = "contract UnicodeTest { string s = '\\u2705\\U0001f512'; }" + ("\n// padding" * 500)
    findings = analyzer.analyze_source(unicode_source, "UnicodeTest.sol")
    assert isinstance(findings, list)


def test_arbitrary_eth_transfer_detector(analyzer):
    code = """
    contract DrainablePool {
        function emergencyDrain(address payable to) external {
            to.transfer(address(this).balance);
        }
    }
    """
    findings = analyzer.analyze_source(code, "DrainablePool.sol")
    assert any(f.rule_id == "CG-015-ARBITRARY-SEND-ETH" for f in findings)
    f = next(f for f in findings if f.rule_id == "CG-015-ARBITRARY-SEND-ETH")
    assert f.severity == "high"
    assert f.cwe_id == "CWE-284"


def test_arbitrary_eth_transfer_safe_with_only_owner(analyzer):
    code = """
    contract SafeDrainablePool {
        address public owner;
        modifier onlyOwner() {
            require(msg.sender == owner);
            _;
        }
        function emergencyDrain(address payable to) external onlyOwner {
            to.transfer(address(this).balance);
        }
    }
    """
    findings = analyzer.analyze_source(code, "SafeDrainablePool.sol")
    assert not any(f.rule_id == "CG-015-ARBITRARY-SEND-ETH" for f in findings)


def test_uninitialized_local_storage_pointer_detector(analyzer):
    code = """
    contract StorageTest {
        struct UserRecord {
            address user;
            uint256 balance;
        }
        mapping(uint256 => UserRecord) public records;

        function getRecord(uint256 id) external {
            UserRecord storage record;
            record.user = msg.sender;
        }
    }
    """
    findings = analyzer.analyze_source(code, "StorageTest.sol")
    assert any(f.rule_id == "CG-016-UNINITIALIZED-STORAGE" for f in findings)
    f = next(f for f in findings if f.rule_id == "CG-016-UNINITIALIZED-STORAGE")
    assert f.severity == "high"
    assert f.cwe_id == "CWE-824"


def test_uninitialized_local_storage_pointer_safe_memory(analyzer):
    code = """
    contract StorageTestSafe {
        struct UserRecord {
            address user;
            uint256 balance;
        }
        mapping(uint256 => UserRecord) public records;

        function getRecord(uint256 id) external view returns (UserRecord memory) {
            UserRecord memory record = records[id];
            return record;
        }
    }
    """
    findings = analyzer.analyze_source(code, "StorageTestSafe.sol")
    assert not any(f.rule_id == "CG-016-UNINITIALIZED-STORAGE" for f in findings)


def test_floating_pragma_detector(analyzer):
    code = """
    pragma solidity ^0.8.20;
    contract PragmaTest {}
    """
    findings = analyzer.analyze_source(code, "PragmaTest.sol")
    assert any(f.rule_id == "CG-017-FLOATING-PRAGMA" for f in findings)
    f = next(f for f in findings if f.rule_id == "CG-017-FLOATING-PRAGMA")
    assert f.severity == "low"
    assert f.cwe_id == "CWE-1038"


def test_locked_pragma_safe(analyzer):
    code = """
    pragma solidity 0.8.24;
    contract LockedPragmaTest {}
    """
    findings = analyzer.analyze_source(code, "LockedPragmaTest.sol")
    assert not any(f.rule_id == "CG-017-FLOATING-PRAGMA" for f in findings)


def test_multiple_contracts_in_single_file(analyzer):
    code = """
    pragma solidity 0.8.24;

    contract ContractA {
        address public owner;
        function setOwner(address _owner) external {
            owner = _owner;
        }
    }

    contract ContractB {
        mapping(address => uint256) public balances;
        function withdraw(uint256 amount) external {
            (bool s, ) = msg.sender.call{value: amount}("");
            require(s);
            balances[msg.sender] -= amount;
        }
    }
    """
    findings = analyzer.analyze_source(code, "MultiContract.sol")
    assert any(f.contract_name == "ContractA" and f.rule_id == "CG-005-ACCESS-CONTROL" for f in findings)
    assert any(f.contract_name == "ContractB" and f.rule_id == "CG-001-REENTRANCY" for f in findings)


def test_library_and_interface_handling(analyzer):
    code = """
    pragma solidity 0.8.24;

    interface IERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
    }

    library SafeMathLib {
        function add(uint256 a, uint256 b) internal pure returns (uint256) {
            return a + b;
        }
    }
    """
    findings = analyzer.analyze_source(code, "LibInterface.sol")
    # Interfaces and pure libraries should not produce false positive vulnerabilities
    high_findings = [f for f in findings if f.severity in ("critical", "high")]
    assert len(high_findings) == 0


def test_inline_multi_rule_suppression(analyzer):
    code = """
    pragma solidity 0.8.24;

    contract MultiSuppressed {
        address public owner;

        // contractguard:disable-next-line CG-005-ACCESS-CONTROL, CG-014-MISSING-ZERO-CHECK
        function setOwner(address _owner) external {
            owner = _owner;
        }
    }
    """
    findings = analyzer.analyze_source(code, "MultiSuppressed.sol")
    assert not any(f.rule_id == "CG-005-ACCESS-CONTROL" for f in findings)
    assert not any(f.rule_id == "CG-014-MISSING-ZERO-CHECK" for f in findings)


def test_inline_disable_all_suppression(analyzer):
    code = """
    pragma solidity 0.8.24;

    contract DisableAll {
        address public owner;

        // contractguard:disable-next-line
        function setOwner(address _owner) external {
            owner = _owner;
        }
    }
    """
    findings = analyzer.analyze_source(code, "DisableAll.sol")
    assert not any(f.rule_id == "CG-005-ACCESS-CONTROL" for f in findings)

