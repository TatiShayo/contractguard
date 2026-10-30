"""
ContractGuard Vulnerability Rules Registry.
Contains rule definitions, CWE mappings, default severities, and remediation advice.
"""

from typing import Dict, Any, Optional
from models import Severity

RULES_REGISTRY: Dict[str, Dict[str, Any]] = {
    "CG-001-REENTRANCY": {
        "rule_id": "CG-001-REENTRANCY",
        "name": "Reentrancy Vulnerability",
        "slither_alias": ["reentrancy-eth", "reentrancy-no-eth", "reentrancy-benign", "reentrancy-events"],
        "mythril_alias": ["State access after external call", "Reentrancy"],
        "default_severity": Severity.HIGH,
        "cwe": "CWE-841",
        "description": "State variable modified after external call (e.g. call.value, send, transfer), allowing reentrant control flow to hijack contract state.",
        "impact": "Malicious contracts can reenter the vulnerable function recursively before internal state is updated, draining ether or token balances.",
        "remediation": (
            "1. Apply the Checks-Effects-Interactions (CEI) pattern: perform all internal state updates before making external calls.\n"
            "2. Use OpenZeppelin's `ReentrancyGuard` and apply the `nonReentrant` modifier to functions making external transfers."
        ),
        "remediation_code": """
// Fix: Apply Checks-Effects-Interactions & ReentrancyGuard
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    balances[msg.sender] -= amount;
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
"""
    },
    "CG-002-TX-ORIGIN": {
        "rule_id": "CG-002-TX-ORIGIN",
        "name": "tx.origin Authentication Bypass",
        "slither_alias": ["tx-origin"],
        "mythril_alias": ["Use of tx.origin", "Tx origin authorization"],
        "default_severity": Severity.MEDIUM,
        "cwe": "CWE-284",
        "description": "Authentication or authorization logic relies on `tx.origin` instead of `msg.sender`.",
        "impact": "If an authorized user executes a transaction on a phishing or malicious smart contract, the contract can make calls back into the vulnerable contract and impersonate the user.",
        "remediation": (
            "Replace all authorization checks using `tx.origin` with `msg.sender`."
        ),
        "remediation_code": """
// Fix: Use msg.sender for authorization
function changeOwner(address newOwner) external {
    require(msg.sender == owner, "Only owner authorized");
    require(newOwner != address(0), "Invalid new owner");
    owner = newOwner;
}
"""
    },
    "CG-003-CONTROLLED-DELEGATECALL": {
        "rule_id": "CG-003-CONTROLLED-DELEGATECALL",
        "name": "Controlled / Arbitrary Delegatecall",
        "slither_alias": ["controlled-delegatecall", "delegatecall-loop"],
        "mythril_alias": ["Delegatecall to user-supplied address", "Controlled delegatecall"],
        "default_severity": Severity.HIGH,
        "cwe": "CWE-829",
        "description": "The contract executes `delegatecall` to a user-supplied target address or with caller-controlled calldata without strict access control.",
        "impact": "An attacker can point `delegatecall` to a malicious contract and execute arbitrary bytecode in the caller's context, overwriting storage slots or taking total ownership.",
        "remediation": (
            "1. Avoid `delegatecall` to dynamic or user-supplied addresses.\n"
            "2. Hardcode trusted implementation contracts or restrict delegatecalls to verified administrative proxy registries with strict access controls."
        ),
        "remediation_code": """
// Fix: Restrict delegatecall to an immutable or admin-verified implementation
address public immutable implementation;

fallback() external payable {
    address impl = implementation;
    require(impl != address(0), "Implementation not set");
    assembly {
        calldatacopy(0, 0, calldatasize())
        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
        returndatacopy(0, 0, returndatasize())
        switch result
        case 0 { revert(0, returndatasize()) }
        default { return(0, returndatasize()) }
    }
}
"""
    },
    "CG-004-UNCHECKED-CALL": {
        "rule_id": "CG-004-UNCHECKED-CALL",
        "name": "Unchecked Low-Level Call Return Value",
        "slither_alias": ["unchecked-lowlevel", "unchecked-send", "unchecked-transfer"],
        "mythril_alias": ["Unchecked return value", "Unchecked CALL"],
        "default_severity": Severity.MEDIUM,
        "cwe": "CWE-252",
        "description": "Return value of low-level `.call()`, `.send()`, or `.delegatecall()` is ignored or not verified with a require/revert.",
        "impact": "If the recipient contract reverts or runs out of gas, execution continues silently, leaving accounting state out of sync.",
        "remediation": (
            "Always check the boolean return value of low-level calls and revert on failure, or use OpenZeppelin `Address.sendValue` / `SafeERC20`."
        ),
        "remediation_code": """
// Fix: Verify return status and revert on failure
(bool success, bytes memory returndata) = recipient.call{value: amount}("");
if (!success) {
    revert("Transfer failed");
}
"""
    },
    "CG-005-ACCESS-CONTROL": {
        "rule_id": "CG-005-ACCESS-CONTROL",
        "name": "Missing Access Control on Sensitive Function",
        "slither_alias": ["unprotected-upgrade", "suicidal", "missing-access-control"],
        "mythril_alias": ["Missing access control", "Public sensitive function"],
        "default_severity": Severity.HIGH,
        "cwe": "CWE-284",
        "description": "Sensitive administrative or state-altering function is publicly callable without caller authentication or role restrictions.",
        "impact": "Any external caller can trigger privileged operations, change critical addresses, mint tokens, or drain protocol funds.",
        "remediation": (
            "Apply `onlyOwner` or OpenZeppelin `AccessControl` (`onlyRole(...)`) modifiers to all sensitive functions."
        ),
        "remediation_code": """
// Fix: Add onlyOwner modifier
function setFee(uint256 newFee) external onlyOwner {
    fee = newFee;
    emit FeeUpdated(newFee);
}
"""
    },
    "CG-006-ARBITRARY-CALL": {
        "rule_id": "CG-006-ARBITRARY-CALL",
        "name": "Arbitrary External Call Execution",
        "slither_alias": ["arbitrary-send-erc20", "arbitrary-send-eth"],
        "mythril_alias": ["Arbitrary external call", "External call to user-supplied target"],
        "default_severity": Severity.HIGH,
        "cwe": "CWE-841",
        "description": "Contract executes an external call to an arbitrary user-supplied target with user-supplied calldata with `msg.sender` as the contract itself.",
        "impact": "Attacker can supply an ERC20 token address as `target` and `approve(attacker, max)` as `data`, stealing all tokens approved for or owned by the contract.",
        "remediation": (
            "Do not allow arbitrary target addresses and calldata in external calls. Whitelist allowed contracts and selectors, or execute callbacks via dedicated interfaces."
        ),
        "remediation_code": """
// Fix: Restrict target to verified whitelist or known interface
function executeAction(address target, bytes calldata data) external onlyOwner {
    require(approvedTargets[target], "Target not approved");
    (bool success, ) = target.call(data);
    require(success, "Execution failed");
}
"""
    },
    "CG-007-FLASHLOAN-DEPOSIT-REENTRANCY": {
        "rule_id": "CG-007-FLASHLOAN-DEPOSIT-REENTRANCY",
        "name": "Deposit-based Flash Loan Reentrancy",
        "slither_alias": ["flashloan-reentrancy"],
        "mythril_alias": ["Flash loan balance check reentrancy"],
        "default_severity": Severity.HIGH,
        "cwe": "CWE-841",
        "description": "Flash loan pool checks repayment via total pool balance (`address(this).balance` or `token.balanceOf(this)`), allowing borrower to deposit the loan back into their internal balance during the callback.",
        "impact": "Attacker satisfies the pool repayment balance check while simultaneously crediting their internal deposit account, allowing them to withdraw the pool's entire balance afterwards.",
        "remediation": (
            "Separate flash loan repayment tracking from internal user balance deposits. Do not allow `deposit()` during an active flash loan, or track loan repayments directly."
        ),
        "remediation_code": """
// Fix: Track loan repayment separately or guard against deposit reentrancy
function flashLoan(uint256 amount) external nonReentrant {
    uint256 balanceBefore = address(this).balance;
    IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
    require(address(this).balance >= balanceBefore, "Repayment failed");
}
"""
    },
    "CG-008-FLASHLOAN-ACCESS-CONTROL": {
        "rule_id": "CG-008-FLASHLOAN-ACCESS-CONTROL",
        "name": "Lack of Access Control in Flash Loan Initiation",
        "slither_alias": ["flashloan-access-control"],
        "mythril_alias": ["Unprotected flash loan receiver"],
        "default_severity": Severity.HIGH,
        "cwe": "CWE-284",
        "description": "The flash loan function allows any sender to initiate a flash loan on behalf of an arbitrary receiver contract that pays a fixed fee.",
        "impact": "An attacker can repeatedly trigger flash loans for victim contracts, draining the victim contract's funds through forced fee payments.",
        "remediation": (
            "Ensure that `msg.sender == address(receiver)` or verify an explicit caller approval before initiating flash loans with fee liability on the receiver."
        ),
        "remediation_code": """
// Fix: Require caller to be the receiver or authorized borrower
function flashLoan(
    IERC3156FlashBorrower receiver,
    address token,
    uint256 amount,
    bytes calldata data
) external nonReentrant returns (bool) {
    require(msg.sender == address(receiver), "Caller must be receiver");
    // ... proceed with loan
}
"""
    },
    "CG-009-PRICE-ORACLE-MANIPULATION": {
        "rule_id": "CG-009-PRICE-ORACLE-MANIPULATION",
        "name": "Spot Price / Oracle Manipulation Risk",
        "slither_alias": ["oracle-trust", "price-manipulation"],
        "mythril_alias": ["Oracle price manipulation"],
        "default_severity": Severity.HIGH,
        "cwe": "CWE-682",
        "description": "Contract computes asset valuation directly from spot AMM pool reserves (`getReserves()`, `balanceOf`) or uses external oracle feeds without staleness and bound validation.",
        "impact": "Attackers can manipulate spot prices inside a single block using flash loans/swaps, distorting protocol pricing to liquidate collateral or borrow undercollateralized funds.",
        "remediation": (
            "Use decentralized Time-Weighted Average Prices (TWAP) or Chainlink Oracles with heartbeat and staleness verification."
        ),
        "remediation_code": """
// Fix: Use Chainlink feed with staleness check
function getLatestPrice() public view returns (int256) {
    (
        uint80 roundID,
        int256 price,
        uint256 startedAt,
        uint256 timeStamp,
        uint80 answeredInRound
    ) = priceFeed.latestRoundData();
    require(timeStamp > 0 && answeredInRound >= roundID, "Stale price");
    require(block.timestamp - timeStamp <= MAX_STALENESS_SECONDS, "Price outdated");
    require(price > 0, "Invalid price");
    return price;
}
"""
    },
    "CG-010-SELFDESTRUCT": {
        "rule_id": "CG-010-SELFDESTRUCT",
        "name": "Unprotected Selfdestruct / Suicide",
        "slither_alias": ["suicidal"],
        "mythril_alias": ["Unprotected Ether withdrawal", "Contract destruction"],
        "default_severity": Severity.CRITICAL,
        "cwe": "CWE-284",
        "description": "Contract contains `selfdestruct()` or `suicide()` that can be called by unauthorized parties.",
        "impact": "Attacker can destroy the contract, wiping its bytecode and forwarding all held Ether to an attacker-controlled address.",
        "remediation": (
            "Remove `selfdestruct()` entirely (deprecated in Ethereum EIP-6780 / Dencun upgrade) or restrict strictly to multi-sig governance with timelocks."
        ),
        "remediation_code": """
// Fix: Remove selfdestruct or enforce strict multi-sig governance
// In modern EVM (EIP-6780), selfdestruct only deletes bytecode in the same tx as creation.
"""
    },
    "CG-011-INTEGER-OVERFLOW": {
        "rule_id": "CG-011-INTEGER-OVERFLOW",
        "name": "Integer Overflow / Underflow in Unchecked Block",
        "slither_alias": ["divide-before-multiply"],
        "mythril_alias": ["Integer overflow", "Integer underflow"],
        "default_severity": Severity.MEDIUM,
        "cwe": "CWE-190",
        "description": "Arithmetic operation executed inside `unchecked { ... }` block (Solidity >=0.8) without precondition validation, or in Solidity <0.8 without SafeMath.",
        "impact": "Unbounded decrement or increment may wrap around, allowing attackers to inflate balances or bypass balance checks.",
        "remediation": (
            "Ensure preconditions (`require(a >= b)`) are verified before entering `unchecked` blocks."
        ),
        "remediation_code": """
// Fix: Validate arithmetic invariants before unchecked operations
function safeDecrement(uint256 balance, uint256 amount) internal pure returns (uint256) {
    require(balance >= amount, "Underflow prevented");
    unchecked {
        return balance - amount;
    }
}
"""
    },
    "CG-012-USELESS-STATEMENT": {
        "rule_id": "CG-012-USELESS-STATEMENT",
        "name": "Useless Statement / Dead Code",
        "slither_alias": ["unused-return", "dead-code"],
        "mythril_alias": ["Useless statement"],
        "default_severity": Severity.LOW,
        "cwe": "CWE-561",
        "description": "Expression statement has no effect on contract state or control flow (e.g. `_amount;` or `this;`).",
        "impact": "Dead code increases contract size, wastes deployment gas, and confuses security audits.",
        "remediation": (
            "Remove useless expression statements from the codebase."
        ),
        "remediation_code": """
// Fix: Remove useless statement
function withdraw(uint256 amount) external {
    // _amount; <-- REMOVED
    balances[msg.sender] -= amount;
}
"""
    },
    "CG-013-UNPROTECTED-INITIALIZE": {
        "rule_id": "CG-013-UNPROTECTED-INITIALIZE",
        "name": "Unprotected Initialize Function",
        "slither_alias": ["unprotected-upgrade"],
        "mythril_alias": ["Unprotected initialization"],
        "default_severity": Severity.HIGH,
        "cwe": "CWE-284",
        "description": "Proxy contract `initialize` function can be called multiple times by anyone without the `initializer` modifier.",
        "impact": "An attacker can call `initialize()` on an uninitialized implementation or proxy contract, gaining admin ownership.",
        "remediation": (
            "Use OpenZeppelin `Initializable` and decorate the initialization function with the `initializer` modifier."
        ),
        "remediation_code": """
// Fix: Use Initializable and initializer modifier
contract MyUpgradeableContract is Initializable {
    function initialize(address _owner) external initializer {
        __Ownable_init(_owner);
    }
}
"""
    },
    "CG-014-MISSING-ZERO-CHECK": {
        "rule_id": "CG-014-MISSING-ZERO-CHECK",
        "name": "Missing Zero-Address Validation",
        "slither_alias": ["missing-zero-check"],
        "mythril_alias": ["Missing zero address check"],
        "default_severity": Severity.LOW,
        "cwe": "CWE-20",
        "description": "Critical address parameter (e.g. new owner or token address) is assigned without checking against `address(0)`.",
        "impact": "Accidental transfer of ownership to address 0 permanently locks the contract.",
        "remediation": (
            "Add `require(target != address(0), 'Zero address');` before assigning critical addresses."
        ),
        "remediation_code": """
// Fix: Validate non-zero address
function setOwner(address newOwner) external onlyOwner {
    require(newOwner != address(0), "Cannot set owner to zero address");
    owner = newOwner;
}
"""
    },
    "CG-015-ARBITRARY-SEND-ETH": {
        "rule_id": "CG-015-ARBITRARY-SEND-ETH",
        "name": "Arbitrary ETH Transfer",
        "slither_alias": ["arbitrary-send-eth", "arbitrary-send-erc20"],
        "mythril_alias": ["Unprotected Ether withdrawal", "Arbitrary token transfer"],
        "default_severity": Severity.HIGH,
        "cwe": "CWE-284",
        "description": "Contract transfers Ether or tokens to an arbitrary caller-controlled address without adequate validation or access control.",
        "impact": "An attacker can drain the contract's entire Ether or token balance by supplying their own address as the transfer recipient.",
        "remediation": (
            "Ensure ETH transfers are strictly restricted to authenticated callers or validated recipient addresses with explicit authorization checks."
        ),
        "remediation_code": """
// Fix: Restrict recipient to authorized addresses
function withdrawEarnings() external {
    uint256 amount = rewards[msg.sender];
    require(amount > 0, "No rewards");
    rewards[msg.sender] = 0;
    (bool s, ) = msg.sender.call{value: amount}("");
    require(s, "Transfer failed");
}
"""
    },
    "CG-016-UNINITIALIZED-STORAGE": {
        "rule_id": "CG-016-UNINITIALIZED-STORAGE",
        "name": "Uninitialized Local Storage Pointer",
        "slither_alias": ["uninitialized-storage", "uninitialized-local"],
        "mythril_alias": ["Uninitialized storage pointer"],
        "default_severity": Severity.HIGH,
        "cwe": "CWE-824",
        "description": "A local storage struct or array variable is declared without initialization, causing it to point to storage slot 0 by default.",
        "impact": "Writing to fields of an uninitialized local storage variable overwrites critical storage variables located at slot 0 (such as contract owner).",
        "remediation": (
            "Explicitly assign local storage variables or use `memory` modifier if persistent storage reference is not intended."
        ),
        "remediation_code": """
// Fix: Use memory or initialize storage pointer explicitly
function getRecord(uint256 id) internal view returns (UserRecord memory) {
    UserRecord memory record = records[id];
    return record;
}
"""
    },
    "CG-017-FLOATING-PRAGMA": {
        "rule_id": "CG-017-FLOATING-PRAGMA",
        "name": "Floating or Outdated Solidity Pragma",
        "slither_alias": ["solc-version", "floating-pragma"],
        "mythril_alias": ["Solidity version"],
        "default_severity": Severity.LOW,
        "cwe": "CWE-1038",
        "description": "Contract uses a floating compiler version (e.g. `^0.8.0`) or an outdated Solidity version vulnerable to known compiler bugs.",
        "impact": "Contracts deployed with untested newer compiler versions or outdated compilers may inherit compiler vulnerabilities.",
        "remediation": (
            "Lock the Solidity pragma to a specific, well-tested compiler version (e.g. `pragma solidity 0.8.24;`)."
        ),
        "remediation_code": """
// Fix: Lock pragma version
pragma solidity 0.8.24;
"""
    },
    "CG-018-SIGNATURE-REPLAY": {
        "rule_id": "CG-018-SIGNATURE-REPLAY",
        "name": "Missing Nonce or Domain Separator in Signature Validation",
        "slither_alias": ["signature-replay", "missing-nonce", "ecrecover-replay"],
        "mythril_alias": ["Signature replay vulnerability", "Missing signature nonce"],
        "default_severity": Severity.HIGH,
        "cwe": "CWE-347",
        "description": "The contract uses `ecrecover` to verify signatures without invalidating a nonce or incorporating an EIP-712 domain separator (chain ID + contract address).",
        "impact": "An attacker can record a valid signature and replay it multiple times or across different contracts and chains to drain assets.",
        "remediation": (
            "1. Track used message hashes or incrementing per-user nonces to ensure signatures can only be executed once.\n"
            "2. Implement OpenZeppelin's `ECDSA` and `EIP712` with proper chain ID and contract address validation."
        ),
        "remediation_code": """
// Fix: Use EIP-712 with nonces and deadline
function permitExecute(
    address owner,
    uint256 amount,
    uint256 nonce,
    uint256 deadline,
    bytes calldata signature
) external {
    require(block.timestamp <= deadline, "Signature expired");
    require(nonces[owner]++ == nonce, "Invalid nonce");
    bytes32 structHash = keccak256(abi.encode(TYPEHASH, owner, amount, nonce, deadline));
    bytes32 hash = _hashTypedDataV4(structHash);
    address signer = ECDSA.recover(hash, signature);
    require(signer == owner, "Invalid signer");
}
"""
    },
    "CG-019-WEAK-PRNG": {
        "rule_id": "CG-019-WEAK-PRNG",
        "name": "Insecure Randomness from On-Chain Variables",
        "slither_alias": ["weak-prng", "bad-randomness", "timestamp"],
        "mythril_alias": ["Weak random number generation", "Dependence on predictable environment variable"],
        "default_severity": Severity.HIGH,
        "cwe": "CWE-330",
        "description": "Contract uses `block.timestamp`, `block.number`, `blockhash`, `block.difficulty`, or `block.prevrandao` as a source of pseudo-randomness for sensitive game/winner selection logic.",
        "impact": "Miners/validators or MEV searchers can manipulate block timestamps or construct transactions only when the pseudo-random outcome is favorable to win prizes or alter protocol states.",
        "remediation": (
            "Do not rely on on-chain block variables for critical randomness. Use Chainlink VRF (Verifiable Random Function) or commit-reveal schemes."
        ),
        "remediation_code": """
// Fix: Use Chainlink VRF for provably fair randomness
function requestRandomWinner() external onlyOwner returns (uint256 requestId) {
    return COORDINATOR.requestRandomWords(
        keyHash,
        s_subscriptionId,
        requestConfirmations,
        callbackGasLimit,
        numWords
    );
}
"""
    },
    "CG-020-READ-ONLY-REENTRANCY": {
        "rule_id": "CG-020-READ-ONLY-REENTRANCY",
        "name": "Read-Only Reentrancy Vulnerability",
        "slither_alias": ["read-only-reentrancy", "readonly-reentrancy"],
        "mythril_alias": ["Read-only reentrancy", "Unprotected view state query"],
        "default_severity": Severity.HIGH,
        "cwe": "CWE-841",
        "description": "Contract reads pool balances, exchange rates, or virtual prices from external DeFi protocols (e.g. Curve, Balancer) while an external pool reentrancy lock is engaged or during an incomplete state update.",
        "impact": "Attackers can reenter a third-party lending or liquidation contract mid-trade when the pool's virtual price is distorted, borrowing against inflated valuation.",
        "remediation": (
            "1. Reentrancy locks on view functions (`nonReentrantView`) or calling reentrancy-guarded pool entrypoints.\n"
            "2. Avoid using raw `get_virtual_price()` in pricing calculations during external calls."
        ),
        "remediation_code": """
// Fix: Verify pool is not currently locked/reentered before querying price
function getSafePrice() external view returns (uint256) {
    // Check pool reentrancy status or query TWAP
    return oracle.getSafeTwapPrice();
}
"""
    },
    "CG-021-UNCHECKED-ERC20-TRANSFER": {
        "rule_id": "CG-021-UNCHECKED-ERC20-TRANSFER",
        "name": "Unchecked ERC20 Transfer Return Value",
        "slither_alias": ["unchecked-transfer", "unchecked-erc20"],
        "mythril_alias": ["Unchecked ERC20 transfer"],
        "default_severity": Severity.MEDIUM,
        "cwe": "CWE-252",
        "description": "Standard ERC20 `.transfer()` or `.transferFrom()` return value is ignored, or contract interacts with non-standard tokens (like USDT) that do not return a boolean.",
        "impact": "Failed transfers will fail silently without reverting, causing internal balances to update while tokens never actually moved.",
        "remediation": (
            "Use OpenZeppelin's `SafeERC20` library and replace `token.transfer(...)` with `token.safeTransfer(...)`."
        ),
        "remediation_code": """
// Fix: Use SafeERC20
using SafeERC20 for IERC20;

function withdrawToken(IERC20 token, uint256 amount) external {
    balances[msg.sender] -= amount;
    token.safeTransfer(msg.sender, amount);
}
"""
    },
    "CG-022-UNPROTECTED-MINT": {
        "rule_id": "CG-022-UNPROTECTED-MINT",
        "name": "Unprotected Token Minting",
        "slither_alias": ["unprotected-mint", "arbitrary-mint"],
        "mythril_alias": ["Public mint function", "Unprotected mint"],
        "default_severity": Severity.CRITICAL,
        "cwe": "CWE-284",
        "description": "Public or external token minting function lacks access control modifiers (such as `onlyOwner` or `onlyRole(MINTER_ROLE)`).",
        "impact": "Any external caller can mint an infinite amount of tokens to any address, instantly collapsing the token economy and draining liquidity pools.",
        "remediation": (
            "Restrict mint functions with strict access control modifiers (e.g. `onlyOwner` or `onlyRole(MINTER_ROLE)`)."
        ),
        "remediation_code": """
// Fix: Restrict minting with access control
function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
    _mint(to, amount);
}
"""
    }
}

def get_rule_by_id(rule_id: str) -> Optional[Dict[str, Any]]:
    if not rule_id:
        return None
    # Direct match
    if rule_id in RULES_REGISTRY:
        return RULES_REGISTRY[rule_id]
    # Case-insensitive or normalized match
    rule_id_clean = rule_id.strip().upper().replace("_", "-")
    for rid, rule in RULES_REGISTRY.items():
        if rid.upper().replace("_", "-") == rule_id_clean:
            return rule
        if rid.endswith(rule_id_clean) or rule_id_clean in rid:
            return rule
    return None

def get_rule_for_category(category: str) -> Optional[Dict[str, Any]]:
    if not category:
        return None
    cat_lower = category.lower().strip()
    for rule in RULES_REGISTRY.values():
        if rule["name"].lower() in cat_lower or cat_lower in rule["name"].lower():
            return rule
        for alias in rule.get("slither_alias", []):
            if alias.lower() in cat_lower or cat_lower in alias.lower():
                return rule
        for alias in rule.get("mythril_alias", []):
            if alias.lower() in cat_lower or cat_lower in alias.lower():
                return rule
    return None

def get_remediation_for_rule(rule_id_or_category: str) -> str:
    rule = get_rule_by_id(rule_id_or_category)
    if not rule:
        rule = get_rule_for_category(rule_id_or_category)
    if rule:
        return rule.get("remediation", "")
    return "Follow standard smart contract security patterns and conduct a comprehensive peer audit."
