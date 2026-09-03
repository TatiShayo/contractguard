import pytest
from ast_analyzer import ASTAnalyzer

@pytest.fixture
def analyzer():
    return ASTAnalyzer()

def test_read_only_reentrancy_vulnerable(analyzer):
    sol_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurvePool {
    function get_virtual_price() external view returns (uint256);
}

contract PriceConsumerVulnerable {
    ICurvePool public pool;

    constructor(address _pool) {
        pool = ICurvePool(_pool);
    }

    function getOraclePrice() external view returns (uint256) {
        return pool.get_virtual_price();
    }
}
"""
    findings = analyzer.analyze_source(sol_code)
    ro_findings = [f for f in findings if f.rule_id == "CG-020-READ-ONLY-REENTRANCY"]
    assert len(ro_findings) >= 1
    assert "PriceConsumerVulnerable" in ro_findings[0].contract_name
    assert "getOraclePrice" in ro_findings[0].function_or_line

def test_read_only_reentrancy_safe_with_guard(analyzer):
    sol_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurvePool {
    function get_virtual_price() external view returns (uint256);
}

contract PriceConsumerSafe {
    ICurvePool public pool;
    bool private locked;

    modifier nonReentrantView() {
        require(!locked, "ReentrancyGuard: reentrant call");
        _;
    }

    constructor(address _pool) {
        pool = ICurvePool(_pool);
    }

    function getOraclePrice() external view nonReentrantView returns (uint256) {
        return pool.get_virtual_price();
    }
}
"""
    findings = analyzer.analyze_source(sol_code)
    ro_findings = [f for f in findings if f.rule_id == "CG-020-READ-ONLY-REENTRANCY"]
    assert len(ro_findings) == 0

def test_unchecked_erc20_transfer_detected(analyzer):
    sol_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract TokenVault {
    function sendTokens(address token, address to, uint256 amount) external {
        IERC20(token).transfer(to, amount);
    }
}
"""
    findings = analyzer.analyze_source(sol_code)
    transfer_findings = [f for f in findings if f.rule_id == "CG-021-UNCHECKED-ERC20-TRANSFER"]
    assert len(transfer_findings) >= 1
