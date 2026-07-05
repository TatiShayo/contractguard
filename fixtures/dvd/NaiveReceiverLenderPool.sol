// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/interfaces/IERC3156FlashLender.sol";
import "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";

/**
 * @title NaiveReceiverLenderPool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract NaiveReceiverLenderPool is ReentrancyGuard, IERC3156FlashLender {

    address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    uint256 private constant FIXED_FEE = 1 ether; // 10^18

    error RepayFailed();
    error UnsupportedCurrency();
    error CallbackFailed();

    function maxFlashLoan(address token) external view returns (uint256) {
        if (token == ETH) {
            return address(this).balance;
        }
        return 0;
    }

    function flashFee(address token, uint256) external view returns (uint256) {
        if (token != ETH) {
            revert UnsupportedCurrency();
        }
        return FIXED_FEE;
    }

    function flashLoan(
        IERC3156FlashBorrower receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external override nonReentrant returns (bool) {
        if (token != ETH) {
            revert UnsupportedCurrency();
        }
        
        uint256 balanceBefore = address(this).balance;

        // Transfer ETH to the receiver
        payable(address(receiver)).transfer(amount);

        // VULNERABILITY: Lack of access control check on flash loan execution. 
        // Anybody can initiate a loan on behalf of another contract, causing that receiver contract to pay the fixed fee.
        if (receiver.onFlashLoan(msg.sender, ETH, amount, FIXED_FEE, data) != keccak256("ERC3156FlashBorrower.onFlashLoan")) {
            revert CallbackFailed();
        }

        if (address(this).balance < balanceBefore + FIXED_FEE) {
            revert RepayFailed();
        }

        return true;
    }

    // Allow deposits of ETH
    receive() external payable {}
}
