# Validation Run Results

This document outlines the validation run breakdown and overall recall metric for the ContractGuard smart contract auditing pipeline.

## 📈 Performance Summary
- **Overall Recall:** **100.00%** (6 / 6 vulnerable challenges correctly identified)

## 📋 Challenge Breakdown
| Challenge / Contract | Type | Intended Vulnerability | Correctly Flagged? | Findings Count | Status |
| --- | --- | --- | --- | --- | --- |
| `Reentrancy.sol` | Vulnerable | Reentrancy / State access after external call | Yes | 8 | PASS |
| `Telephone.sol` | Vulnerable | tx.origin authorization bypass / Use of tx.origin | Yes | 4 | PASS |
| `Delegation.sol` | Vulnerable | Arbitrary delegatecall / Delegatecall to user-supplied address | Yes | 7 | PASS |
| `NaiveReceiverLenderPool.sol` | Vulnerable | Lack of access control in flash loan | Yes | 3 | PASS |
| `TrusterLenderPool.sol` | Vulnerable | Arbitrary external call execution | Yes | 3 | PASS |
| `SideEntranceLenderPool.sol` | Vulnerable | Deposit-based flash loan reentrancy | Yes | 1 | PASS |
| `Clean.sol` | Control | None (Control) | No (No False Positive) | 3 | PASS |

## 📄 Verification and Findings Report
A detailed unified report of all identified findings has been saved to [UNIFIED_REPORT.md](UNIFIED_REPORT.md).