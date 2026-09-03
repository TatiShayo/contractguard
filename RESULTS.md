# Validation Run Results

This document outlines the validation run breakdown and overall recall metric for the ContractGuard smart contract auditing pipeline.

## 📈 Performance Summary
- **Overall Recall:** **100.00%** (6 / 6 vulnerable challenges correctly identified)
- **Security Posture Score:** **0/100** (F (Critical Risk))
- **Total Findings:** **22** across benchmark fixtures

## 📋 Challenge Breakdown
| Challenge / Contract | Type | Intended Vulnerability | Correctly Flagged? | Findings Count | Status |
| --- | --- | --- | --- | --- | --- |
| `Reentrancy.sol` | Vulnerable | Reentrancy / State access after external call | Yes | 2 | PASS |
| `Telephone.sol` | Vulnerable | tx.origin authorization bypass / Use of tx.origin | Yes | 3 | PASS |
| `Delegation.sol` | Vulnerable | Arbitrary delegatecall / Delegatecall to user-supplied address | Yes | 5 | PASS |
| `NaiveReceiverLenderPool.sol` | Vulnerable | Lack of access control in flash loan | Yes | 3 | PASS |
| `TrusterLenderPool.sol` | Vulnerable | Arbitrary external call execution | Yes | 4 | PASS |
| `SideEntranceLenderPool.sol` | Vulnerable | Deposit-based flash loan reentrancy | Yes | 5 | PASS |
| `Clean.sol` | Control | None (Control) | No (No False Positive) | 0 | PASS |

## 📄 Verification and Findings Report
- Comprehensive Markdown Report: [UNIFIED_REPORT.md](UNIFIED_REPORT.md)
- OASIS SARIF v2.1.0 Report: [SARIF_REPORT.sarif](SARIF_REPORT.sarif)
- Sanitized JSON Findings: [FINDINGS.json](FINDINGS.json)