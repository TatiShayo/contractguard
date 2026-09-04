# SPEC 001: Solidity Static Analyzer & DeFi Reentrancy Detector

## Problem Statement
Smart contract developers deploy vulnerable contracts because existing linters miss read-only reentrancy and non-standard ERC-20 return values.

## Solution
A static analysis tool that parses Solidity ASTs, identifies cross-contract reentrancy vectors, and enforces safe token transfer primitives.

## User Stories
1. As a Web3 developer, I want my CI pipeline to catch read-only reentrancy, so that our protocol's price oracles cannot be manipulated.
2. As an auditor, I want automated detection of missing SafeERC20 wrappers, so that silent transfer failures are eliminated.

## Implementation Decisions
- Read-only reentrancy detector in `rules/read_only_reentrancy.py`.
- Safe transfer checker in `rules/safe_transfer.py`.

## Testing Decisions
- Seam: `tests/test_read_only_reentrancy_detector.py`.
- Verify AST detection against vulnerable and secure mock contract benchmarks.
