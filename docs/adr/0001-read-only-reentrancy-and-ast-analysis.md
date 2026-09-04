# ADR 0001: AST Taint Analysis for Read-Only Reentrancy and SafeERC20 Enforcement

## Context
DeFi protocols lose hundreds of millions to reentrancy attacks that exploit view functions and unchecked token transfers.

## Decision
1. **AST Taint Traversal**: Analyze Solidity syntax trees for cross-function state dependencies.
2. **SafeERC20 Enforcement**: Mandate OpenZeppelin SafeERC20 wrapping for all token operations.
3. **CI Confidence Gates**: Only high-confidence E1 findings block automated build pipelines.

## Consequences
- **Positive**: Proactive prevention of multi-million dollar DeFi oracle exploits.
- **Negative**: Deeper static analysis requires 5-10 seconds of processing per contract.
