# CONTEXT.md — Ubiquitous Domain Language (ContractGuard)

## Core Entities
- **AstTaintFlow**: Path traversal tracing untrusted user input or manipulated state across Solidity AST nodes.
- **ReadOnlyReentrancyRule**: Detector inspecting view functions reading pool balances during active state mutations.
- **SafeTransferRule**: Pattern checker flagging bare ERC-20 transfer calls lacking return value verification.
- **ConfidenceTier**: Severity classification (`E1_CRITICAL`, `E2_PROBABLE`) determining CI pipeline blocking.

## Domain Invariants
- All bare `IERC20.transfer()` invocations must be flagged as high-confidence vulnerabilities.
- Read-only reentrancy checks must evaluate multi-contract oracle interaction patterns.

## Forbidden Terminology
- Do not call vulnerabilities "bugs"; use "Vulnerability" or "SecurityFinding".
- Do not refer to AST analysis as "regex search"; use "AbstractSyntaxTreeTraversal".
