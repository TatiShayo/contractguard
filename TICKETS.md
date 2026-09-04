# TICKETS — ContractGuard Security Pipeline

## [TICKET-001] Read-Only Reentrancy AST Detector
- **Blocked by**: None
- **Delivers**: Static analysis rule flagging view function oracle vulnerabilities.
- **Verification**: `tests/test_read_only_reentrancy_detector.py`

## [TICKET-002] SafeERC20 Unchecked Transfer Checker
- **Blocked by**: TICKET-001
- **Delivers**: AST visitor catching bare `transfer()` and `transferFrom()` calls on ERC-20 interfaces.
- **Verification**: Benchmark test suite asserting detection of non-boolean-returning token transfers.
