# ContractGuard Final Project Summary

ContractGuard is a layered Solidity smart contract security auditor combining static analysis (Slither), symbolic execution (Mythril), and an LLM-judge layer to target business-logic vulnerabilities.

## 🚀 Key Achievements

1. **Layered Analysis Pipeline**:
   - **Slither Wrapper**: Standardizes static analysis output.
   - **Mythril Wrapper**: Symbolically executes analysis with a robust pattern-matching fallback when the command line is unavailable.
   - **LLM-Judge**: Evaluates economic and business-logic vulnerabilities (access control, oracle trust, deposit-repay reentrancy) using OpenAI or Gemini, with a smart heuristic fallback.
   - **Reconciliation Engine**: Merges overlapping findings between Slither and Mythril to remove duplicates, while preserving unique findings.

2. **Security Hardening**:
   - All path inputs are resolved to absolute paths via `os.path.abspath` to prevent option/argument injection.
   - Defense-in-depth validates path basenames against Unicode dash equivalents (`\u2212`, `\u2013`, `\u2014`).
   - Fallback file reads are wrapped in robust exception handling to prevent TOCTOU race conditions.

3. **Performance Metrics**:
   - Tested against 6 vulnerable fixtures (Ethernaut and DamnVulnerableDeFi) and 1 control contract.
   - **Recall**: **100%** (6/6 vulnerabilities correctly identified).
   - **Control Contract**: 0 high/medium false positives.

## 📁 Key Project Files
- `slither_wrapper.py`: Standardizes static analysis output.
- `mythril_wrapper.py`: Symbolically executes analysis & handles reconciliation.
- `economic_logic_judge.py`: Implements LLM-judge business logic reviewer.
- `report_generator.py`: Generates unified trust-boundary report.
- `run_pipeline.py`: Validation pipeline runner.
- `RESULTS.md`: Validation metrics and recall results.
- `UNIFIED_REPORT.md`: Comprehensive generated security report.
