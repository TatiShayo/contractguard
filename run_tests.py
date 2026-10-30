import os
import json
import traceback

os.environ.setdefault("CONTRACTGUARD_OFFLINE", "1")

from slither_wrapper import run_slither
from mythril_wrapper import run_mythril, reconcile
from economic_logic_judge import review_economic_logic

def run_test_with_retries(test_func, retries=2):
    last_err = None
    for attempt in range(retries + 1):
        try:
            test_func()
            return {"status": "passed", "message": "Success", "retries": attempt}
        except Exception as e:
            last_err = e
            print(f"Attempt {attempt} failed: {e}")
    return {"status": "failed", "message": f"{str(last_err)}\n{traceback.format_exc()}", "retries": retries}

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Define the individual tests
    def test_reentrancy():
        path = os.path.join(base_dir, "fixtures", "ethernaut", "Reentrancy.sol")
        findings = run_slither(path, offline=True)
        reentrancy_findings = [
            f for f in findings
            if f.rule_id == "CG-001-REENTRANCY" or "reentrancy" in f.category.lower() or "state access" in f.category.lower()
        ]
        assert len(reentrancy_findings) > 0, f"Expected reentrancy detector in findings, got {findings}"
        assert all(f.severity == "high" for f in reentrancy_findings), f"Expected 'reentrancy' severity to be 'high'"

    def test_telephone():
        path = os.path.join(base_dir, "fixtures", "ethernaut", "Telephone.sol")
        findings = run_slither(path, offline=True)
        assert len(findings) > 0, "Expected some findings in Telephone.sol"
        has_expected = any(
            f.rule_id in ("CG-002-TX-ORIGIN", "CG-014-MISSING-ZERO-CHECK") or
            "missing-zero-check" in f.category.lower() or
            "origin" in f.category.lower()
            for f in findings
        )
        assert has_expected, f"Expected tx.origin or missing-zero-check in findings, got {findings}"

    def test_delegation():
        path = os.path.join(base_dir, "fixtures", "ethernaut", "Delegation.sol")
        findings = run_slither(path, offline=True)
        delegation_findings = [
            f for f in findings
            if f.rule_id == "CG-003-CONTROLLED-DELEGATECALL" or "delegatecall" in f.category.lower()
        ]
        assert len(delegation_findings) > 0, f"Expected delegatecall in findings, got {findings}"
        assert all(f.severity == "high" for f in delegation_findings), f"Expected 'controlled-delegatecall' severity to be 'high'"

    def test_clean():
        path = os.path.join(base_dir, "fixtures", "ethernaut", "Clean.sol")
        findings = run_slither(path, offline=True)
        high_or_medium = [f for f in findings if f.severity in ("high", "medium", "critical")]
        assert len(high_or_medium) == 0, f"Expected no high or medium findings in Clean.sol, got {high_or_medium}"

    def test_mythril_reentrancy():
        path = os.path.join(base_dir, "fixtures", "ethernaut", "Reentrancy.sol")
        findings = run_mythril(path, offline=True)
        categories = [f.category for f in findings]
        assert any("State access after external call" in c or "reentrancy" in c.lower() for c in categories), f"Expected reentrancy finding, got {categories}"
        assert any("Useless statement" in c or f.rule_id == "CG-012-USELESS-STATEMENT" for f, c in zip(findings, categories)), f"Expected 'Useless statement' in findings, got {categories}"

    def test_reconciliation():
        path = os.path.join(base_dir, "fixtures", "ethernaut", "Reentrancy.sol")
        slither_f = run_slither(path, offline=True)
        mythril_f = run_mythril(path, offline=True)

        reconciled = reconcile(slither_f, mythril_f)

        reentrancy_merged = [
            f for f in reconciled
            if "reentrancy" in f.category.lower() or "state access" in f.category.lower() or f.rule_id == "CG-001-REENTRANCY"
        ]
        assert len(reentrancy_merged) > 0, "Expected reconciled reentrancy finding"

        useless_statement = [
            f for f in reconciled
            if f.category == "Useless statement" or f.rule_id == "CG-012-USELESS-STATEMENT"
        ]
        assert len(useless_statement) >= 1, "Expected unique Useless statement finding to be preserved"

    def test_llm_judge_naive_receiver():
        path = os.path.join(base_dir, "fixtures", "dvd", "NaiveReceiverLenderPool.sol")
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        try:
            existing = run_slither(path, offline=True)
        except Exception:
            existing = []
        findings = review_economic_logic(source, existing)
        categories = [f.category for f in findings]
        assert any("access control" in c.lower() or "flash loan" in c.lower() for c in categories), f"Expected access control finding, got {categories}"

    def test_llm_judge_truster():
        path = os.path.join(base_dir, "fixtures", "dvd", "TrusterLenderPool.sol")
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        try:
            existing = run_slither(path, offline=True)
        except Exception:
            existing = []
        findings = review_economic_logic(source, existing)
        categories = [f.category for f in findings]
        assert any("arbitrary" in c.lower() or "external call" in c.lower() for c in categories), f"Expected arbitrary external call finding, got {categories}"

    def test_llm_judge_side_entrance():
        path = os.path.join(base_dir, "fixtures", "dvd", "SideEntranceLenderPool.sol")
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        try:
            existing = run_slither(path, offline=True)
        except Exception:
            existing = []
        findings = review_economic_logic(source, existing)
        categories = [f.category for f in findings]
        assert any("reentrancy" in c.lower() or "deposit" in c.lower() for c in categories), f"Expected deposit-based flash loan reentrancy, got {categories}"

    tests = {
        "test_reentrancy": test_reentrancy,
        "test_telephone": test_telephone,
        "test_delegation": test_delegation,
        "test_clean": test_clean,
        "test_mythril_reentrancy": test_mythril_reentrancy,
        "test_reconciliation": test_reconciliation,
        "test_llm_judge_naive_receiver": test_llm_judge_naive_receiver,
        "test_llm_judge_truster": test_llm_judge_truster,
        "test_llm_judge_side_entrance": test_llm_judge_side_entrance
    }

    details = []
    all_passed = True

    for name, test_func in tests.items():
        print(f"Running {name}...")
        res = run_test_with_retries(test_func, retries=2)
        res["test_name"] = name
        details.append(res)
        if res["status"] != "passed":
            all_passed = False

    passed_count = sum(1 for d in details if d["status"] == "passed")
    summary = f"{passed_count} of {len(tests)} tests passed"

    results = {
        "passed": all_passed,
        "summary": summary,
        "details": details
    }

    results_path = os.path.join(base_dir, "TEST_RESULTS.json")
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"Saved results to {results_path}")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
