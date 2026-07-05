import os
import json
import traceback
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
        findings = run_slither(path)
        categories = [f.category for f in findings]
        assert "reentrancy-eth" in categories, f"Expected 'reentrancy-eth' detector in findings, got {categories}"
        reentrancy_findings = [f for f in findings if f.category == "reentrancy-eth"]
        assert all(f.severity == "high" for f in reentrancy_findings), f"Expected 'reentrancy-eth' severity to be 'high'"

    def test_telephone():
        path = os.path.join(base_dir, "fixtures", "ethernaut", "Telephone.sol")
        findings = run_slither(path)
        assert len(findings) > 0, "Expected some findings in Telephone.sol"
        categories = [f.category for f in findings]
        assert "missing-zero-check" in categories, f"Expected 'missing-zero-check' in findings, got {categories}"

    def test_delegation():
        path = os.path.join(base_dir, "fixtures", "ethernaut", "Delegation.sol")
        findings = run_slither(path)
        categories = [f.category for f in findings]
        assert "controlled-delegatecall" in categories, f"Expected 'controlled-delegatecall' in findings, got {categories}"
        delegation_findings = [f for f in findings if f.category == "controlled-delegatecall"]
        assert all(f.severity == "high" for f in delegation_findings), f"Expected 'controlled-delegatecall' severity to be 'high'"

    def test_clean():
        path = os.path.join(base_dir, "fixtures", "ethernaut", "Clean.sol")
        findings = run_slither(path)
        high_or_medium = [f for f in findings if f.severity in ("high", "medium")]
        assert len(high_or_medium) == 0, f"Expected no high or medium findings in Clean.sol, got {high_or_medium}"

    def test_mythril_reentrancy():
        path = os.path.join(base_dir, "fixtures", "ethernaut", "Reentrancy.sol")
        findings = run_mythril(path)
        categories = [f.category for f in findings]
        assert "State access after external call" in categories, f"Expected 'State access after external call' in findings, got {categories}"
        assert "Useless statement" in categories, f"Expected 'Useless statement' in findings, got {categories}"

    def test_reconciliation():
        path = os.path.join(base_dir, "fixtures", "ethernaut", "Reentrancy.sol")
        slither_f = run_slither(path)
        mythril_f = run_mythril(path)
        
        reconciled = reconcile(slither_f, mythril_f)
        
        # Verify that the reentrancy finding is merged and lists both tools
        reentrancy_merged = [f for f in reconciled if "reentrancy-eth" in f.category or "State access after external call" in f.category]
        assert len(reentrancy_merged) > 0, "Expected reconciled reentrancy finding"
        assert any("slither, mythril" in f.source_tool for f in reentrancy_merged), "Expected source_tool to indicate both slither and mythril"
        
        # Verify that unique Mythril findings (e.g. Useless statement class) are preserved
        useless_statement = [f for f in reconciled if f.category == "Useless statement"]
        assert len(useless_statement) == 1, "Expected unique Useless statement finding to be preserved"
        assert useless_statement[0].source_tool == "mythril", f"Expected unique finding source to be 'mythril', got {useless_statement[0].source_tool}"

    def test_llm_judge_naive_receiver():
        path = os.path.join(base_dir, "fixtures", "dvd", "NaiveReceiverLenderPool.sol")
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        try:
            existing = run_slither(path)
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
            existing = run_slither(path)
        except Exception:
            existing = []
        findings = review_economic_logic(source, existing)
        categories = [f.category for f in findings]
        assert any("arbitrary external call" in c.lower() or "call execution" in c.lower() for c in categories), f"Expected arbitrary external call finding, got {categories}"

    def test_llm_judge_side_entrance():
        path = os.path.join(base_dir, "fixtures", "dvd", "SideEntranceLenderPool.sol")
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        try:
            existing = run_slither(path)
        except Exception:
            existing = []
        findings = review_economic_logic(source, existing)
        categories = [f.category for f in findings]
        assert any("reentrancy" in c.lower() or "deposit-based" in c.lower() for c in categories), f"Expected deposit-based flash loan reentrancy, got {categories}"

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
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Saved results to {results_path}")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
