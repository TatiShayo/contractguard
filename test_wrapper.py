import os
import json
from slither_wrapper import run_slither
from mythril_wrapper import run_mythril, reconcile
from economic_logic_judge import review_economic_logic

ethernaut_fixtures = [
    "fixtures/ethernaut/Reentrancy.sol",
    "fixtures/ethernaut/Telephone.sol",
    "fixtures/ethernaut/Delegation.sol",
    "fixtures/ethernaut/Clean.sol"
]

dvd_fixtures = [
    "fixtures/dvd/NaiveReceiverLenderPool.sol",
    "fixtures/dvd/TrusterLenderPool.sol",
    "fixtures/dvd/SideEntranceLenderPool.sol"
]

print("Running Combined Slither + Mythril Pipeline test on Ethernaut fixtures...")
for fix in ethernaut_fixtures:
    path = os.path.join(os.path.dirname(__file__), fix)
    print(f"\n--- Testing Ethernaut: {fix} ---")
    try:
        slither_findings = run_slither(path)
        print(f"Slither found {len(slither_findings)} findings.")
        
        mythril_findings = run_mythril(path)
        print(f"Mythril found {len(mythril_findings)} findings.")
        
        reconciled_findings = reconcile(slither_findings, mythril_findings)
        print(f"Reconciled into {len(reconciled_findings)} findings:")
        for f in reconciled_findings:
            print(json.dumps(f.to_dict(), indent=2))
            
    except Exception as e:
        print(f"Error running pipeline on {fix}: {e}")

print("\nRunning Economic Logic LLM Judge on DamnVulnerableDeFi fixtures...")
for fix in dvd_fixtures:
    path = os.path.join(os.path.dirname(__file__), fix)
    print(f"\n--- Testing DVD: {fix} ---")
    try:
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        
        # In a real environment, we'd run Slither/Mythril first to feed existing findings.
        # Let's run Slither first to see if it runs on the fixture.
        try:
            existing = run_slither(path)
        except Exception:
            existing = []

        llm_findings = review_economic_logic(source, existing)
        print(f"LLM Judge found {len(llm_findings)} findings:")
        for f in llm_findings:
            print(json.dumps(f.to_dict(), indent=2))
            
    except Exception as e:
        print(f"Error running economic logic judge on {fix}: {e}")
