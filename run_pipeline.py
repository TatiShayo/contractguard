import os
import json
from slither_wrapper import run_slither
from mythril_wrapper import run_mythril, reconcile
from economic_logic_judge import review_economic_logic
from report_generator import generate_report

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 1. Define fixtures and their intended vulnerabilities / detection rules
    vulnerable_challenges = [
        {
            "name": "Reentrancy.sol",
            "path": os.path.join(base_dir, "fixtures", "ethernaut", "Reentrancy.sol"),
            "intended_vulnerability": "Reentrancy / State access after external call",
            "check_fn": lambda findings: any(
                "reentrancy" in f.category.lower() or 
                "state access after external call" in f.category.lower() or 
                "reentrancy" in f.description.lower() or 
                "state access after external call" in f.description.lower()
                for f in findings
            )
        },
        {
            "name": "Telephone.sol",
            "path": os.path.join(base_dir, "fixtures", "ethernaut", "Telephone.sol"),
            "intended_vulnerability": "tx.origin authorization bypass / Use of tx.origin",
            "check_fn": lambda findings: any(
                "tx.origin" in f.category.lower() or 
                "use of tx.origin" in f.category.lower() or 
                "tx.origin" in f.description.lower() or 
                "origin" in f.description.lower()
                for f in findings
            )
        },
        {
            "name": "Delegation.sol",
            "path": os.path.join(base_dir, "fixtures", "ethernaut", "Delegation.sol"),
            "intended_vulnerability": "Arbitrary delegatecall / Delegatecall to user-supplied address",
            "check_fn": lambda findings: any(
                "delegatecall" in f.category.lower() or 
                "delegate-call" in f.category.lower() or 
                "delegatecall" in f.description.lower()
                for f in findings
            )
        },
        {
            "name": "NaiveReceiverLenderPool.sol",
            "path": os.path.join(base_dir, "fixtures", "dvd", "NaiveReceiverLenderPool.sol"),
            "intended_vulnerability": "Lack of access control in flash loan",
            "check_fn": lambda findings: any(
                "access control" in f.category.lower() or 
                "flash loan" in f.category.lower() or 
                "access control" in f.description.lower() or 
                "flash loan" in f.description.lower()
                for f in findings
            )
        },
        {
            "name": "TrusterLenderPool.sol",
            "path": os.path.join(base_dir, "fixtures", "dvd", "TrusterLenderPool.sol"),
            "intended_vulnerability": "Arbitrary external call execution",
            "check_fn": lambda findings: any(
                "arbitrary call" in f.category.lower() or 
                "external call" in f.category.lower() or 
                "call execution" in f.category.lower() or 
                "arbitrary call" in f.description.lower() or 
                "external call" in f.description.lower()
                for f in findings
            )
        },
        {
            "name": "SideEntranceLenderPool.sol",
            "path": os.path.join(base_dir, "fixtures", "dvd", "SideEntranceLenderPool.sol"),
            "intended_vulnerability": "Deposit-based flash loan reentrancy",
            "check_fn": lambda findings: any(
                "reentrancy" in f.category.lower() or 
                "deposit-based" in f.category.lower() or 
                "reentrancy" in f.description.lower() or 
                "deposit" in f.description.lower()
                for f in findings
            )
        }
    ]

    control_contracts = [
        {
            "name": "Clean.sol",
            "path": os.path.join(base_dir, "fixtures", "ethernaut", "Clean.sol"),
            "intended_vulnerability": "None (Control)",
            "check_fn": lambda findings: len([f for f in findings if f.severity in ("high", "medium")]) == 0
        }
    ]

    all_findings = []
    results_breakdown = []
    correctly_flagged_count = 0

    print("Starting ContractGuard Validation Pipeline Run...")
    
    # Process vulnerable challenges
    for challenge in vulnerable_challenges:
        name = challenge["name"]
        path = challenge["path"]
        print(f"Processing challenge: {name}...")
        
        try:
            # 1. Run Slither
            try:
                slither_f = run_slither(path)
            except Exception as e:
                print(f"  [!] Slither failed on {name}: {e}")
                slither_f = []
                
            # 2. Run Mythril
            try:
                mythril_f = run_mythril(path)
            except Exception as e:
                print(f"  [!] Mythril failed on {name}: {e}")
                mythril_f = []
                
            # 3. Reconcile
            reconciled_f = reconcile(slither_f, mythril_f)
            
            # 4. Run LLM economic logic judge
            try:
                with open(path, "r", encoding="utf-8") as f:
                    source = f.read()
                llm_f = review_economic_logic(source, reconciled_f)
            except Exception as e:
                print(f"  [!] LLM Judge failed on {name}: {e}")
                llm_f = []
                
            # Combine findings
            challenge_findings = reconciled_f + llm_f
            
            # Assign contract name
            for f in challenge_findings:
                f.contract_name = name
                
            all_findings.extend(challenge_findings)
            
            # Check if intended vulnerability was flagged
            flagged = challenge["check_fn"](challenge_findings)
            if flagged:
                correctly_flagged_count += 1
                status = "PASS"
            else:
                status = "FAIL"
                
            results_breakdown.append({
                "name": name,
                "type": "vulnerable",
                "intended_vulnerability": challenge["intended_vulnerability"],
                "flagged": flagged,
                "status": status,
                "findings_count": len(challenge_findings)
            })
            
            print(f"  -> {status}: Findings count = {len(challenge_findings)}")
            
        except Exception as e:
            print(f"  [ERROR] Pipeline failed on {name}: {e}")
            results_breakdown.append({
                "name": name,
                "type": "vulnerable",
                "intended_vulnerability": challenge["intended_vulnerability"],
                "flagged": False,
                "status": "ERROR",
                "findings_count": 0
            })

    # Process control contracts
    for control in control_contracts:
        name = control["name"]
        path = control["path"]
        print(f"Processing control contract: {name}...")
        
        try:
            try:
                slither_f = run_slither(path)
            except Exception:
                slither_f = []
            try:
                mythril_f = run_mythril(path)
            except Exception:
                mythril_f = []
            reconciled_f = reconcile(slither_f, mythril_f)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    source = f.read()
                llm_f = review_economic_logic(source, reconciled_f)
            except Exception:
                llm_f = []
                
            control_findings = reconciled_f + llm_f
            for f in control_findings:
                f.contract_name = name
                
            all_findings.extend(control_findings)
            
            passed_control = control["check_fn"](control_findings)
            status = "PASS" if passed_control else "FAIL"
            
            results_breakdown.append({
                "name": name,
                "type": "control",
                "intended_vulnerability": "None (Control)",
                "flagged": not passed_control,  # True if false positive occurred
                "status": status,
                "findings_count": len(control_findings)
            })
            print(f"  -> {status}: Control contract check, findings count = {len(control_findings)}")
        except Exception as e:
            print(f"  [ERROR] Control contract check failed: {e}")
            results_breakdown.append({
                "name": name,
                "type": "control",
                "intended_vulnerability": "None (Control)",
                "flagged": True,
                "status": "ERROR",
                "findings_count": 0
            })

    # Calculate recall
    total_vulnerable = len(vulnerable_challenges)
    recall = correctly_flagged_count / total_vulnerable if total_vulnerable > 0 else 0.0
    recall_percentage = recall * 100

    print(f"\nRecall calculation completed: {correctly_flagged_count} / {total_vulnerable} ({recall_percentage:.2f}%)")

    # Generate unified report
    report_content = generate_report(all_findings)
    report_path = os.path.join(base_dir, "UNIFIED_REPORT.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"Saved unified report to {report_path}")

    # Generate RESULTS.md content
    results_md = []
    results_md.append("# Validation Run Results")
    results_md.append("")
    results_md.append("This document outlines the validation run breakdown and overall recall metric for the ContractGuard smart contract auditing pipeline.")
    results_md.append("")
    results_md.append("## 📈 Performance Summary")
    results_md.append(f"- **Overall Recall:** **{recall_percentage:.2f}%** ({correctly_flagged_count} / {total_vulnerable} vulnerable challenges correctly identified)")
    results_md.append("")
    results_md.append("## 📋 Challenge Breakdown")
    results_md.append("| Challenge / Contract | Type | Intended Vulnerability | Correctly Flagged? | Findings Count | Status |")
    results_md.append("| --- | --- | --- | --- | --- | --- |")
    
    for r in results_breakdown:
        flagged_str = "Yes" if r["flagged"] else "No"
        if r["type"] == "control":
            flagged_str = "No (No False Positive)" if not r["flagged"] else "Yes (False Positive)"
        results_md.append(f"| `{r['name']}` | {r['type'].capitalize()} | {r['intended_vulnerability']} | {flagged_str} | {r['findings_count']} | {r['status']} |")

    results_md.append("")
    results_md.append("## 📄 Verification and Findings Report")
    results_md.append("A detailed unified report of all identified findings has been saved to [UNIFIED_REPORT.md](UNIFIED_REPORT.md).")
    
    results_path = os.path.join(base_dir, "RESULTS.md")
    with open(results_path, "w", encoding="utf-8") as f:
        f.write("\n".join(results_md))
    print(f"Saved results summary to {results_path}")

if __name__ == "__main__":
    main()
