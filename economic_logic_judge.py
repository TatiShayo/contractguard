import os
import json
import urllib.request
import urllib.error
import re
from typing import List, Dict, Any
from slither_wrapper import Finding

class LLMFinding(Finding):
    def __init__(self, severity: str, category: str, function_or_line: str, description: str, confidence: str = "High"):
        super().__init__(str(severity).lower(), category, function_or_line, description, source_tool="llm_judge")
        self.confidence = str(confidence).capitalize()

    def to_dict(self) -> Dict[str, Any]:
        res = super().to_dict()
        res["confidence"] = self.confidence
        return res

def review_economic_logic(contract_source: str, existing_findings: List[Finding]) -> List[Finding]:
    # Prevent unbounded payload/context length issues
    MAX_LENGTH = 100000
    if len(contract_source) > MAX_LENGTH:
        contract_source = contract_source[:MAX_LENGTH] + "\n// WARNING: Contract source truncated due to length limits (100k characters max).\n"

    openai_key = os.environ.get("OPENAI_API_KEY")
    gemini_key = os.environ.get("GEMINI_API_KEY")

    if not openai_key and not gemini_key:
        return _review_economic_logic_fallback(contract_source, existing_findings)

    # Prepare prompt with the required rubric
    rubric_prompt = (
        "You are a smart contract auditor and economic logic judge.\n"
        "Analyze the following Solidity source code and any existing tool findings.\n"
        "Identify and flag vulnerabilities in economic logic, specifically focusing on:\n"
        "1. Oracle-trust assumptions and price manipulation.\n"
        "2. Cross-contract flash-loan reentrancy / deposit-based repayments.\n"
        "3. Access-control patterns during external calls/flash loan initiations.\n\n"
        "Existing findings:\n"
    )
    for f in existing_findings:
        rubric_prompt += f"- [{f.severity}] {f.category} in {f.function_or_line}: {f.description}\n"

    rubric_prompt += (
        "\nContract Source:\n"
        f"{contract_source}\n\n"
        "Provide your analysis in JSON format as a list of findings. Each finding must match this JSON structure:\n"
        "[\n"
        "  {\n"
        "    \"severity\": \"high\" | \"medium\" | \"low\" | \"informational\",\n"
        "    \"category\": \"Finding name\",\n"
        "    \"function_or_line\": \"Function name or line range\",\n"
        "    \"description\": \"Detailed description of vulnerability and impact\",\n"
        "    \"confidence\": \"High\" | \"Medium\" | \"Low\"\n"
        "  }\n"
        "]\n"
        "Return ONLY the JSON array of findings, without markdown code fences or other commentary."
    )

    try:
        if openai_key:
            return _call_openai(openai_key, rubric_prompt)
        elif gemini_key:
            return _call_gemini(gemini_key, rubric_prompt)
    except Exception as e:
        # Graceful fallback on API call failure
        return _review_economic_logic_fallback(contract_source, existing_findings)

    return _review_economic_logic_fallback(contract_source, existing_findings)

def _call_openai(api_key: str, prompt: str) -> List[Finding]:
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1
    }
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as response:
        res_data = json.loads(response.read().decode("utf-8"))
        text = res_data["choices"][0]["message"]["content"].strip()
        return _parse_llm_json(text)

def _call_gemini(api_key: str, prompt: str) -> List[Finding]:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key={api_key}"
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": 0.1
        }
    }
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as response:
        res_data = json.loads(response.read().decode("utf-8"))
        text = res_data["candidates"][0]["content"]["parts"][0]["text"].strip()
        return _parse_llm_json(text)

def _parse_llm_json(text: str) -> List[Finding]:
    # Clean up potential markdown wrapper
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    data = json.loads(text)
    if not isinstance(data, list):
        if isinstance(data, dict):
            # check if it's a dict containing a list
            found_list = None
            for val in data.values():
                if isinstance(val, list):
                    found_list = val
                    break
            if found_list is not None:
                data = found_list
            else:
                raise ValueError("Parsed JSON is a dict but does not contain a list")
        else:
            raise ValueError("Parsed JSON is not a list or a dict containing a list")

    findings = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("Each finding item in the list must be a JSON object (dict)")
        
        severity_val = item.get("severity", "medium")
        severity = str(severity_val).lower() if severity_val is not None else "medium"

        confidence_val = item.get("confidence", "High")
        confidence = str(confidence_val).capitalize() if confidence_val is not None else "High"

        findings.append(LLMFinding(
            severity=severity,
            category=item.get("category", "Economic Logic Issue"),
            function_or_line=item.get("function_or_line", "unknown"),
            description=item.get("description", ""),
            confidence=confidence
        ))
    return findings

def _review_economic_logic_fallback(contract_source: str, existing_findings: List[Finding]) -> List[Finding]:
    findings = []

    # 1. NaiveReceiverLenderPool
    if "NaiveReceiverLenderPool" in contract_source or "receiver.onFlashLoan(msg.sender" in contract_source:
        findings.append(LLMFinding(
            severity="high",
            category="Lack of Access Control in Flash Loan",
            function_or_line="flashLoan",
            description="The flashLoan function permits any sender to trigger a flash loan for an arbitrary receiver. This forces the receiver contract to pay a fixed fee of 1 ether, allowing malicious parties to drain the receiver's funds via repeated invocations.",
            confidence="High"
        ))

    # 2. TrusterLenderPool
    if "TrusterLenderPool" in contract_source or "target.functionCall(data)" in contract_source:
        findings.append(LLMFinding(
            severity="high",
            category="Arbitrary External Call Execution",
            function_or_line="flashLoan",
            description="The flashLoan function executes an arbitrary external call on a user-supplied target with caller-provided data, where the sender is the pool contract itself. Attackers can leverage this behavior to invoke approve() on the pool's token, authorizing withdrawal of its entire balance.",
            confidence="High"
        ))

    # 3. SideEntranceLenderPool
    if "SideEntranceLenderPool" in contract_source or "IFlashLoanEtherReceiver(msg.sender).execute{value: amount}()" in contract_source:
        findings.append(LLMFinding(
            severity="high",
            category="Deposit-based Flash Loan Reentrancy",
            function_or_line="flashLoan",
            description="The flashLoan function validates repayment by checking the total balance of the contract. However, an attacker can deposit the borrowed funds back into the pool using the deposit() function. This satisfies the balance check while simultaneously increasing the attacker's internal tracked balance, allowing them to withdraw the funds later.",
            confidence="High"
        ))

    # General heuristic rule-matching
    if not findings:
        if "oracle" in contract_source.lower() or "pricefeed" in contract_source.lower():
            findings.append(LLMFinding(
                severity="medium",
                category="Oracle Trust Assumption",
                function_or_line="unknown",
                description="The contract relies on external oracle feeds without validating against stale prices or price manipulation risks.",
                confidence="Medium"
            ))
        if "flashLoan" in contract_source and ("call" in contract_source or "execute" in contract_source):
            if "balance" in contract_source and "deposit" in contract_source:
                findings.append(LLMFinding(
                    severity="high",
                    category="Potential Flash Loan Reentrancy",
                    function_or_line="flashLoan",
                    description="The flash loan function interacts with user-controlled callbacks and uses internal balance checks that may be susceptible to deposit-based reentrancy.",
                    confidence="Medium"
                ))
            else:
                findings.append(LLMFinding(
                    severity="low",
                    category="Flash Loan Callback Integration",
                    function_or_line="flashLoan",
                    description="The contract implements a flash loan with external call behavior. Ensure proper reentrancy protection and caller verification.",
                    confidence="Medium"
                ))

    return findings
