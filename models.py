"""
ContractGuard Data Models and Severity Classifications.
Hermes v6 Engineering Standard compliant.
"""

from enum import Enum
from typing import Dict, Any, Optional, List, Union
import json
import re

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    INFO = "informational"

    @classmethod
    def from_str(cls, value: Union[str, "Severity", None]) -> "Severity":
        if isinstance(value, Severity):
            return value
        if not value:
            return cls.INFORMATIONAL
        val = str(value).strip().lower()
        if val in ("crit", "critical"):
            return cls.CRITICAL
        elif val in ("high", "h"):
            return cls.HIGH
        elif val in ("med", "medium", "m"):
            return cls.MEDIUM
        elif val in ("low", "l"):
            return cls.LOW
        elif val in ("info", "informational", "optimization", "opt", "none"):
            return cls.INFORMATIONAL
        return cls.INFORMATIONAL

    @property
    def score_penalty(self) -> int:
        penalties = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 0,
        }
        return penalties.get(self, 0)

    @property
    def sarif_level(self) -> str:
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        elif self == Severity.MEDIUM:
            return "warning"
        elif self == Severity.LOW:
            return "note"
        return "none"

    def _order_val(self, other: Any) -> tuple[int, int]:
        order = {
            Severity.INFORMATIONAL: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        self_val = order.get(self, 0)
        if isinstance(other, Severity):
            other_val = order.get(other, 0)
        elif isinstance(other, str):
            other_val = order.get(Severity.from_str(other), 0)
        else:
            other_val = 0
        return self_val, other_val

    def __ge__(self, other: Any) -> bool:
        s, o = self._order_val(other)
        return s >= o

    def __gt__(self, other: Any) -> bool:
        s, o = self._order_val(other)
        return s > o

    def __le__(self, other: Any) -> bool:
        s, o = self._order_val(other)
        return s <= o

    def __lt__(self, other: Any) -> bool:
        s, o = self._order_val(other)
        return s < o

class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

    @classmethod
    def from_str(cls, value: Union[str, "Confidence", None]) -> "Confidence":
        if isinstance(value, Confidence):
            return value
        if not value:
            return cls.HIGH
        val = str(value).strip().lower()
        if val in ("high", "h"):
            return cls.HIGH
        elif val in ("med", "medium", "m"):
            return cls.MEDIUM
        elif val in ("low", "l"):
            return cls.LOW
        return cls.HIGH

class Finding:
    """
    Standardized smart contract vulnerability finding.
    Compatible with Slither, Mythril, LLM-Judge, and AST Engine.
    """

    def __init__(
        self,
        severity: Union[str, Severity],
        category: str,
        function_or_line: str,
        description: str,
        source_tool: str = "slither",
        rule_id: Optional[str] = None,
        contract_name: Optional[str] = None,
        line_start: Optional[int] = None,
        line_end: Optional[int] = None,
        column_start: Optional[int] = None,
        column_end: Optional[int] = None,
        confidence: Union[str, Confidence] = Confidence.HIGH,
        cwe_id: Optional[str] = None,
        impact: Optional[str] = None,
        remediation: Optional[str] = None,
        code_snippet: Optional[str] = None,
        suppressed: bool = False,
    ):
        self.severity_enum: Severity = (
            severity if isinstance(severity, Severity) else Severity.from_str(str(severity))
        )
        self.severity: str = self.severity_enum.value
        self.category: str = category or "General Vulnerability"
        self.function_or_line: str = function_or_line or "unknown"
        self.description: str = description or ""
        self.source_tool: str = source_tool or "contractguard"
        self.rule_id: str = rule_id or self._derive_rule_id(category)
        self.contract_name: str = contract_name or "UnknownContract"
        self.confidence_enum: Confidence = (
            confidence if isinstance(confidence, Confidence) else Confidence.from_str(str(confidence))
        )
        self.confidence: str = self.confidence_enum.value
        self.cwe_id: str = cwe_id or self._derive_cwe(category)
        self.impact: str = impact or self._derive_impact(category, self.severity_enum)
        self.remediation: str = remediation or ""
        self.code_snippet: Optional[str] = code_snippet
        self.suppressed: bool = suppressed

        if line_start is None or line_end is None:
            parsed_start, parsed_end = self._parse_line_numbers(self.function_or_line)
            self.line_start: Optional[int] = line_start if line_start is not None else parsed_start
            self.line_end: Optional[int] = line_end if line_end is not None else parsed_end
        else:
            self.line_start = line_start
            self.line_end = line_end

        self.column_start: Optional[int] = column_start
        self.column_end: Optional[int] = column_end

    @staticmethod
    def _parse_line_numbers(text: str) -> tuple[Optional[int], Optional[int]]:
        if not text:
            return None, None
        # match patterns like "(lines 15-23)" or "Line 15" or "lines 15 to 23" or "line: 15" or "L15-L23" or "15..23"
        match_l_range = re.search(r"\bL(\d+)\s*[-–—to\.]+\s*L?(\d+)\b", text, re.IGNORECASE)
        if match_l_range:
            return int(match_l_range.group(1)), int(match_l_range.group(2))
        match_l_single = re.search(r"\bL(\d+)\b", text, re.IGNORECASE)
        if match_l_single:
            line = int(match_l_single.group(1))
            return line, line
        match_range = re.search(r"\blines?\s*[:#-]?\s*(\d+)\s*[-–—to\.]+\s*[:#-]?\s*(\d+)\b", text, re.IGNORECASE)
        if match_range:
            return int(match_range.group(1)), int(match_range.group(2))
        match_single = re.search(r"\blines?\s*[:#-]?\s*(\d+)\b", text, re.IGNORECASE)
        if match_single:
            line = int(match_single.group(1))
            return line, line
        match_dot_range = re.search(r"\b(\d+)\s*\.{2,}\s*(\d+)\b", text)
        if match_dot_range:
            return int(match_dot_range.group(1)), int(match_dot_range.group(2))
        match_paren = re.search(r"\(\s*(?:lines?\s*)?(\d+)\s*[-–—to\.]+\s*(\d+)\s*\)", text, re.IGNORECASE)
        if match_paren:
            return int(match_paren.group(1)), int(match_paren.group(2))
        match_paren_single = re.search(r"\(\s*(?:lines?\s*)?(\d+)\s*\)", text, re.IGNORECASE)
        if match_paren_single:
            line = int(match_paren_single.group(1))
            return line, line
        return None, None

    @staticmethod
    def _derive_rule_id(category: str) -> str:
        cat = (category or "").lower()
        if "selfdestruct" in cat or "suicide" in cat:
            return "CG-010-SELFDESTRUCT"
        elif "flash loan" in cat and ("deposit" in cat or "reentrancy" in cat):
            if "deposit" in cat:
                return "CG-007-FLASHLOAN-DEPOSIT-REENTRANCY"
            return "CG-008-FLASHLOAN-ACCESS-CONTROL"
        elif "flash loan" in cat or "flashloan" in cat:
            return "CG-008-FLASHLOAN-ACCESS-CONTROL"
        elif "read-only reentrancy" in cat or "readonly reentrancy" in cat:
            return "CG-020-READ-ONLY-REENTRANCY"
        elif "reentrancy" in cat or "state access" in cat:
            return "CG-001-REENTRANCY"
        elif "origin" in cat or "tx-origin" in cat:
            return "CG-002-TX-ORIGIN"
        elif "delegatecall" in cat:
            return "CG-003-CONTROLLED-DELEGATECALL"
        elif "overflow" in cat or "underflow" in cat:
            return "CG-011-INTEGER-OVERFLOW"
        elif "unchecked" in cat and ("erc20" in cat or "token" in cat or "safetransfer" in cat):
            return "CG-021-UNCHECKED-ERC20-TRANSFER"
        elif "unchecked" in cat:
            return "CG-004-UNCHECKED-CALL"
        elif "initialize" in cat or "init" in cat:
            return "CG-013-UNPROTECTED-INITIALIZE"
        elif "mint" in cat and ("unprotected" in cat or "access" in cat):
            return "CG-022-UNPROTECTED-MINT"
        elif "zero" in cat or "missing-zero-check" in cat:
            return "CG-014-MISSING-ZERO-CHECK"
        elif "arbitrary" in cat or "external call" in cat:
            if "eth" in cat or "ether" in cat:
                return "CG-015-ARBITRARY-SEND-ETH"
            return "CG-006-ARBITRARY-CALL"
        elif "random" in cat or "prng" in cat or "timestamp" in cat or "weak-prng" in cat:
            return "CG-019-WEAK-PRNG"
        elif "signature" in cat or "replay" in cat or "ecrecover" in cat:
            return "CG-018-SIGNATURE-REPLAY"
        elif "oracle" in cat or "price" in cat:
            return "CG-009-PRICE-ORACLE-MANIPULATION"
        elif "useless" in cat or "dead" in cat:
            return "CG-012-USELESS-STATEMENT"
        elif "uninitialized" in cat or "storage" in cat:
            return "CG-016-UNINITIALIZED-STORAGE"
        elif "pragma" in cat or "solc" in cat:
            return "CG-017-FLOATING-PRAGMA"
        elif "access control" in cat or "unprotected" in cat or "owner" in cat:
            return "CG-005-ACCESS-CONTROL"
        return "CG-999-GENERIC"

    @staticmethod
    def _derive_cwe(category: str) -> str:
        cat = (category or "").lower()
        if "reentrancy" in cat or "state access" in cat or "deposit" in cat:
            return "CWE-841"  # Improper Enforcement of Behavioral Workflow
        elif "origin" in cat:
            return "CWE-284"  # Improper Access Control / tx.origin
        elif "delegatecall" in cat:
            return "CWE-829"  # Inclusion of Functionality from Untrusted Control Sphere
        elif "unchecked" in cat:
            return "CWE-252"  # Unchecked Return Value
        elif "access control" in cat or "owner" in cat or "initialize" in cat or "mint" in cat:
            return "CWE-284"  # Improper Access Control
        elif "arbitrary" in cat or "external call" in cat:
            return "CWE-841"
        elif "oracle" in cat or "price" in cat:
            return "CWE-682"  # Incorrect Calculation
        elif "selfdestruct" in cat or "suicide" in cat:
            return "CWE-284"
        elif "overflow" in cat or "underflow" in cat:
            return "CWE-190"  # Integer Overflow or Wraparound
        elif "random" in cat or "prng" in cat:
            return "CWE-330"  # Use of Insufficiently Random Values
        elif "signature" in cat or "replay" in cat:
            return "CWE-347"  # Improper Verification of Cryptographic Signature
        elif "useless" in cat or "dead" in cat:
            return "CWE-561"  # Dead Code
        elif "zero" in cat:
            return "CWE-20"   # Improper Input Validation
        return "CWE-693"  # Protection Mechanism Failure

    @staticmethod
    def _derive_impact(category: str, severity: Severity) -> str:
        cat = (category or "").lower()
        if "reentrancy" in cat:
            return "Attacker can drain contract funds via recursive reentrant callbacks before state updates."
        elif "origin" in cat:
            return "Attacker can trick authorized users into executing state changes via malicious intermediary contracts."
        elif "delegatecall" in cat:
            return "Attacker can overwrite contract storage variables or hijack contract ownership."
        elif "unchecked" in cat:
            return "Silent call failures may leave contract state inconsistent or trap tokens."
        elif "initialize" in cat:
            return "Attacker can re-initialize contract state, taking total control of contract administrative roles."
        elif "zero" in cat:
            return "Setting critical state variables to zero address can permanently lock contract ownership or funds."
        elif "access control" in cat:
            return "Unauthorized users can invoke administrative operations or withdraw funds."
        elif "mint" in cat:
            return "Unauthorized users can mint arbitrary token balances, destroying token economics."
        elif "arbitrary" in cat:
            return "Attacker can execute arbitrary logic in contract context, leading to token theft or approval drain."
        elif "deposit" in cat and "flash loan" in cat:
            return "Attacker can borrow flash funds, deposit them to credit internal balance, pass repayment check, and withdraw."
        elif "flash loan" in cat:
            return "Attacker can trigger fee charges against victim contracts or drain flash borrower funds."
        elif "oracle" in cat:
            return "Attacker can manipulate spot prices via flash swaps to liquidate positions or drain lending pools."
        elif "random" in cat or "prng" in cat:
            return "Miners/validators or attackers can predict random numbers and manipulate game or lottery outcomes."
        elif "signature" in cat or "replay" in cat:
            return "Attackers can reuse valid signatures across different transactions, chains, or contracts."
        elif "selfdestruct" in cat or "suicide" in cat:
            return "Contract code and state can be irreversibly destroyed, freezing or losing assets."
        elif "overflow" in cat:
            return "Unintended numeric wrap-around can result in arithmetic bypasses or arbitrary token minting."
        elif "useless" in cat:
            return "Dead statement wastes gas and harms code readability."
        return f"{severity.value.capitalize()} severity security vulnerability."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.rule_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "function_or_line": self.function_or_line,
            "contract_name": self.contract_name,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "column_start": self.column_start,
            "column_end": self.column_end,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "confidence": self.confidence,
            "source_tool": self.source_tool,
            "code_snippet": self.code_snippet,
            "suppressed": self.suppressed,
        }

    def to_sarif_result(self, uri: str = "") -> Dict[str, Any]:
        level = self.severity_enum.sarif_level
        start_line = max(1, self.line_start) if self.line_start and self.line_start > 0 else 1
        end_line = max(start_line, self.line_end) if self.line_end and self.line_end > 0 else start_line

        artifact_uri = (uri or self.contract_name or "Contract.sol").replace("\\", "/")

        return {
            "ruleId": self.rule_id,
            "level": level,
            "message": {
                "text": f"[{self.severity.upper()}] {self.category}: {self.description}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": artifact_uri,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": start_line,
                            "endLine": end_line,
                            "startColumn": max(1, self.column_start) if self.column_start else 1,
                            "endColumn": max(1, self.column_end) if self.column_end else 80,
                            "snippet": {
                                "text": self.code_snippet or ""
                            }
                        }
                    }
                }
            ],
            "properties": {
                "cwe": self.cwe_id,
                "confidence": self.confidence,
                "sourceTool": self.source_tool,
                "impact": self.impact,
                "remediation": self.remediation,
            }
        }

    def __repr__(self) -> str:
        return (
            f"Finding(rule_id={self.rule_id!r}, severity={self.severity!r}, "
            f"category={self.category!r}, function_or_line={self.function_or_line!r}, "
            f"source_tool={self.source_tool!r})"
        )

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Finding):
            return False
        return (
            self.rule_id == other.rule_id
            and self.category == other.category
            and self.function_or_line == other.function_or_line
            and self.severity == other.severity
        )

    def __hash__(self) -> int:
        return hash((self.rule_id, self.category, self.function_or_line, self.severity))
