"""
ContractGuard Standalone Solidity AST & Static Analysis Engine.
Implements precision lexical and AST-based vulnerability detectors for Solidity.
Zero external runtime dependencies.
Hermes v6 Engineering Standard compliant.
"""

import os
import re
from typing import List, Dict, Any, Optional, Set, Tuple
from models import Finding, Severity, Confidence
from rules import RULES_REGISTRY, get_rule_by_id

def _find_matching_brace(source: str, open_brace_idx: int) -> int:
    """
    Find index of matching closing brace '}' in Solidity source code,
    safely handling comments (// and /* */) and string literals ("" and '').
    """
    if open_brace_idx < 0 or open_brace_idx >= len(source) or source[open_brace_idx] != '{':
        return len(source)

    depth = 0
    i = open_brace_idx
    n = len(source)

    in_single_line_comment = False
    in_multi_line_comment = False
    in_double_quote = False
    in_single_quote = False

    while i < n:
        char = source[i]

        # Check escape sequence inside strings
        if (in_double_quote or in_single_quote) and char == '\\':
            i += 2
            continue

        if in_single_line_comment:
            if char == '\n':
                in_single_line_comment = False
            i += 1
            continue

        if in_multi_line_comment:
            if char == '*' and i + 1 < n and source[i + 1] == '/':
                in_multi_line_comment = False
                i += 2
                continue
            i += 1
            continue

        if in_double_quote:
            if char == '"':
                in_double_quote = False
            i += 1
            continue

        if in_single_quote:
            if char == "'":
                in_single_quote = False
            i += 1
            continue

        # Check start of comments or strings
        if char == '/' and i + 1 < n:
            if source[i + 1] == '/':
                in_single_line_comment = True
                i += 2
                continue
            elif source[i + 1] == '*':
                in_multi_line_comment = True
                i += 2
                continue

        if char == '"':
            in_double_quote = True
            i += 1
            continue

        if char == "'":
            in_single_quote = True
            i += 1
            continue

        if char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                return i

        i += 1

    return len(source)

class SolidityFunction:
    def __init__(
        self,
        name: str,
        contract_name: str,
        start_line: int,
        end_line: int,
        visibility: str = "public",
        modifiers: Optional[List[str]] = None,
        params: Optional[List[str]] = None,
        returns: Optional[List[str]] = None,
        body: str = "",
        raw_signature: str = "",
        is_constructor: bool = False,
        is_fallback: bool = False,
        is_receive: bool = False,
        is_modifier: bool = False,
    ):
        self.name = name
        self.contract_name = contract_name
        self.start_line = start_line
        self.end_line = end_line
        self.visibility = visibility
        self.modifiers = modifiers or []
        self.params = params or []
        self.returns = returns or []
        self.body = body
        self.raw_signature = raw_signature
        self.is_constructor = is_constructor
        self.is_fallback = is_fallback
        self.is_receive = is_receive
        self.is_modifier = is_modifier

    @property
    def has_non_reentrant_guard(self) -> bool:
        guards = {
            "nonreentrant", "reentrancyguard", "lock", "non_reentrant", "mutex",
            "guarded", "noreentrancy", "nonreentrantview", "whennotpaused"
        }
        for mod in self.modifiers:
            mod_clean = mod.lower().split("(")[0].strip()
            if mod_clean in guards or "reentrant" in mod_clean or "lock" in mod_clean or "mutex" in mod_clean:
                return True
        return False

    @property
    def has_owner_or_auth_modifier(self) -> bool:
        auth_mods = {
            "onlyowner", "onlyrole", "onlyadmin", "auth", "authorized",
            "onlygovernance", "onlymanager", "only_owner", "only_admin",
            "requiresauth", "onlyminter", "onlyvault"
        }
        for mod in self.modifiers:
            mod_clean = mod.lower().split("(")[0].strip()
            if (
                mod_clean in auth_mods
                or "owner" in mod_clean
                or "role" in mod_clean
                or "auth" in mod_clean
                or "admin" in mod_clean
                or "minter" in mod_clean
                or "gov" in mod_clean
            ):
                return True
        return False

class SolidityContract:
    def __init__(
        self,
        name: str,
        start_line: int,
        end_line: int,
        kind: str = "contract",
        bases: Optional[List[str]] = None,
        body: str = "",
        start_pos: int = 0,
        end_pos: int = 0,
        body_start_pos: int = 0,
    ):
        self.name = name
        self.start_line = start_line
        self.end_line = end_line
        self.kind = kind  # contract, interface, library, abstract contract
        self.bases = bases or []
        self.body = body
        self.start_pos = start_pos
        self.end_pos = end_pos
        self.body_start_pos = body_start_pos
        self.functions: List[SolidityFunction] = []
        self.state_vars: List[Dict[str, Any]] = []
        self.events: List[str] = []
        self.modifiers_defined: List[str] = []

class ASTAnalyzer:
    """
    Precision Solidity Static & AST Analysis Engine.
    """

    def __init__(self):
        self.rules = RULES_REGISTRY

    def analyze_source(self, source_code: str, file_path: str = "") -> List[Finding]:
        if not source_code or not source_code.strip():
            return []

        if len(source_code) > 10_000_000:
            source_code = source_code[:10_000_000]

        lines = source_code.splitlines()
        contract_name = self._guess_primary_contract_name(source_code, file_path)

        suppressed_rules_by_line = self._parse_suppressions(lines)

        contracts = self._parse_contracts(source_code, lines)

        findings: List[Finding] = []

        for contract in contracts:
            findings.extend(self._detect_reentrancy(contract, lines))

            findings.extend(self._detect_tx_origin(contract, lines))

            findings.extend(self._detect_controlled_delegatecall(contract, lines))

            findings.extend(self._detect_unchecked_calls(contract, lines))

            findings.extend(self._detect_missing_access_control(contract, lines))

            findings.extend(self._detect_arbitrary_calls(contract, lines))

            findings.extend(self._detect_flashloan_deposit_reentrancy(contract, lines))

            findings.extend(self._detect_flashloan_access_control(contract, lines))

            findings.extend(self._detect_oracle_manipulation(contract, lines))

            findings.extend(self._detect_selfdestruct(contract, lines))

            findings.extend(self._detect_integer_overflow(contract, lines))

            findings.extend(self._detect_useless_statements(contract, lines))

            findings.extend(self._detect_unprotected_initialize(contract, lines))

            findings.extend(self._detect_missing_zero_check(contract, lines))

            findings.extend(self._detect_arbitrary_eth_transfer(contract, lines))

            findings.extend(self._detect_uninitialized_storage(contract, lines))

            findings.extend(self._detect_signature_replay(contract, lines))

            findings.extend(self._detect_weak_prng(contract, lines))

            findings.extend(self._detect_read_only_reentrancy(contract, lines))

            findings.extend(self._detect_unchecked_erc20_transfer(contract, lines))

            findings.extend(self._detect_unprotected_mint(contract, lines))

        findings.extend(self._detect_floating_pragma(source_code, lines, contract_name))

        # Filter out suppressed findings
        active_findings: List[Finding] = []
        for f in findings:
            if not f.contract_name or f.contract_name == "UnknownContract":
                f.contract_name = contract_name

            target_line = f.line_start or 1
            suppressed = False

            candidate_lines = [target_line, target_line - 1]
            for c_line in candidate_lines:
                if c_line in suppressed_rules_by_line:
                    suppressed_rules = suppressed_rules_by_line[c_line]
                    rule_id_lower = f.rule_id.lower()
                    aliases_lower = [a.lower() for a in self._get_rule_aliases(f.rule_id)]
                    if "all" in suppressed_rules or rule_id_lower in suppressed_rules or any(a in suppressed_rules for a in aliases_lower):
                        suppressed = True
                        break

            f.suppressed = suppressed
            if not suppressed:
                active_findings.append(f)

        return active_findings

    def _get_rule_aliases(self, rule_id: str) -> List[str]:
        rule = get_rule_by_id(rule_id)
        if not rule:
            return []
        aliases = [rule_id.lower()]
        for a in rule.get("slither_alias", []):
            aliases.append(a.lower())
        for a in rule.get("mythril_alias", []):
            aliases.append(a.lower())
        return aliases

    def _parse_suppressions(self, lines: List[str]) -> Dict[int, Set[str]]:
        suppressions: Dict[int, Set[str]] = {}
        for idx, line in enumerate(lines):
            line_num = idx + 1
            match = re.search(r"//\s*(?:contractguard|slither)[:\-](?:disable-next-line|disable)\s*(.*)", line, re.IGNORECASE)
            if match:
                rules_str = match.group(1).strip()
                target_rules = set()
                if not rules_str:
                    target_rules.add("all")
                else:
                    for r in re.split(r"[,;\s]+", rules_str):
                        r_clean = r.strip().lower()
                        if r_clean:
                            target_rules.add(r_clean)
                suppressions[line_num] = target_rules
        return suppressions

    def _guess_primary_contract_name(self, source: str, file_path: str) -> str:
        if file_path:
            base = os.path.basename(file_path)
            if base.endswith(".sol"):
                return base[:-4]
        match = re.search(r"(?:contract|interface|library)\s+([a-zA-Z0-9_]+)", source)
        if match:
            return match.group(1)
        return "UnknownContract"

    def _parse_contracts(self, source: str, lines: List[str]) -> List[SolidityContract]:
        contracts: List[SolidityContract] = []

        contract_pattern = re.compile(
            r"(contract|interface|library|abstract\s+contract)\s+([a-zA-Z0-9_]+)(?:\s+is\s+([^{]+))?\s*\{",
            re.MULTILINE
        )

        for match in contract_pattern.finditer(source):
            kind = match.group(1).strip()
            name = match.group(2).strip()
            bases_str = match.group(3) or ""
            bases = [b.strip() for b in bases_str.split(",") if b.strip()]

            start_pos = match.start()
            start_line = source.count("\n", 0, start_pos) + 1

            brace_idx = match.end() - 1
            end_pos = _find_matching_brace(source, brace_idx)
            end_line = source.count("\n", 0, end_pos) + 1
            contract_body = source[brace_idx + 1:end_pos]

            contract = SolidityContract(
                name=name,
                start_line=start_line,
                end_line=end_line,
                kind=kind,
                bases=bases,
                body=contract_body,
                start_pos=start_pos,
                end_pos=end_pos,
                body_start_pos=brace_idx + 1,
            )

            contract.functions = self._parse_functions(contract, source, lines)
            contracts.append(contract)

        if not contracts:
            dummy = SolidityContract(
                name=self._guess_primary_contract_name(source, ""),
                start_line=1,
                end_line=len(lines),
                body=source,
                start_pos=0,
                end_pos=len(source),
                body_start_pos=0,
            )
            dummy.functions = self._parse_functions(dummy, source, lines)
            contracts.append(dummy)

        return contracts

    def _parse_functions(self, contract: SolidityContract, full_source: str, lines: List[str]) -> List[SolidityFunction]:
        functions: List[SolidityFunction] = []
        body = contract.body

        func_pattern = re.compile(
            r"(function\s+([a-zA-Z0-9_]+)|modifier\s+([a-zA-Z0-9_]+)|constructor|fallback|receive)\s*(?:\((.*?)\))?\s*([^{;]*?)(?:\{|;)",
            re.DOTALL
        )

        for match in func_pattern.finditer(body):
            header = match.group(0)
            full_match_start_in_body = match.start()
            contract_body_start_pos = contract.body_start_pos if contract.body_start_pos > 0 else (full_source.find(body, 0) if body in full_source else 0)
            abs_start_pos = contract_body_start_pos + full_match_start_in_body

            start_line = full_source.count("\n", 0, abs_start_pos) + 1

            if header.strip().endswith(";"):
                continue

            decl_type = match.group(1)
            raw_name = match.group(2)
            modifier_name = match.group(3)
            is_constructor = "constructor" in decl_type
            is_fallback = "fallback" in decl_type
            is_receive = "receive" in decl_type
            is_modifier = "modifier" in decl_type

            if is_constructor:
                func_name = "constructor"
            elif is_fallback:
                func_name = "fallback"
            elif is_receive:
                func_name = "receive"
            elif is_modifier:
                func_name = modifier_name or "custom_modifier"
            else:
                func_name = raw_name or "anonymous"

            params_str = match.group(4) or ""
            params = [p.strip() for p in params_str.split(",") if p.strip()]

            qualifiers_str = match.group(5) or ""
            qualifiers = qualifiers_str.split()

            visibility = "modifier" if is_modifier else "public"
            for v in ["public", "external", "internal", "private"]:
                if v in qualifiers:
                    visibility = v
                    break

            modifiers = []
            for token in qualifiers:
                if token not in ["public", "external", "internal", "private", "view", "pure", "payable", "override", "virtual"]:
                    modifiers.append(token)

            brace_pos_in_body = full_match_start_in_body + len(header) - 1
            body_end_in_body = _find_matching_brace(body, brace_pos_in_body)

            func_body = body[brace_pos_in_body + 1:body_end_in_body]
            abs_end_pos = contract_body_start_pos + body_end_in_body
            end_line = full_source.count("\n", 0, abs_end_pos) + 1

            functions.append(SolidityFunction(
                name=func_name,
                contract_name=contract.name,
                start_line=start_line,
                end_line=end_line,
                visibility=visibility,
                modifiers=modifiers,
                params=params,
                body=func_body,
                raw_signature=header,
                is_constructor=is_constructor,
                is_fallback=is_fallback,
                is_receive=is_receive,
                is_modifier=is_modifier,
            ))

        return functions

    # DETECTOR 1: Reentrancy (CWE-841)
    def _detect_reentrancy(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-001-REENTRANCY"]

        for func in contract.functions:
            body = func.body
            if not body:
                continue

            # Look for external calls
            call_matches = list(re.finditer(
                r"((?:\b[a-zA-Z0-9_\.]+|\bpayable\s*\([^)]*\))\s*\.\s*(?:call\s*\{[^}]*\}|call\s*\.\s*value\s*\([^)]*\)|transfer\s*\([^)]*\)|send\s*\([^)]*\)|call\s*\([^)]*\)))",
                body
            ))

            if not call_matches:
                continue

            if func.has_non_reentrant_guard:
                continue

            for call_m in call_matches:
                call_pos = call_m.end()
                subsequent_body = body[call_pos:]

                # Check for state mutations, mapping updates, arithmetic assignments, delete, or array mutations
                state_mutations = re.findall(
                    r"(?:delete\s+[a-zA-Z0-9_]+(?:\s*\[[^\]]+\])*|\b[a-zA-Z0-9_]+(?:\s*\[[^\]]+\])*\s*(?:\-=|\+=|\*=|\/=|=(?!=)|\.push\s*\(|\.pop\s*\())",
                    subsequent_body
                )

                true_mutations = []
                for mut in state_mutations:
                    # Ignore local declarations
                    if not re.search(r"^\s*(?:bool|uint\d*|int\d*|address|bytes\d*|string)\s+", mut.strip()):
                        true_mutations.append(mut.strip())

                if true_mutations:
                    snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                    findings.append(Finding(
                        severity=rule["default_severity"],
                        category="Reentrancy / State access after external call",
                        function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                        description=(
                            f"In contract '{contract.name}', function '{func.name}' performs an external call "
                            f"before updating persistent state ({', '.join(true_mutations[:2])}). "
                            "An attacker can reenter this function before balances are deducted."
                        ),
                        source_tool="ast_analyzer",
                        rule_id=rule["rule_id"],
                        contract_name=contract.name,
                        line_start=func.start_line,
                        line_end=func.end_line,
                        confidence=Confidence.HIGH,
                        cwe_id=rule["cwe"],
                        impact=rule["impact"],
                        remediation=rule["remediation"],
                        code_snippet="\n".join(snippet[:10])
                    ))
                    break

        return findings

    # DETECTOR 2: tx.origin Authentication (CWE-284)
    def _detect_tx_origin(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-002-TX-ORIGIN"]

        for func in contract.functions:
            body = func.body
            if "tx.origin" in body:
                match = re.search(r"(?:require|if|assert)\s*\([^)]*tx\.origin[^)]*\)|(?:tx\.origin\s*==|==\s*tx\.origin|tx\.origin\s*!=|!=\s*tx\.origin)", body)
                if match:
                    snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                    findings.append(Finding(
                        severity=rule["default_severity"],
                        category="Use of tx.origin",
                        function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                        description=(
                            f"Function '{func.name}' in contract '{contract.name}' uses 'tx.origin' for authorization. "
                            "An attacker can exploit this via phishing or malicious proxy contracts to impersonate the user."
                        ),
                        source_tool="ast_analyzer",
                        rule_id=rule["rule_id"],
                        contract_name=contract.name,
                        line_start=func.start_line,
                        line_end=func.end_line,
                        confidence=Confidence.HIGH,
                        cwe_id=rule["cwe"],
                        impact=rule["impact"],
                        remediation=rule["remediation"],
                        code_snippet="\n".join(snippet[:10])
                    ))

        return findings

    # DETECTOR 3: Controlled / Arbitrary Delegatecall (CWE-829)
    def _detect_controlled_delegatecall(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-003-CONTROLLED-DELEGATECALL"]

        for func in contract.functions:
            body = func.body
            if "delegatecall" in body:
                if (func.visibility in ("public", "external") or func.is_fallback) and not func.has_owner_or_auth_modifier:
                    snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                    findings.append(Finding(
                        severity=rule["default_severity"],
                        category="Controlled delegatecall / Delegatecall to user-supplied address",
                        function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                        description=(
                            f"Function '{func.name}' in contract '{contract.name}' executes delegatecall "
                            "in an unauthenticated public/fallback context, exposing storage slots and ownership to takeover."
                        ),
                        source_tool="ast_analyzer",
                        rule_id=rule["rule_id"],
                        contract_name=contract.name,
                        line_start=func.start_line,
                        line_end=func.end_line,
                        confidence=Confidence.HIGH,
                        cwe_id=rule["cwe"],
                        impact=rule["impact"],
                        remediation=rule["remediation"],
                        code_snippet="\n".join(snippet[:10])
                    ))

        return findings

    # DETECTOR 4: Unchecked Low-Level Calls (CWE-252)
    def _detect_unchecked_calls(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-004-UNCHECKED-CALL"]

        for func in contract.functions:
            body = func.body
            statements = body.split(";")
            for stmt in statements:
                stmt_clean = stmt.strip()
                if re.search(r"\.\s*(?:call|delegatecall|send|staticcall)\s*(?:\{|\()", stmt_clean):
                    if "SafeTransferLib" in stmt_clean or "safeTransfer" in stmt_clean:
                        continue
                    is_assigned = bool(re.search(r"(?:(?:bool|\(bool)[^=]*=)", stmt_clean))
                    is_in_require = bool(re.search(r"(?:require|if|assert)\s*\(", stmt_clean))
                    if not is_assigned and not is_in_require:
                        snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                        findings.append(Finding(
                            severity=rule["default_severity"],
                            category="Unchecked Low-Level Call Return Value",
                            function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                            description=(
                                f"Function '{func.name}' in contract '{contract.name}' makes a low-level call without checking "
                                "the success return value, causing silent failures to go undetected."
                            ),
                            source_tool="ast_analyzer",
                            rule_id=rule["rule_id"],
                            contract_name=contract.name,
                            line_start=func.start_line,
                            line_end=func.end_line,
                            confidence=Confidence.MEDIUM,
                            cwe_id=rule["cwe"],
                            impact=rule["impact"],
                            remediation=rule["remediation"],
                            code_snippet=stmt_clean
                        ))

        return findings

    # DETECTOR 5: Missing Access Control on Sensitive Functions (CWE-284)
    def _detect_missing_access_control(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-005-ACCESS-CONTROL"]
        sensitive_names = {
            "pwn", "setowner", "transferownership", "changeowner", "kill", "destroy",
            "emergencywithdraw", "drain", "setfee", "updateadmin", "pause", "unpause",
            "setimplementation", "upgradeto"
        }

        for func in contract.functions:
            fname_lower = func.name.lower()
            if fname_lower in sensitive_names or any(s in fname_lower for s in ["setowner", "changeowner", "transferownership"]):
                if func.visibility in ("public", "external") and not func.has_owner_or_auth_modifier:
                    if not re.search(r"require\s*\(\s*msg\.sender\s*==|if\s*\(\s*msg\.sender\s*!=|assert\s*\(\s*msg\.sender\s*==", func.body):
                        snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                        findings.append(Finding(
                            severity=rule["default_severity"],
                            category="Missing Access Control on Sensitive Function",
                            function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                            description=(
                                f"Sensitive function '{func.name}' in contract '{contract.name}' is publicly accessible without "
                                "access control modifiers (e.g. onlyOwner) or caller validation checks."
                            ),
                            source_tool="ast_analyzer",
                            rule_id=rule["rule_id"],
                            contract_name=contract.name,
                            line_start=func.start_line,
                            line_end=func.end_line,
                            confidence=Confidence.HIGH,
                            cwe_id=rule["cwe"],
                            impact=rule["impact"],
                            remediation=rule["remediation"],
                            code_snippet="\n".join(snippet[:10])
                        ))

        return findings

    # DETECTOR 6: Arbitrary External Call (CWE-841) - Truster Pattern
    def _detect_arbitrary_calls(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-006-ARBITRARY-CALL"]

        for func in contract.functions:
            body = func.body
            if re.search(r"(?:target\s*\.\s*(?:functionCall|call)\s*\(\s*(?:data|calldata)[\s,\)]|\baddress\s*\(\s*target\s*\)\s*\.\s*call\s*\()", body):
                snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                findings.append(Finding(
                    severity=rule["default_severity"],
                    category="Arbitrary External Call Execution",
                    function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                    description=(
                        f"Function '{func.name}' in contract '{contract.name}' executes an arbitrary external call on a "
                        "caller-supplied target address with arbitrary calldata in the pool's context."
                    ),
                    source_tool="ast_analyzer",
                    rule_id=rule["rule_id"],
                    contract_name=contract.name,
                    line_start=func.start_line,
                    line_end=func.end_line,
                    confidence=Confidence.HIGH,
                    cwe_id=rule["cwe"],
                    impact=rule["impact"],
                    remediation=rule["remediation"],
                    code_snippet="\n".join(snippet[:10])
                ))

        return findings

    # DETECTOR 7: Flash Loan Deposit Reentrancy (CWE-841) - SideEntrance Pattern
    def _detect_flashloan_deposit_reentrancy(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-007-FLASHLOAN-DEPOSIT-REENTRANCY"]

        has_deposit = any(f.name == "deposit" for f in contract.functions)
        has_flash_loan = any("flashloan" in f.name.lower() for f in contract.functions)

        if has_deposit and has_flash_loan:
            for func in contract.functions:
                if "flashloan" in func.name.lower():
                    body = func.body
                    if re.search(r"(?:address\s*\(\s*this\s*\)\s*\.\s*balance|\.balanceOf\s*\()\s*<\s*balanceBefore", body) or "balanceBefore" in body:
                        snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                        findings.append(Finding(
                            severity=rule["default_severity"],
                            category="Deposit-based Flash Loan Reentrancy",
                            function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                            description=(
                                f"Contract '{contract.name}' allows borrowers to deposit borrowed flash loan funds back into the pool via deposit(), "
                                "satisfying the pool balance check while simultaneously increasing the borrower's withdrawable balance."
                            ),
                            source_tool="ast_analyzer",
                            rule_id=rule["rule_id"],
                            contract_name=contract.name,
                            line_start=func.start_line,
                            line_end=func.end_line,
                            confidence=Confidence.HIGH,
                            cwe_id=rule["cwe"],
                            impact=rule["impact"],
                            remediation=rule["remediation"],
                            code_snippet="\n".join(snippet[:10])
                        ))

        return findings

    # DETECTOR 8: Flash Loan Access Control (CWE-284) - NaiveReceiver Pattern
    def _detect_flashloan_access_control(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-008-FLASHLOAN-ACCESS-CONTROL"]

        for func in contract.functions:
            if "flashloan" in func.name.lower():
                body = func.body
                has_receiver_param = any("receiver" in p.lower() for p in func.params)
                has_fixed_fee = "fee" in body.lower() or "fixed_fee" in body.lower()
                has_caller_check = "msg.sender == address(receiver)" in body or "msg.sender == receiver" in body

                if has_receiver_param and has_fixed_fee and not has_caller_check:
                    snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                    findings.append(Finding(
                        severity=rule["default_severity"],
                        category="Lack of Access Control in Flash Loan",
                        function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                        description=(
                            f"Function '{func.name}' in contract '{contract.name}' allows any external caller to trigger a flash loan on "
                            "behalf of an arbitrary receiver contract, forcing the receiver to incur loan fees."
                        ),
                        source_tool="ast_analyzer",
                        rule_id=rule["rule_id"],
                        contract_name=contract.name,
                        line_start=func.start_line,
                        line_end=func.end_line,
                        confidence=Confidence.HIGH,
                        cwe_id=rule["cwe"],
                        impact=rule["impact"],
                        remediation=rule["remediation"],
                        code_snippet="\n".join(snippet[:10])
                    ))

        return findings

    # DETECTOR 9: Spot Price / Oracle Manipulation (CWE-682)
    def _detect_oracle_manipulation(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-009-PRICE-ORACLE-MANIPULATION"]
        body = contract.body

        if re.search(r"\b(?:getReserves\s*\(|slot0\s*\(|balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)\s*\/\s*totalSupply)", body):
            if "twap" not in body.lower() and "consult" not in body.lower() and "latestrounddata" not in body.lower():
                snippet = lines[contract.start_line - 1:min(contract.end_line, contract.start_line + 15)]
                findings.append(Finding(
                    severity=rule["default_severity"],
                    category="Spot Price Oracle Manipulation",
                    function_or_line=f"{contract.name} (lines {contract.start_line}-{contract.end_line})",
                    description=(
                        f"Contract '{contract.name}' references spot AMM pool reserves or instantaneous token balances "
                        "which can be manipulated within a single transaction using flash loans or swaps."
                    ),
                    source_tool="ast_analyzer",
                    rule_id=rule["rule_id"],
                    contract_name=contract.name,
                    line_start=contract.start_line,
                    line_end=contract.end_line,
                    confidence=Confidence.MEDIUM,
                    cwe_id=rule["cwe"],
                    impact=rule["impact"],
                    remediation=rule["remediation"],
                    code_snippet="\n".join(snippet[:10])
                ))

        return findings

    # DETECTOR 10: Selfdestruct / Suicide (CWE-284)
    def _detect_selfdestruct(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-010-SELFDESTRUCT"]

        for func in contract.functions:
            body = func.body
            if "selfdestruct" in body or "suicide" in body:
                snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                is_protected = func.has_owner_or_auth_modifier
                sev = Severity.MEDIUM if is_protected else Severity.CRITICAL
                findings.append(Finding(
                    severity=sev,
                    category="Unprotected Selfdestruct / Suicide",
                    function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                    description=(
                        f"Function '{func.name}' in contract '{contract.name}' contains selfdestruct/suicide instruction. "
                        "Selfdestruct can permanently destroy contract bytecode and force-forward all contract Ether."
                    ),
                    source_tool="ast_analyzer",
                    rule_id=rule["rule_id"],
                    contract_name=contract.name,
                    line_start=func.start_line,
                    line_end=func.end_line,
                    confidence=Confidence.HIGH,
                    cwe_id=rule["cwe"],
                    impact=rule["impact"],
                    remediation=rule["remediation"],
                    code_snippet="\n".join(snippet[:10])
                ))

        return findings

    # DETECTOR 11: Integer Overflow in Unchecked Block (CWE-190)
    def _detect_integer_overflow(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-011-INTEGER-OVERFLOW"]

        for func in contract.functions:
            body = func.body
            if "unchecked" in body:
                unchecked_blocks = re.findall(r"unchecked\s*\{([^}]+)\}", body)
                for block in unchecked_blocks:
                    if re.search(r"(?:\+=|\-=|\*=|\+\s*[a-zA-Z0-9_]|\-\s*[a-zA-Z0-9_]|\*\s*[a-zA-Z0-9_])", block):
                        snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                        findings.append(Finding(
                            severity=rule["default_severity"],
                            category="Integer Overflow / Underflow in Unchecked Block",
                            function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                            description=(
                                f"Function '{func.name}' in contract '{contract.name}' executes arithmetic operations inside an "
                                "unchecked { ... } block without boundary assertions."
                            ),
                            source_tool="ast_analyzer",
                            rule_id=rule["rule_id"],
                            contract_name=contract.name,
                            line_start=func.start_line,
                            line_end=func.end_line,
                            confidence=Confidence.LOW,
                            cwe_id=rule["cwe"],
                            impact=rule["impact"],
                            remediation=rule["remediation"],
                            code_snippet=block.strip()
                        ))
                        break

        return findings

    # DETECTOR 12: Useless Statements / Dead Code (CWE-561)
    def _detect_useless_statements(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-012-USELESS-STATEMENT"]

        for func in contract.functions:
            body = func.body
            useless_matches = re.finditer(r"(?:^|[;{}])\s*([a-zA-Z0-9_]+|this)\s*;", body)
            for m in useless_matches:
                identifier = m.group(1).strip()
                if identifier not in ("return", "break", "continue", "revert", "assembly", "unchecked"):
                    if identifier in ("_amount", "this") or (identifier.startswith("_") and len(identifier) > 1):
                        snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                        findings.append(Finding(
                            severity=rule["default_severity"],
                            category="Useless statement",
                            function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                            description=f"The statement '{identifier};' inside '{func.name}' has no effect and should be removed.",
                            source_tool="ast_analyzer",
                            rule_id=rule["rule_id"],
                            contract_name=contract.name,
                            line_start=func.start_line,
                            line_end=func.end_line,
                            confidence=Confidence.HIGH,
                            cwe_id=rule["cwe"],
                            impact=rule["impact"],
                            remediation=rule["remediation"],
                            code_snippet=f"{identifier};"
                        ))

        return findings

    # DETECTOR 13: Unprotected Initialize (CWE-284)
    def _detect_unprotected_initialize(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-013-UNPROTECTED-INITIALIZE"]

        for func in contract.functions:
            if func.name.lower() in ("initialize", "init") and func.visibility in ("public", "external"):
                if "initializer" not in [m.lower() for m in func.modifiers] and not func.has_owner_or_auth_modifier:
                    snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                    findings.append(Finding(
                        severity=rule["default_severity"],
                        category="Unprotected Initialize Function",
                        function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                        description=(
                            f"Initialize function '{func.name}' in contract '{contract.name}' lacks the 'initializer' modifier or "
                            "re-initialization protection, allowing attackers to re-initialize contract state."
                        ),
                        source_tool="ast_analyzer",
                        rule_id=rule["rule_id"],
                        contract_name=contract.name,
                        line_start=func.start_line,
                        line_end=func.end_line,
                        confidence=Confidence.HIGH,
                        cwe_id=rule["cwe"],
                        impact=rule["impact"],
                        remediation=rule["remediation"],
                        code_snippet="\n".join(snippet[:10])
                    ))

        return findings

    # DETECTOR 14: Missing Zero-Address Validation (CWE-20)
    def _detect_missing_zero_check(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-014-MISSING-ZERO-CHECK"]

        for func in contract.functions:
            if func.visibility in ("public", "external") or func.is_constructor:
                body = func.body
                match = re.search(r"\b(?:owner|admin|delegate|target)\s*=\s*(?:[a-zA-Z0-9_]+\s*\(\s*)?(_[a-zA-Z0-9_]+|new[a-zA-Z0-9_]+)\s*(?:\))?\s*;", body)
                if match:
                    var_name = match.group(1)
                    if var_name not in ("msg.sender", "address(this)") and "address(0)" not in body and "address(0x0)" not in body:
                        snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                        findings.append(Finding(
                            severity=rule["default_severity"],
                            category="missing-zero-check",
                            function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                            description=(
                                f"Function '{func.name}' in contract '{contract.name}' assigns critical address variables without "
                                "verifying that the address parameter is non-zero (address(0))."
                            ),
                            source_tool="ast_analyzer",
                            rule_id=rule["rule_id"],
                            contract_name=contract.name,
                            line_start=func.start_line,
                            line_end=func.end_line,
                            confidence=Confidence.LOW,
                            cwe_id=rule["cwe"],
                            impact=rule["impact"],
                            remediation=rule["remediation"],
                            code_snippet="\n".join(snippet[:10])
                        ))

        return findings

    # DETECTOR 15: Arbitrary ETH Transfer (CWE-284)
    def _detect_arbitrary_eth_transfer(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-015-ARBITRARY-SEND-ETH"]

        for func in contract.functions:
            if func.visibility in ("public", "external") and not func.has_owner_or_auth_modifier:
                body = func.body
                # Check for transferring full contract balance to arbitrary address without accounting
                if re.search(r"(?:payable\s*\([^)]*\)|\b[a-zA-Z0-9_]+)\s*\.\s*(?:transfer|send)\s*\(\s*address\s*\(\s*this\s*\)\s*\.\s*balance\s*\)", body):
                    if not re.search(r"balances\s*\[\s*msg\.sender\s*\]|shares\s*\[\s*msg\.sender\s*\]", body):
                        snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                        findings.append(Finding(
                            severity=rule["default_severity"],
                            category="Arbitrary ETH Transfer",
                            function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                            description=(
                                f"Function '{func.name}' in contract '{contract.name}' allows transferring the contract's "
                                "entire Ether balance without authorization modifiers or internal balance deduction."
                            ),
                            source_tool="ast_analyzer",
                            rule_id=rule["rule_id"],
                            contract_name=contract.name,
                            line_start=func.start_line,
                            line_end=func.end_line,
                            confidence=Confidence.HIGH,
                            cwe_id=rule["cwe"],
                            impact=rule["impact"],
                            remediation=rule["remediation"],
                            code_snippet="\n".join(snippet[:10])
                        ))

        return findings

    # DETECTOR 16: Uninitialized Local Storage Pointer (CWE-824)
    def _detect_uninitialized_storage(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-016-UNINITIALIZED-STORAGE"]

        for func in contract.functions:
            body = func.body
            # Look for struct/type declared with storage modifier but no assignment: Type storage var;
            matches = re.finditer(r"\b([A-Z][a-zA-Z0-9_]*)\s+storage\s+([a-zA-Z0-9_]+)\s*;", body)
            for m in matches:
                struct_type = m.group(1)
                var_name = m.group(2)
                snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                findings.append(Finding(
                    severity=rule["default_severity"],
                    category="Uninitialized Local Storage Pointer",
                    function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                    description=(
                        f"Function '{func.name}' in contract '{contract.name}' declares an uninitialized local storage "
                        f"pointer '{struct_type} storage {var_name};' pointing to storage slot 0."
                    ),
                    source_tool="ast_analyzer",
                    rule_id=rule["rule_id"],
                    contract_name=contract.name,
                    line_start=func.start_line,
                    line_end=func.end_line,
                    confidence=Confidence.HIGH,
                    cwe_id=rule["cwe"],
                    impact=rule["impact"],
                    remediation=rule["remediation"],
                    code_snippet=f"{struct_type} storage {var_name};"
                ))

        return findings

    # DETECTOR 17: Floating / Outdated Pragma (CWE-1038)
    def _detect_floating_pragma(self, source: str, lines: List[str], contract_name: str) -> List[Finding]:
        findings = []
        rule = self.rules["CG-017-FLOATING-PRAGMA"]

        pragma_match = re.search(r"pragma\s+solidity\s+([^;]+);", source)
        if pragma_match:
            version_str = pragma_match.group(1).strip()
            if version_str.startswith(("^", ">=", ">", "<")):
                pragma_pos = pragma_match.start()
                line_num = source.count("\n", 0, pragma_pos) + 1
                findings.append(Finding(
                    severity=rule["default_severity"],
                    category="Floating or Outdated Solidity Pragma",
                    function_or_line=f"Line {line_num}",
                    description=(
                        f"Contract '{contract_name}' uses a floating or unbounded pragma statement: 'pragma solidity {version_str};'. "
                        "Contracts should lock pragma to a specific compiler version for production deployments."
                    ),
                    source_tool="ast_analyzer",
                    rule_id=rule["rule_id"],
                    contract_name=contract_name,
                    line_start=line_num,
                    line_end=line_num,
                    confidence=Confidence.LOW,
                    cwe_id=rule["cwe"],
                    impact=rule["impact"],
                    remediation=rule["remediation"],
                    code_snippet=f"pragma solidity {version_str};"
                ))

        return findings

    # DETECTOR 18: Missing Nonce / Signature Replay (CWE-347)
    def _detect_signature_replay(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-018-SIGNATURE-REPLAY"]

        for func in contract.functions:
            body = func.body
            if "ecrecover" in body:
                has_nonce = bool(re.search(r"\b(?:nonce|nonces)\b", body, re.IGNORECASE))
                has_used_signatures = bool(re.search(r"\b(?:usedSignatures|usedHashes|executed)\b", body, re.IGNORECASE))
                has_domain_separator = bool(re.search(r"\b(?:DOMAIN_SEPARATOR|_domainSeparatorV4|EIP712)\b", body))

                if not (has_nonce or has_used_signatures) or not has_domain_separator:
                    snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                    findings.append(Finding(
                        severity=rule["default_severity"],
                        category="Missing Nonce or Domain Separator in Signature Validation",
                        function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                        description=(
                            f"Function '{func.name}' in contract '{contract.name}' uses 'ecrecover' without proper "
                            "nonce tracking or EIP-712 domain separation, exposing the contract to signature replay attacks."
                        ),
                        source_tool="ast_analyzer",
                        rule_id=rule["rule_id"],
                        contract_name=contract.name,
                        line_start=func.start_line,
                        line_end=func.end_line,
                        confidence=Confidence.HIGH,
                        cwe_id=rule["cwe"],
                        impact=rule["impact"],
                        remediation=rule["remediation"],
                        code_snippet="\n".join(snippet[:10])
                    ))

        return findings

    # DETECTOR 19: Insecure Randomness from On-Chain Variables (CWE-330)
    def _detect_weak_prng(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-019-WEAK-PRNG"]

        for func in contract.functions:
            body = func.body
            # Check for block variables used in modulo arithmetic or hash-based randomness
            has_block_var = bool(re.search(r"\b(?:block\.timestamp|block\.number|blockhash|block\.difficulty|block\.prevrandao|now)\b", body))
            has_modulo = "%" in body
            has_random_context = bool(re.search(r"(?:random|lottery|winner|flip|dice|spin|chance|prize|luck|pick)", func.name + " " + body, re.IGNORECASE))

            if has_block_var and (has_modulo or has_random_context):
                snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                findings.append(Finding(
                    severity=rule["default_severity"],
                    category="Insecure Randomness from On-Chain Variables",
                    function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                    description=(
                        f"Function '{func.name}' in contract '{contract.name}' derives pseudo-randomness from predictable "
                        "on-chain block environment variables (block.timestamp / blockhash / prevrandao)."
                    ),
                    source_tool="ast_analyzer",
                    rule_id=rule["rule_id"],
                    contract_name=contract.name,
                    line_start=func.start_line,
                    line_end=func.end_line,
                    confidence=Confidence.HIGH,
                    cwe_id=rule["cwe"],
                    impact=rule["impact"],
                    remediation=rule["remediation"],
                    code_snippet="\n".join(snippet[:10])
                ))

        return findings

    # DETECTOR 20: Read-Only Reentrancy Vulnerability (CWE-841)
    def _detect_read_only_reentrancy(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-020-READ-ONLY-REENTRANCY"]

        for func in contract.functions:
            body = func.body
            if re.search(r"\b(?:get_virtual_price|getVirtualPrice|get_dy|calc_token_amount)\s*\(", body):
                if not func.has_non_reentrant_guard and "nonreentrantview" not in [m.lower() for m in func.modifiers]:
                    snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                    findings.append(Finding(
                        severity=rule["default_severity"],
                        category="Read-Only Reentrancy Vulnerability",
                        function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                        description=(
                            f"Function '{func.name}' in contract '{contract.name}' queries pool virtual prices without "
                            "read-only reentrancy protection, allowing price manipulation during active pool state updates."
                        ),
                        source_tool="ast_analyzer",
                        rule_id=rule["rule_id"],
                        contract_name=contract.name,
                        line_start=func.start_line,
                        line_end=func.end_line,
                        confidence=Confidence.MEDIUM,
                        cwe_id=rule["cwe"],
                        impact=rule["impact"],
                        remediation=rule["remediation"],
                        code_snippet="\n".join(snippet[:10])
                    ))

        return findings

    # DETECTOR 21: Unchecked ERC20 Transfer Return Value (CWE-252)
    def _detect_unchecked_erc20_transfer(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-021-UNCHECKED-ERC20-TRANSFER"]

        for func in contract.functions:
            body = func.body
            # Check for IERC20(token).transfer(...) or token.transfer(...) without require or boolean check
            statements = body.split(";")
            for stmt in statements:
                stmt_clean = stmt.strip()
                if re.search(r"(?:IERC20\s*\([^)]*\)|token|erc20)\s*\.\s*(?:transfer|transferFrom)\s*\(", stmt_clean):
                    if "safeTransfer" in stmt_clean or "SafeERC20" in stmt_clean or "SafeTransferLib" in stmt_clean:
                        continue
                    is_assigned = bool(re.search(r"(?:(?:bool|\(bool)[^=]*=)", stmt_clean))
                    is_in_require = bool(re.search(r"(?:require|if|assert)\s*\(", stmt_clean))
                    if not is_assigned and not is_in_require:
                        snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                        findings.append(Finding(
                            severity=rule["default_severity"],
                            category="Unchecked ERC20 Transfer Return Value",
                            function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                            description=(
                                f"Function '{func.name}' in contract '{contract.name}' executes ERC20 transfer/transferFrom without "
                                "verifying the returned boolean value or using SafeERC20."
                            ),
                            source_tool="ast_analyzer",
                            rule_id=rule["rule_id"],
                            contract_name=contract.name,
                            line_start=func.start_line,
                            line_end=func.end_line,
                            confidence=Confidence.HIGH,
                            cwe_id=rule["cwe"],
                            impact=rule["impact"],
                            remediation=rule["remediation"],
                            code_snippet=stmt_clean
                        ))

        return findings

    # DETECTOR 22: Unprotected Token Minting (CWE-284)
    def _detect_unprotected_mint(self, contract: SolidityContract, lines: List[str]) -> List[Finding]:
        findings = []
        rule = self.rules["CG-022-UNPROTECTED-MINT"]

        for func in contract.functions:
            body = func.body
            fname_lower = func.name.lower()
            if (fname_lower in ("mint", "minttoken", "createtokens") or "mint" in fname_lower) and func.visibility in ("public", "external"):
                if not func.has_owner_or_auth_modifier and not func.is_constructor:
                    if re.search(r"\b_mint\s*\(|\bmint\s*\(", body):
                        if not re.search(r"require\s*\(\s*msg\.sender\s*==|if\s*\(\s*msg\.sender\s*!=|assert\s*\(\s*msg\.sender\s*==", body):
                            snippet = lines[func.start_line - 1:func.end_line] if func.start_line <= len(lines) else []
                            findings.append(Finding(
                                severity=rule["default_severity"],
                                category="Unprotected Token Minting",
                                function_or_line=f"{func.name} (lines {func.start_line}-{func.end_line})",
                                description=(
                                    f"Function '{func.name}' in contract '{contract.name}' allows arbitrary external callers to mint "
                                    "new tokens without access control modifiers or role validation."
                                ),
                                source_tool="ast_analyzer",
                                rule_id=rule["rule_id"],
                                contract_name=contract.name,
                                line_start=func.start_line,
                                line_end=func.end_line,
                                confidence=Confidence.HIGH,
                                cwe_id=rule["cwe"],
                                impact=rule["impact"],
                                remediation=rule["remediation"],
                                code_snippet="\n".join(snippet[:10])
                            ))

        return findings
