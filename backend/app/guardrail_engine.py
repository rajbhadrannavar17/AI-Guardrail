from __future__ import annotations

import csv
import io
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal


Action = Literal["allow", "warn", "redact", "manager_approval", "security_approval", "block"]
RiskLevel = Literal["Low", "Medium", "High", "Critical"]


RISK_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
ACTION_ORDER = {
    "allow": 1,
    "warn": 2,
    "redact": 3,
    "manager_approval": 4,
    "security_approval": 5,
    "block": 6,
}


@dataclass(frozen=True)
class DetectionRule:
    name: str
    category: str
    pattern: re.Pattern[str]
    risk: RiskLevel
    action: Action
    confidence: float


RULES: list[DetectionRule] = [
    DetectionRule("AWS access key", "Cloud Credential", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Critical", "block", 0.98),
    DetectionRule("AWS secret key", "Cloud Credential", re.compile(r"(?i)\baws(.{0,24})?(secret|private).{0,12}[:=]\s*['\"]?[A-Za-z0-9/+=]{32,}"), "Critical", "block", 0.96),
    DetectionRule("GitHub token", "Developer Secret", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "Critical", "block", 0.98),
    DetectionRule("OpenAI API key", "AI Provider Secret", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "Critical", "block", 0.98),
    DetectionRule("API key disclosure", "AI Provider Secret", re.compile(r"(?i)\b(?:[a-z0-9_.-]+\s+){0,4}(api[_\s-]?key|access[_\s-]?key|client[_\s-]?secret|secret[_\s-]?key)\s*(is|as|=|:)\s*['\"]?[A-Za-z0-9_.\-]{3,}"), "Critical", "block", 0.94),
    DetectionRule("Private key", "Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "Critical", "block", 0.99),
    DetectionRule("JWT token", "Access Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "Critical", "block", 0.96),
    DetectionRule("Password assignment", "Credential", re.compile(r"(?i)\b(?:[a-z0-9_.-]+\s+){0,4}(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{3,}"), "High", "block", 0.9),
    DetectionRule("Password disclosure", "Credential", re.compile(r"(?i)\b(?:[a-z0-9_.-]+\s+){0,4}(password|passwd|pwd)\s+(is|as|=|:)\s*['\"]?[^'\"\s]{3,}"), "High", "block", 0.92),
    DetectionRule("Password value after label", "Credential", re.compile(r"(?i)\b(?:[a-z0-9_.-]+\s+){0,4}(password|passwd|pwd)\s+['\"]?[A-Za-z0-9_@#$%^&*+=.!?\-]{3,}\b"), "High", "block", 0.88),
    DetectionRule("Token disclosure", "Access Token", re.compile(r"(?i)\b(?:[a-z0-9_.-]+\s+){0,4}(token|auth[_\s-]?token|bearer[_\s-]?token)\s*(is|as|=|:)\s*['\"]?[A-Za-z0-9_.\-]{3,}"), "Critical", "block", 0.92),
    DetectionRule("Token value after label", "Access Token", re.compile(r"(?i)\b(?:[a-z0-9_.-]+\s+){0,4}(token|auth[_\s-]?token|bearer[_\s-]?token)\s+['\"]?[A-Za-z0-9_.\-]{3,}\b"), "Critical", "block", 0.88),
    DetectionRule("Connection string", "Database Secret", re.compile(r"(?i)\b(postgres|mysql|mongodb|redis)://[^ \n]+"), "Critical", "block", 0.95),
    DetectionRule("Environment secret", "Environment Variable", re.compile(r"(?im)^\s*[A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD)[A-Z0-9_]*\s*=\s*.+$"), "High", "redact", 0.88),
    DetectionRule("Credit card", "PCI", re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "Critical", "block", 0.78),
    DetectionRule("CVV", "PCI", re.compile(r"(?i)\bcvv\s*[:=]?\s*\d{3,4}\b"), "Critical", "block", 0.86),
    DetectionRule("Aadhaar", "India PII", re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"), "Critical", "block", 0.82),
    DetectionRule("PAN", "India PII", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"), "High", "manager_approval", 0.82),
    DetectionRule("Passport", "PII", re.compile(r"(?i)\bpassport\s*(number|no)?\s*[:=]?\s*[A-Z0-9]{6,12}\b"), "High", "manager_approval", 0.8),
    DetectionRule("Email address", "PII", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "Medium", "redact", 0.72),
    DetectionRule("Phone number", "PII", re.compile(r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3,5}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}(?!\d)"), "Medium", "redact", 0.68),
    DetectionRule("Internal URL", "Internal System", re.compile(r"(?i)\bhttps?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+|[a-z0-9.-]+\.internal)\S*"), "High", "manager_approval", 0.86),
    DetectionRule("Prompt injection", "LLM Threat", re.compile(r"(?i)\b(ignore previous|developer message|system prompt|jailbreak|reveal hidden|bypass policy)\b"), "High", "block", 0.84),
    DetectionRule("Data exfiltration", "LLM Threat", re.compile(r"(?i)\b(exfiltrate|dump database|export all users|steal credentials|leak secrets)\b"), "Critical", "block", 0.9),
    DetectionRule("Financial report", "Confidential Document", re.compile(r"(?i)\b(balance sheet|income statement|financial report|quarterly forecast|revenue forecast)\b"), "High", "manager_approval", 0.78),
    DetectionRule("Legal contract", "Confidential Document", re.compile(r"(?i)\b(master services agreement|nda|non-disclosure|legal contract|statement of work)\b"), "High", "manager_approval", 0.78),
    DetectionRule("Medical record", "Regulated Data", re.compile(r"(?i)\b(patient|diagnosis|medical record|prescription|hipaa)\b"), "Critical", "security_approval", 0.78),
    DetectionRule("Source code", "Intellectual Property", re.compile(r"(?m)\b(function|class|import|const|def|public static void|SELECT \* FROM)\b.*[;{:]?"), "Medium", "warn", 0.62),
]


POLICIES = [
    {
        "id": "POL-001",
        "name": "Credentials never leave the company",
        "departments": ["All"],
        "condition": "Cloud credentials, access tokens, private keys, passwords, and connection strings",
        "action": "block",
        "routing": "none",
        "compliance": ["SOC 2", "ISO 27001", "NIST CSF"],
    },
    {
        "id": "POL-002",
        "name": "PII is redacted or requires approval",
        "departments": ["HR", "Finance", "Support"],
        "condition": "Customer, employee, medical, payment, Aadhaar, PAN, passport, email, and phone data",
        "action": "redact / manager_approval / security_approval",
        "routing": "approved enterprise LLM only",
        "compliance": ["GDPR", "DPDP Act", "HIPAA", "PCI DSS"],
    },
    {
        "id": "POL-003",
        "name": "Source code routes to internal models",
        "departments": ["Engineering", "Security"],
        "condition": "Repository excerpts, stack traces, internal URLs, and design documents",
        "action": "warn or manager_approval",
        "routing": "internal-llm",
        "compliance": ["OWASP LLM", "NIST AI RMF"],
    },
    {
        "id": "POL-004",
        "name": "Prompt injection and exfiltration are blocked",
        "departments": ["All"],
        "condition": "Jailbreak, hidden instruction disclosure, data theft, and model bypass attempts",
        "action": "block",
        "routing": "none",
        "compliance": ["OWASP LLM01", "OWASP LLM06"],
    },
]

CATEGORY_POLICY_IDS = {
    "Access Token": {"POL-001"},
    "AI Provider Secret": {"POL-001"},
    "Cloud Credential": {"POL-001"},
    "Credential": {"POL-001"},
    "Database Secret": {"POL-001"},
    "Developer Secret": {"POL-001"},
    "Environment Variable": {"POL-001"},
    "Private Key": {"POL-001"},
    "Possible Secret": {"POL-001"},
    "PCI": {"POL-002"},
    "PII": {"POL-002"},
    "India PII": {"POL-002"},
    "Regulated Data": {"POL-002"},
    "Internal System": {"POL-003"},
    "Intellectual Property": {"POL-003"},
    "Confidential Document": {"POL-003"},
    "LLM Threat": {"POL-004"},
}


MODEL_ROUTES = {
    "Low": "openai-enterprise",
    "Medium": "azure-openai-private",
    "High": "internal-llm",
    "Critical": "none",
}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def mask(value: str) -> str:
    compact = value.strip()
    if len(compact) <= 8:
        return "[REDACTED]"
    return f"{compact[:3]}...[REDACTED]...{compact[-3:]}"


def redact_text(text: str, findings: list[dict]) -> str:
    redacted = text
    for finding in sorted(findings, key=lambda item: item["start"], reverse=True):
        redacted = redacted[: finding["start"]] + f"[REDACTED:{finding['category']}]" + redacted[finding["end"] :]
    return redacted


def classify_prompt(prompt: str, department: str, role: str) -> dict:
    findings: list[dict] = []
    for rule in RULES:
        for match in rule.pattern.finditer(prompt):
            value = match.group(0)
            if rule.name == "Credit card" and not likely_payment_card(value):
                continue
            findings.append(
                {
                    "rule": rule.name,
                    "category": rule.category,
                    "risk": rule.risk,
                    "action": rule.action,
                    "confidence": rule.confidence,
                    "start": match.start(),
                    "end": match.end(),
                    "preview": mask(value),
                }
            )

    for token in re.findall(r"\b[A-Za-z0-9_/\-+=]{24,}\b", prompt):
        entropy = shannon_entropy(token)
        if entropy >= 4.2 and not any(f["start"] <= prompt.find(token) < f["end"] for f in findings):
            start = prompt.find(token)
            findings.append(
                {
                    "rule": "High entropy token",
                    "category": "Possible Secret",
                    "risk": "High",
                    "action": "redact",
                    "confidence": round(min(0.94, entropy / 5.5), 2),
                    "start": start,
                    "end": start + len(token),
                    "preview": mask(token),
                }
            )

    highest_risk: RiskLevel = "Low"
    action: Action = "allow"
    for finding in findings:
        if RISK_ORDER[finding["risk"]] > RISK_ORDER[highest_risk]:
            highest_risk = finding["risk"]
        if ACTION_ORDER[finding["action"]] > ACTION_ORDER[action]:
            action = finding["action"]

    if action == "allow" and len(prompt) > 4000:
        highest_risk = max_risk(highest_risk, "Medium")
        action = "warn"
        findings.append(
            {
                "rule": "Large prompt",
                "category": "Mass Upload",
                "risk": "Medium",
                "action": "warn",
                "confidence": 0.65,
                "start": 0,
                "end": min(len(prompt), 32),
                "preview": "Large prompt body",
            }
        )

    if role.lower() in {"ciso", "security analyst", "soc analyst"} and action in {"manager_approval", "security_approval"}:
        action = "redact" if any(f["action"] == "redact" for f in findings) else "warn"

    if department.lower() == "finance" and any(f["category"] in {"Confidential Document", "PCI"} for f in findings):
        action = max_action(action, "security_approval")
        highest_risk = max_risk(highest_risk, "High")

    redacted_prompt = redact_text(prompt, findings)
    model_route = MODEL_ROUTES[highest_risk] if action not in {"block", "security_approval", "manager_approval"} else "pending"
    if action == "block":
        model_route = "none"

    return {
        "risk_level": highest_risk,
        "risk_score": risk_score(highest_risk, findings),
        "action": action,
        "model_route": model_route,
        "redacted_prompt": redacted_prompt,
        "findings": findings,
        "policy_matches": matched_policies(findings),
        "approval_required": action in {"manager_approval", "security_approval"},
        "decision_reason": decision_reason(action, highest_risk, findings),
    }


def inspect_response(response: str) -> dict:
    result = classify_prompt(response, "All", "Employee")
    if result["action"] in {"manager_approval", "security_approval"}:
        result["action"] = "block"
        result["decision_reason"] = "Response contains sensitive content and was blocked before delivery."
    return result


def simulated_llm_response(prompt: str, model_route: str) -> str:
    if model_route in {"none", "pending"}:
        return ""
    trimmed = prompt.strip().replace("\n", " ")
    return (
        f"Simulated response from {model_route}: I can help with the sanitized request. "
        f"Summary of safe prompt context: {trimmed[:220]}"
    )


def analytics_from_logs(logs: list[dict]) -> dict:
    departments: dict[str, int] = {}
    actions: dict[str, int] = {}
    risks: dict[str, int] = {}
    users: dict[str, int] = {}
    categories: dict[str, int] = {}
    for log in logs:
        departments[log["department"]] = departments.get(log["department"], 0) + 1
        actions[log["action"]] = actions.get(log["action"], 0) + 1
        risks[log["risk_level"]] = risks.get(log["risk_level"], 0) + 1
        if log["risk_level"] in {"High", "Critical"}:
            users[log["user_email"]] = users.get(log["user_email"], 0) + 1
        for finding in log.get("findings", []):
            categories[finding["category"]] = categories.get(finding["category"], 0) + 1
    return {
        "total": len(logs),
        "actions": actions,
        "risks": risks,
        "departments": departments,
        "highest_risk_users": sorted(users.items(), key=lambda item: item[1], reverse=True)[:5],
        "common_secret_types": sorted(categories.items(), key=lambda item: item[1], reverse=True)[:6],
        "blocked": actions.get("block", 0),
        "redacted": actions.get("redact", 0),
        "allowed": actions.get("allow", 0),
        "approvals": actions.get("manager_approval", 0) + actions.get("security_approval", 0),
    }


def logs_to_csv(logs: list[dict]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["id", "created_at", "user_email", "department", "role", "risk_level", "risk_score", "action", "model_route", "approval_status"],
    )
    writer.writeheader()
    for log in logs:
        writer.writerow({key: log.get(key, "") for key in writer.fieldnames})
    return output.getvalue()


def siem_event(log: dict) -> dict:
    return {
        "event_type": "ai_guardrail.prompt_decision",
        "event_time": log.get("created_at") or datetime.now(timezone.utc).isoformat(),
        "user": log["user_email"],
        "department": log["department"],
        "risk": log["risk_level"],
        "score": log["risk_score"],
        "action": log["action"],
        "model": log["model_route"],
        "categories": [finding["category"] for finding in log.get("findings", [])],
        "frameworks": ["OWASP Top 10 for LLM Applications", "NIST AI RMF", "ISO 27001", "SOC 2"],
    }


def likely_payment_card(value: str) -> bool:
    digits = [int(ch) for ch in value if ch.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def risk_score(risk: RiskLevel, findings: list[dict]) -> int:
    base = {"Low": 18, "Medium": 45, "High": 72, "Critical": 93}[risk]
    return min(100, base + len(findings) * 2)


def matched_policies(findings: list[dict]) -> list[dict]:
    policy_ids: set[str] = set()
    for finding in findings:
        policy_ids.update(CATEGORY_POLICY_IDS.get(finding["category"], set()))
    matches = []
    for policy in POLICIES:
        if policy["id"] in policy_ids:
            matches.append(policy)
    return matches[:4]


def decision_reason(action: Action, risk: RiskLevel, findings: list[dict]) -> str:
    if not findings:
        return "No sensitive data or prompt abuse indicators were detected."
    primary = ", ".join(sorted({finding["category"] for finding in findings})[:4])
    return f"{risk} risk content detected: {primary}. Policy action: {action.replace('_', ' ')}."


def max_action(left: Action, right: Action) -> Action:
    return left if ACTION_ORDER[left] >= ACTION_ORDER[right] else right


def max_risk(left: RiskLevel, right: RiskLevel) -> RiskLevel:
    return left if RISK_ORDER[left] >= RISK_ORDER[right] else right
