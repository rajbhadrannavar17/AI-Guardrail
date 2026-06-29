from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from mitmproxy import http
except Exception:  # pragma: no cover - lets unit tests run without mitmproxy installed
    http = None

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.guardrail_engine import classify_prompt, redact_text
from app.file_scanner import extract_upload_candidates, scan_upload_bytes


AI_HOSTS = {
    "chatgpt.com",
    "chat.openai.com",
    "api.openai.com",
    "claude.ai",
    "api.anthropic.com",
    "gemini.google.com",
    "generativelanguage.googleapis.com",
    "copilot.microsoft.com",
    "www.bing.com",
}

AI_PATH_HINTS = (
    "/backend-api/",
    "/conversation",
    "/chat",
    "/completion",
    "/completions",
    "/responses",
    "/v1/messages",
    "/v1beta/models",
)

LOG_PATH = ROOT / "data" / "proxy_audit.jsonl"


class AIGuardrailProxy:
    def request(self, flow: Any) -> None:
        if not should_inspect(flow.request.host, flow.request.path, flow.request.method):
            return

        content_type = flow.request.headers.get("content-type", "")
        body_bytes = flow.request.raw_content or b""
        for upload in extract_upload_candidates(content_type, body_bytes):
            decision = scan_upload_bytes(upload.filename, upload.content_type, upload.data)
            write_audit(flow, decision, f"file:{upload.filename}")
            if decision["action"] in {"block", "manager_approval", "security_approval"}:
                flow.response = make_block_response(decision)
                return

        body = flow.request.get_text(strict=False) or ""
        extracted = extract_prompt_text(body, content_type)
        if not extracted.strip():
            return

        decision = classify_prompt(extracted, "Browser", "Employee")
        write_audit(flow, decision, extracted)

        if decision["action"] in {"block", "manager_approval", "security_approval"}:
            flow.response = make_block_response(decision)
            return

        if decision["action"] == "redact" and body:
            redacted_body = redact_payload(body, extracted, decision["findings"], content_type)
            if redacted_body != body:
                flow.request.set_text(redacted_body)
                flow.request.headers["x-ai-guardrail-action"] = "redacted"

        flow.request.headers["x-ai-guardrail-risk"] = decision["risk_level"]
        flow.request.headers["x-ai-guardrail-action"] = decision["action"]

    def response(self, flow: Any) -> None:
        if not flow.response or not should_inspect(flow.request.host, flow.request.path, flow.request.method):
            return
        content_type = flow.response.headers.get("content-type", "")
        if "json" not in content_type and "text" not in content_type:
            return
        text = flow.response.get_text(strict=False) or ""
        if not text.strip():
            return
        decision = classify_prompt(extract_prompt_text(text, content_type), "Browser", "Employee")
        if decision["action"] in {"block", "manager_approval", "security_approval"}:
            flow.response = make_block_response(
                {
                    **decision,
                    "decision_reason": "AI response was blocked because it contained sensitive data.",
                }
            )


def should_inspect(host: str, path: str, method: str) -> bool:
    host_l = (host or "").lower()
    path_l = path or ""
    if method.upper() not in {"POST", "PUT", "PATCH"}:
        return False
    if not any(host_l == item or host_l.endswith(f".{item}") for item in AI_HOSTS):
        return False
    return any(hint in path_l for hint in AI_PATH_HINTS)


def extract_prompt_text(body: str, content_type: str) -> str:
    if not body:
        return ""
    if "json" not in content_type:
        return body
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return body
    values: list[str] = []
    collect_strings(data, values)
    return "\n".join(values)


def collect_strings(value: Any, values: list[str]) -> None:
    if isinstance(value, str):
        if len(value.strip()) >= 3:
            values.append(value)
        return
    if isinstance(value, list):
        for item in value:
            collect_strings(item, values)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in {"authorization", "cookie", "csrf", "session"}:
                continue
            collect_strings(item, values)


def redact_payload(body: str, extracted: str, findings: list[dict], content_type: str) -> str:
    if "json" not in content_type:
        return redact_text(body, findings)
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return body
    redacted = redact_json_value(data, findings)
    return json.dumps(redacted, separators=(",", ":"))


def redact_json_value(value: Any, findings: list[dict]) -> Any:
    if isinstance(value, str):
        redacted = value
        for finding in findings:
            raw_category = f"[REDACTED:{finding['category']}]"
            # Re-run simple category replacement on matching substrings found inside this field.
            preview_start = finding["preview"].split("...[REDACTED]...")[0]
            if preview_start and preview_start in redacted:
                redacted = redacted.replace(preview_start, raw_category)
        return redacted
    if isinstance(value, list):
        return [redact_json_value(item, findings) for item in value]
    if isinstance(value, dict):
        return {key: redact_json_value(item, findings) for key, item in value.items()}
    return value


def make_block_response(decision: dict) -> Any:
    payload = {
        "error": "AI Guardrail blocked this request",
        "risk_level": decision["risk_level"],
        "risk_score": decision["risk_score"],
        "action": decision["action"],
        "reason": decision["decision_reason"],
        "findings": [
            {
                "rule": finding["rule"],
                "category": finding["category"],
                "risk": finding["risk"],
                "preview": finding["preview"],
            }
            for finding in decision["findings"][:6]
        ],
    }
    if http is None:
        return payload
    return http.Response.make(
        403,
        json.dumps(payload, indent=2),
        {
            "content-type": "application/json",
            "x-ai-guardrail-action": "blocked",
            "access-control-allow-origin": "*",
        },
    )


def write_audit(flow: Any, decision: dict, extracted: str) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": flow.request.host,
        "path": flow.request.path,
        "method": flow.request.method,
        "risk_level": decision["risk_level"],
        "risk_score": decision["risk_score"],
        "action": decision["action"],
        "reason": decision["decision_reason"],
        "findings": decision["findings"],
        "prompt_preview": extracted[:240],
    }
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


addons = [AIGuardrailProxy()]
