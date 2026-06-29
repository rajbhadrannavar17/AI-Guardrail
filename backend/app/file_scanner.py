from __future__ import annotations

import io
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser

from pypdf import PdfReader

from .guardrail_engine import classify_prompt, risk_score


MAX_FILE_BYTES = 15 * 1024 * 1024
MAX_PDF_PAGES = 25


@dataclass(frozen=True)
class UploadCandidate:
    filename: str
    content_type: str
    data: bytes


def scan_upload_bytes(filename: str, content_type: str, data: bytes, department: str = "Browser", role: str = "Employee") -> dict:
    if len(data) > MAX_FILE_BYTES:
        return blocked_file_decision(filename, "High", "File is larger than the local inspection limit.")

    if is_pdf(filename, content_type, data):
        try:
            text = extract_pdf_text(data)
        except Exception as exc:
            return blocked_file_decision(filename, "High", f"PDF could not be inspected: {exc}")
        if not text.strip():
            return blocked_file_decision(filename, "Medium", "PDF has no extractable text for DLP inspection.")
        decision = classify_prompt(text, department, role)
        decision["file_name"] = filename
        decision["file_type"] = "pdf"
        decision["extracted_characters"] = len(text)
        if decision["action"] != "allow":
            decision["action"] = "block"
            decision["model_route"] = "none"
            decision["approval_required"] = False
            decision["decision_reason"] = f"PDF upload blocked: {decision['decision_reason']}"
        return decision

    text = data[:MAX_FILE_BYTES].decode("utf-8", errors="ignore")
    decision = classify_prompt(text, department, role)
    decision["file_name"] = filename
    decision["file_type"] = content_type or "application/octet-stream"
    decision["extracted_characters"] = len(text)
    if decision["action"] in {"redact", "manager_approval", "security_approval"}:
        decision["action"] = "block"
        decision["model_route"] = "none"
        decision["decision_reason"] = f"File upload blocked: {decision['decision_reason']}"
    return decision


def extract_pdf_text(data: bytes) -> str:
    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:
        try:
            reader.decrypt("")
        except Exception as exc:
            raise ValueError("encrypted PDF requires a password") from exc

    pages = []
    for page in reader.pages[:MAX_PDF_PAGES]:
        pages.append(page.extract_text() or "")
    return "\n".join(pages)


def extract_upload_candidates(content_type: str, body: bytes) -> list[UploadCandidate]:
    if not body:
        return []

    content_type_l = (content_type or "").lower()
    if content_type_l.startswith("application/pdf") or body.startswith(b"%PDF"):
        return [UploadCandidate("request-body.pdf", content_type or "application/pdf", body)]

    if "multipart/form-data" not in content_type_l:
        return []

    raw_message = (
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8")
        + body
    )
    message = BytesParser(policy=policy.default).parsebytes(raw_message)
    candidates: list[UploadCandidate] = []
    for part in message.iter_parts():
        payload = part.get_payload(decode=True) or b""
        if not payload:
            continue
        filename = part.get_filename() or part.get_param("name", header="content-disposition") or "upload"
        part_type = part.get_content_type() or "application/octet-stream"
        if is_pdf(filename, part_type, payload) or looks_textual(part_type, filename):
            candidates.append(UploadCandidate(filename, part_type, payload))
    return candidates


def is_pdf(filename: str, content_type: str, data: bytes) -> bool:
    name_l = (filename or "").lower()
    type_l = (content_type or "").lower()
    return type_l.startswith("application/pdf") or name_l.endswith(".pdf") or data.startswith(b"%PDF")


def looks_textual(content_type: str, filename: str) -> bool:
    type_l = (content_type or "").lower()
    name_l = (filename or "").lower()
    return (
        type_l.startswith("text/")
        or "json" in type_l
        or name_l.endswith((".txt", ".md", ".csv", ".json", ".env", ".log", ".py", ".js", ".ts", ".java", ".go", ".rs"))
    )


def blocked_file_decision(filename: str, risk: str, reason: str) -> dict:
    return {
        "risk_level": risk,
        "risk_score": risk_score(risk, []),
        "action": "block",
        "model_route": "none",
        "redacted_prompt": "",
        "findings": [
            {
                "rule": "File upload inspection",
                "category": "File Upload",
                "risk": risk,
                "action": "block",
                "confidence": 0.9,
                "start": 0,
                "end": 0,
                "preview": filename,
            }
        ],
        "policy_matches": [],
        "approval_required": False,
        "decision_reason": reason,
        "file_name": filename,
        "file_type": "pdf",
        "extracted_characters": 0,
    }
