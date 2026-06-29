from app import file_scanner
from app.file_scanner import extract_upload_candidates, scan_upload_bytes


def test_text_file_with_api_key_is_blocked():
    decision = scan_upload_bytes("notes.txt", "text/plain", b"my api key is 788")

    assert decision["action"] == "block"
    assert decision["risk_level"] == "Critical"


def test_uninspectable_pdf_is_blocked():
    decision = scan_upload_bytes("confidential.pdf", "application/pdf", b"%PDF-1.7\nnot a real pdf")

    assert decision["action"] == "block"
    assert "could not be inspected" in decision["decision_reason"]


def test_pdf_with_sensitive_text_is_blocked(monkeypatch):
    monkeypatch.setattr(file_scanner, "extract_pdf_text", lambda _: "admin password is xxx")

    decision = scan_upload_bytes("secrets.pdf", "application/pdf", b"%PDF-1.7\nfake")

    assert decision["action"] == "block"
    assert decision["file_type"] == "pdf"
    assert "PDF upload blocked" in decision["decision_reason"]


def test_multipart_pdf_candidate_is_extracted():
    boundary = "----guardrail-test"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="plan.pdf"\r\n'
        "Content-Type: application/pdf\r\n\r\n"
        "%PDF-1.7\nfake\r\n"
        f"--{boundary}--\r\n"
    ).encode()

    candidates = extract_upload_candidates(f"multipart/form-data; boundary={boundary}", body)

    assert len(candidates) == 1
    assert candidates[0].filename == "plan.pdf"
    assert candidates[0].content_type == "application/pdf"
