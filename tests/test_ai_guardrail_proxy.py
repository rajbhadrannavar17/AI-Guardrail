from proxy.ai_guardrail_proxy import extract_prompt_text, should_inspect
from app.guardrail_engine import classify_prompt


def test_proxy_targets_chatgpt_conversation_posts():
    assert should_inspect("chatgpt.com", "/backend-api/conversation", "POST") is True


def test_proxy_ignores_non_ai_hosts():
    assert should_inspect("example.com", "/backend-api/conversation", "POST") is False


def test_proxy_extracts_nested_json_prompt_text():
    body = '{"messages":[{"author":"user","content":{"parts":["my api key is 788"]}}]}'

    assert "my api key is 788" in extract_prompt_text(body, "application/json")


def test_proxy_blocks_natural_language_key_disclosure():
    decision = classify_prompt("my api key is 788", "Browser", "Employee")

    assert decision["action"] == "block"
    assert decision["risk_level"] == "Critical"
