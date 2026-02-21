"""Unit tests for modules/ai_decision.py."""

import json
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Test 1 — build_prompt includes scan data
# ---------------------------------------------------------------------------

def test_build_prompt_contains_scan_data(sample_scan_results, mock_state):
    """The prompt string must embed the scan results as JSON."""
    from modules.ai_decision import build_prompt

    prompt = build_prompt(sample_scan_results)

    assert "ssh" in prompt
    assert "OpenSSH 8.9" in prompt
    assert "Apache 2.4.54" in prompt
    assert "decisions" in prompt  # asks for this key in the output


# ---------------------------------------------------------------------------
# Test 2 — Falls back to Ollama when Groq fails
# ---------------------------------------------------------------------------

@patch("modules.ai_decision.requests.post")
@patch("modules.ai_decision.groq.Groq")
def test_get_decision_falls_back_to_ollama(
    mock_groq_cls, mock_post, sample_scan_results, mock_state
):
    """When Groq raises, get_attack_decision should try Ollama and return
    its decisions.
    """
    # Groq: raise
    mock_groq_cls.return_value.chat.completions.create.side_effect = Exception("Groq down")

    # Ollama: valid response
    ollama_body = {
        "response": json.dumps({
            "decisions": [
                {
                    "technique": "ssh_brute",
                    "mitre_id": "T1110.001",
                    "target_service": "ssh",
                    "target_port": 22,
                    "rationale": "SSH open with password auth",
                    "priority": 1,
                }
            ]
        })
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = ollama_body
    mock_resp.raise_for_status = MagicMock()
    mock_post.return_value = mock_resp

    from modules.ai_decision import get_attack_decision

    decisions = get_attack_decision(sample_scan_results)

    assert isinstance(decisions, list)
    assert len(decisions) >= 1
    assert decisions[0]["technique"] == "ssh_brute"


# ---------------------------------------------------------------------------
# Test 3 — Default fallback when both LLMs fail
# ---------------------------------------------------------------------------

@patch("modules.ai_decision.requests.post")
@patch("modules.ai_decision.groq.Groq")
def test_default_fallback_when_all_fail(
    mock_groq_cls, mock_post, sample_scan_results, mock_state
):
    """When both Groq and Ollama fail, a non-empty default decision list
    should be returned.
    """
    mock_groq_cls.return_value.chat.completions.create.side_effect = Exception("Groq down")
    mock_post.side_effect = Exception("Ollama down")

    from modules.ai_decision import get_attack_decision

    decisions = get_attack_decision(sample_scan_results)

    assert isinstance(decisions, list)
    assert len(decisions) > 0
    # All defaults should have required keys
    for d in decisions:
        assert "technique" in d
        assert "mitre_id" in d
        assert "priority" in d
