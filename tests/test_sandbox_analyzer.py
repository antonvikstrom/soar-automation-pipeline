"""Tests for sandbox_analyzer.py, the pre-LLM risk scoring step.

Run from the repo root with:  python -m pytest -v
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sandbox_analyzer import analyze_payload  # noqa: E402

SCRIPT = REPO_ROOT / "sandbox_analyzer.py"

# Realistic log lines, shaped like the DVWA access logs Splunk forwards.
ATTACK_LOG = (
    '10.1.4.100 - - [25/Sep/2026:10:15:01] '
    '"GET /vulnerabilities/fi/?page=../../../../etc/passwd HTTP/1.1" 200 '
    '"python-requests/2.31.0"'
)
ROUTINE_LOG = (
    '10.1.4.100 - - [25/Sep/2026:10:16:12] '
    '"GET /vulnerabilities/fi/?page=include.php HTTP/1.1" 200 '
    '"Mozilla/5.0 (X11; Linux x86_64)"'
)


# --- The two cases the pipeline was built around --------------------------

def test_attack_from_the_lab_is_high_and_malicious():
    result = analyze_payload(ATTACK_LOG)
    assert result["risk_score"] == 100  # 40 traversal + 50 file + 10 tool
    assert result["threat_level"] == "HIGH"
    assert result["is_malicious"] is True
    assert len(result["findings"]) == 3


def test_routine_include_is_suppressed():
    result = analyze_payload(ROUTINE_LOG)
    assert result == {
        "risk_score": 0,
        "threat_level": "LOW",
        "findings": [],
        "is_malicious": False,
    }


# --- Each scoring rule on its own --------------------------------------------

def test_traversal_alone_is_medium_but_not_malicious():
    result = analyze_payload("GET /?page=../include.php")
    assert result["risk_score"] == 40
    assert result["threat_level"] == "MEDIUM"
    assert result["is_malicious"] is False


@pytest.mark.parametrize("target", ["/etc/passwd", "/etc/shadow", "web.config", "boot.ini"])
def test_each_sensitive_file_is_malicious_on_its_own(target):
    result = analyze_payload(f"GET /?file={target}")
    assert result["risk_score"] == 50
    assert result["is_malicious"] is True
    assert f"Sensitive file access targeted ({target})" in result["findings"]


@pytest.mark.parametrize("agent", ["python-requests/2.31.0", "curl/8.5.0"])
def test_tool_user_agent_adds_ten(agent):
    result = analyze_payload(f'GET /index.php "{agent}"')
    assert result["risk_score"] == 10
    assert result["threat_level"] == "LOW"
    assert result["is_malicious"] is False


def test_several_sensitive_files_add_up():
    result = analyze_payload("GET /?a=/etc/passwd&b=/etc/shadow")
    assert result["risk_score"] == 100
    assert result["threat_level"] == "HIGH"


# --- Threshold boundaries ------------------------------------------------------

def test_score_of_50_is_malicious_but_still_medium():
    """Documents the current design: is_malicious starts at 50, HIGH at 70."""
    result = analyze_payload("GET /?file=/etc/passwd")
    assert result["is_malicious"] is True
    assert result["threat_level"] == "MEDIUM"


def test_traversal_plus_tool_just_reaches_malicious():
    result = analyze_payload('GET /?page=../x "curl/8.5.0"')
    assert result["risk_score"] == 50
    assert result["is_malicious"] is True


def test_empty_log():
    result = analyze_payload("")
    assert result["risk_score"] == 0
    assert result["is_malicious"] is False


# --- Known gaps (expected to fail until the analyzer is improved) -----------

@pytest.mark.xfail(reason="URL-encoded traversal (%2e%2e%2f) is not decoded before matching", strict=True)
def test_url_encoded_traversal_is_detected():
    result = analyze_payload("GET /?page=%2e%2e%2f%2e%2e%2fetc%2fpasswd")
    assert result["is_malicious"] is True


@pytest.mark.xfail(reason="Matching is case-sensitive, so 'Curl' or '/ETC/PASSWD' slip through", strict=True)
def test_matching_is_case_insensitive():
    result = analyze_payload("GET /?file=/ETC/PASSWD")
    assert result["is_malicious"] is True


# --- The script as the Docker container runs it ------------------------------

def run_script(input_file):
    out = subprocess.run(
        [sys.executable, str(SCRIPT), str(input_file)],
        capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)


def test_script_reads_raw_log_from_input_json(tmp_path):
    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps({"src_ip": "10.1.4.100", "raw_log": ATTACK_LOG}))
    result = run_script(input_file)
    assert result["is_malicious"] is True
    assert result["threat_level"] == "HIGH"


def test_script_without_raw_log_falls_back_to_whole_payload(tmp_path):
    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps({"uri": "/?page=../../etc/passwd"}))
    result = run_script(input_file)
    assert result["is_malicious"] is True


def test_script_returns_json_error_for_missing_file(tmp_path):
    result = run_script(tmp_path / "does_not_exist.json")
    assert "error" in result


def test_script_returns_json_error_for_invalid_json(tmp_path):
    input_file = tmp_path / "input.json"
    input_file.write_text("not json")
    result = run_script(input_file)
    assert "error" in result