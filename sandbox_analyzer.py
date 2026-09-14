import sys
import json

def analyze_payload(raw_log):
    score = 0
    findings = []
    
    if ".." in raw_log:
        score += 40
        findings.append("Directory traversal sequence detected ('..')")
        
    sensitive_files = ["/etc/passwd", "/etc/shadow", "web.config", "boot.ini"]
    for target in sensitive_files:
        if target in raw_log:
            score += 50
            findings.append(f"Sensitive file access targeted ({target})")
            
    if "python-requests" in raw_log or "curl" in raw_log:
        score += 10
        findings.append("Automated attack tool User-Agent identified")

    threat_level = "HIGH" if score >= 70 else "MEDIUM" if score >= 30 else "LOW"

    return {
        "risk_score": score,
        "threat_level": threat_level,
        "findings": findings,
        "is_malicious": score >= 50
    }

if __name__ == "__main__":
    try:
        file_path = sys.argv[1] if len(sys.argv) > 1 else "/app/input.json"
        with open(file_path, "r") as f:
            payload = json.load(f)
            
        log_content = payload.get("raw_log", str(payload))
        analysis = analyze_payload(log_content)
        print(json.dumps(analysis))
    except Exception as e:
        print(json.dumps({"error": str(e)}))