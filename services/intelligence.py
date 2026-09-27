from services.analyzer import analyze_email
from services.header_forensics import parse_headers
from services.ioc import extract_iocs
from services.intel import enrich_indicator
from services.ml_detector import predict


def analyze_message(subject, sender, recipient, body, headers=""):
    rules = analyze_email(subject, sender, body, headers)
    ml = predict(f"{subject}\n{sender}\n{body}")
    base_score = rules["risk_score"]
    ml_score = ml["score"] if ml.get("confidence") else 0
    score = min(99, round(base_score * 0.75 + ml_score * 0.25))
    if base_score < 20 and ml_score == 0:
        score = base_score
    if score >= 75:
        verdict, level = "Malicious", "critical"
    elif score >= 45:
        verdict, level = "Suspicious", "high"
    elif score >= 20:
        verdict, level = "Needs Review", "medium"
    else:
        verdict, level = "Likely Safe", "low"

    if any(word in (subject + body).lower() for word in ("invoice", "payment", "wire", "gift card", "urgent", "verify")):
        category = "BEC" if any(word in (subject + body).lower() for word in ("invoice", "payment", "wire", "gift card")) else "PHISHING"
    elif rules["risk_score"] >= 45:
        category = "PHISHING"
    else:
        category = "SAFE"

    headers_result = parse_headers(headers)
    explanations = list(rules["evidence"])
    explanations.extend(headers_result["anomalies"])
    evidence = list(dict.fromkeys(explanations))
    if not evidence:
        evidence = ["No high-confidence threat indicators"]

    classification = rules["classification"]
    if classification == "SAFE" and score >= 45:
        classification = "SUSPICIOUS"
    if any("domain" in item.lower() or "brand" in item.lower() for item in evidence):
        classification = "IMPERSONATION" if score >= 20 else "PHISHING"

    mitre = ["T1566.002 Spearphishing Link"] if any("link" in item.lower() for item in evidence) else []
    if category in {"BEC", "PHISHING"}:
        mitre.append("T1656 Phishing for Information")
    iocs = extract_iocs(subject, sender, body, headers)
    enrichments = [enrich_indicator(kind, value) for kind, value in iocs]
    model_name = "AI/Heuristic Demo Analysis"
    explanation = "AI/Heuristic Demo Analysis: " + "; ".join(evidence[:5])
    return {
        "score": score,
        "risk_score": score,
        "verdict": verdict,
        "level": level,
        "risk_level": level,
        "category": category,
        "classification": classification,
        "confidence": max(50, min(99, round((rules["confidence"] + ml.get("confidence", 0)) / 2))),
        "indicators": evidence,
        "evidence": evidence,
        "explanation": explanation,
        "mitre": mitre,
        "headers": headers_result,
        "iocs": iocs,
        "enrichments": enrichments,
        "model": model_name,
    }
