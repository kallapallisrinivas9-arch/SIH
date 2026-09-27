import re
from urllib.parse import urlparse

URGENCY = re.compile(r"\b(urgent|immediately|24 hours|action required|verify|suspended|expire|password expiry|invoice|pay now|secure your account)\b", re.I)
URL_PATTERN = re.compile(r"https?://[^\s<>]+", re.I)
ATTACHMENT = re.compile(r"\b(invoice|payment|attachment|document|resume|refund|benefits|policy)\b", re.I)
TRUSTED_DOMAINS = {"acme.in", "gmail.com", "outlook.com", "microsoft.com", "example.com"}


def _classify(score):
    if score >= 75:
        return "Malicious", "critical"
    if score >= 45:
        return "Suspicious", "high"
    if score >= 20:
        return "Needs Review", "medium"
    return "Likely Safe", "low"


def analyze_email(subject, sender, body, headers=""):
    text = f"{subject}\n{sender}\n{body}\n{headers or ''}"
    score = 0
    evidence = []
    sender_domain = sender.lower().split("@")[-1] if "@" in sender else "unknown"

    if sender_domain not in TRUSTED_DOMAINS:
        score += 25
        evidence.append("External or unrecognized sender domain")
    if any(ch.isdigit() for ch in sender_domain) or any(token in sender_domain for token in ("micr0", "secure-login", "verify-account", "paypa1", "update-your", "support-login")):
        score += 35
        evidence.append("Lookalike or suspicious sender domain")
    if URGENCY.search(text):
        score += 18
        evidence.append("Urgency or account-pressure language")
    urls = URL_PATTERN.findall(text)
    if urls:
        score += min(25, len(urls) * 12)
        evidence.append(f"{len(urls)} embedded link(s) require verification")
        for url in urls:
            host = urlparse(url).netloc.lower()
            if host and sender_domain not in host and not host.endswith(tuple(TRUSTED_DOMAINS)):
                score += 10
                evidence.append("Link domain differs from sender domain or appears impersonating the brand")
                break
    if ATTACHMENT.search(text):
        score += 12
        evidence.append("Financial or attachment lure detected")
    auth_text = (headers or "").lower()
    if auth_text and ("spf=fail" in auth_text or "dkim=fail" in auth_text or "dmarc=fail" in auth_text):
        score += 18
        evidence.append("SPF/DKIM/DMARC authentication failed")
    if any(token in text.lower() for token in ("click here", "verify immediately", "confirm your password", "reset your account")):
        score += 10
        evidence.append("Credential theft CTA detected")

    score = min(score, 99)
    verdict, level = _classify(score)
    explanation = "AI/Heuristic Demo Analysis: " + "; ".join(dict.fromkeys(evidence)) if evidence else "AI/Heuristic Demo Analysis: No suspicious indicators were confidently matched."
    classification = "SAFE" if score < 20 else "SUSPICIOUS" if score < 45 else "PHISHING" if score >= 75 else "IMPERSONATION" if any("domain" in item.lower() or "brand" in item.lower() for item in evidence) else "SUSPICIOUS"
    return {
        "score": score,
        "risk_score": score,
        "verdict": verdict,
        "level": level,
        "risk_level": level,
        "indicators": evidence or ["No high-confidence threat indicators"],
        "evidence": evidence or ["No high-confidence threat indicators"],
        "explanation": explanation,
        "classification": classification,
        "confidence": max(45, min(96, score)),
        "model": "AI/Heuristic Demo Analysis",
    }
