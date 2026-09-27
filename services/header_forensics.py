import re
from email import policy
from email.parser import BytesParser

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _domain(value):
    if not value:
        return ""
    cleaned = value.strip().replace("<", "").replace(">", "")
    if "@" in cleaned:
        cleaned = cleaned.split("@", 1)[1]
    return cleaned.lower().strip("()[]")


def parse_headers(raw_headers):
    raw_headers = raw_headers or ""
    message = BytesParser(policy=policy.default).parsebytes(raw_headers.encode("utf-8", errors="replace"))
    received = message.get_all("Received", [])
    auth = message.get("Authentication-Results", "")
    spf_match = re.search(r"spf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|unknown)", auth, re.I)
    dkim_match = re.search(r"dkim\s*=\s*(pass|fail|none|temperror|permerror|unknown)", auth, re.I)
    dmarc_match = re.search(r"dmarc\s*=\s*(pass|fail|none|temperror|permerror|unknown)", auth, re.I)
    spf = spf_match.group(1).lower() if spf_match else "unknown"
    dkim = dkim_match.group(1).lower() if dkim_match else "unknown"
    dmarc = dmarc_match.group(1).lower() if dmarc_match else "unknown"
    received_ips = []
    for hop in received:
        received_ips.extend(IP_PATTERN.findall(hop))
    anomalies = []
    sender = message.get("From", "")
    reply_to = message.get("Reply-To", "")
    return_path = message.get("Return-Path", "")
    sender_domain = _domain(sender)
    reply_domain = _domain(reply_to)
    return_domain = _domain(return_path)
    if reply_to and sender and reply_domain and sender_domain and reply_domain != sender_domain:
        anomalies.append("Reply-To domain differs from From domain")
    if return_path and sender and return_domain and sender_domain and return_domain != sender_domain:
        anomalies.append("Return-Path domain differs from From domain")
    if any(status in {"fail", "softfail", "temperror", "permerror"} for status in (spf, dkim, dmarc)):
        anomalies.append("One or more email authentication checks failed or are degraded")
    if any(hop.lower().find("mx") >= 0 for hop in received):
        anomalies.append("Received header path indicates a remote relay or external MX hop")
    return {
        "message_id": message.get("Message-ID", ""),
        "return_path": return_path,
        "reply_to": reply_to,
        "authentication": {"spf": spf, "dkim": dkim, "dmarc": dmarc},
        "received_chain": received,
        "received_ips": list(dict.fromkeys(received_ips)),
        "anomalies": anomalies,
    }
