import hashlib
import re
from urllib.parse import urlparse

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.I)
DOMAIN_PATTERN = re.compile(r"(?<!@)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)


def extract_iocs(subject, sender, body, headers):
    text = "\n".join((subject, sender, body, headers))
    values = []
    for value in IP_PATTERN.findall(text):
        values.append(("ip", value))
    for value in URL_PATTERN.findall(text):
        values.append(("url", value.rstrip(".,;")))
    for value in DOMAIN_PATTERN.findall(text):
        if value.lower() not in {"acme.in", "gmail.com", "outlook.com", "microsoft.com"}:
            values.append(("domain", value.lower()))
    digest = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
    values.append(("sha256", digest))
    return list(dict.fromkeys(values))
