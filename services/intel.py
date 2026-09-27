import os
import socket
from services.geo import locate_ip


def enrich_indicator(kind, value):
    provider = "offline-fallback"
    result = {"indicator": value, "kind": kind, "verdict": "unknown", "confidence": 15, "provider": provider, "details": {}}
    if kind == "ip":
        location = locate_ip(value)
        result["details"] = location
        result["verdict"] = "private" if location["country"] == "Private network" else "unverified"
    elif kind == "domain":
        try:
            result["details"] = {"dns": socket.gethostbyname_ex(value)[2], "note": "Passive DNS lookup; no reputation claim"}
            result["verdict"] = "resolves"
            result["confidence"] = 30
        except socket.gaierror:
            result["details"] = {"note": "Domain did not resolve from this environment"}
            result["verdict"] = "unresolved"
    elif kind == "url":
        result["details"] = {"note": "No paid URL reputation API configured", "api_configured": bool(os.getenv("URLSCAN_API_KEY"))}
    elif kind == "sha256":
        result["details"] = {"note": "Hash ready for VirusTotal/OTX lookup", "api_configured": bool(os.getenv("VIRUSTOTAL_API_KEY"))}
    return result
