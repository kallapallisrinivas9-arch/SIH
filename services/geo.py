import ipaddress
import json
import os
from urllib.error import URLError
from urllib.request import Request, urlopen


def _online_location(ip):
    if os.getenv("GEOIP_LOOKUP", "auto").lower() == "off":
        return None
    endpoint = os.getenv("GEOIP_LOOKUP_URL", "https://ipapi.co/{ip}/json/").format(ip=ip)
    try:
        request = Request(endpoint, headers={"User-Agent": "SentinelMail/2.0"})
        with urlopen(request, timeout=float(os.getenv("GEOIP_TIMEOUT", "2"))) as response:
            payload = json.load(response)
    except (OSError, URLError, ValueError, TypeError):
        return None
    if not isinstance(payload, dict) or payload.get("error") or not payload.get("country_name"):
        return None
    try:
        latitude = float(payload["latitude"])
        longitude = float(payload["longitude"])
    except (KeyError, TypeError, ValueError):
        latitude = longitude = None
    return {
        "ip": ip,
        "country": payload.get("country_name", "Unknown"),
        "city": payload.get("city", "Unknown"),
        "region": payload.get("region", payload.get("region_code", "Unknown")),
        "latitude": latitude,
        "longitude": longitude,
        "source": "online GeoIP",
        "accuracy_radius_km": 25,
        "confidence": "medium",
        "vpn_status": "not verified"
    }


def locate_ip(value):
    value = (value or "").strip()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return {"ip": value or "Unknown", "country": "Unknown", "city": "Unknown", "region": "Unknown", "source": "validation", "accuracy_radius_km": None, "confidence": "none", "vpn_status": "not verified"}
    if ip.is_private or ip.is_loopback:
        return {"ip": value, "country": "Private network", "city": "Internal", "region": "Local network", "source": "local classification", "accuracy_radius_km": None, "confidence": "network only", "vpn_status": "not verified"}
    online = _online_location(value)
    if online:
        return online
    return {"ip": value, "country": "Enrichment pending", "city": "External network", "region": "Unknown region", "source": "offline fallback", "accuracy_radius_km": None, "confidence": "low", "vpn_status": "not verified"}
