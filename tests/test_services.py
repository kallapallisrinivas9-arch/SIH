from services.analyzer import analyze_email
from services.evidence import evidence_hash
from services.header_forensics import parse_headers
from services.intelligence import analyze_message
import services.geo as geo
from services.geo import locate_ip


def test_safe_email_has_low_risk():
    result = analyze_email("Team update", "hr@acme.in", "The meeting is at 10 AM.")
    assert result["level"] == "low"
    assert result["score"] < 20


def test_lookalike_link_is_malicious():
    result = analyze_email("Account suspended - verify", "alert@micr0soft-support.com", "Verify immediately at https://evil.example/login")
    assert result["verdict"] == "Malicious"
    assert len(result["indicators"]) >= 3


def test_analyze_message_exposes_explainable_evidence():
    result = analyze_message(
        "Urgent invoice payment required",
        "billing@secure-payments.com",
        "finance@acme.in",
        "Please review the attached invoice and pay immediately at https://paypa1.example/login",
        "From: billing@secure-payments.com\r\nReply-To: finance@paypa1-example.com\r\nReturn-Path: <bounce@paypa1-example.com>\r\nReceived: from mx.paypa1-example.com (203.0.113.11)\r\nAuthentication-Results: spf=fail dkim=fail dmarc=fail",
    )
    assert result["risk_score"] >= 70
    assert result["classification"] in {"PHISHING", "SUSPICIOUS", "IMPERSONATION"}
    assert any("SPF/DKIM/DMARC" in item or "spf" in item.lower() for item in result["evidence"])
    assert "DEMO" in result["model"].upper() or "demo" in result["explanation"].lower()


def test_parse_headers_flags_auth_and_route_anomalies():
    result = parse_headers(
        "From: finance@acme.in\r\nReply-To: billing@fake-paypal.com\r\nReturn-Path: <bounce@fake-paypal.com>\r\nReceived: from mx1.example.net (203.0.113.5)\r\nReceived: from relay.example.net (198.51.100.9)\r\nAuthentication-Results: spf=fail dkim=fail dmarc=fail"
    )
    assert result["authentication"]["spf"] == "fail"
    assert any("Reply-To domain differs" in item for item in result["anomalies"])
    assert len(result["received_ips"]) >= 2


def test_private_ip_is_classified_without_network_call():
    assert locate_ip("10.0.0.1")["country"] == "Private network"
    assert locate_ip("not-an-ip")["source"] == "validation"


def test_public_ip_uses_online_geoip_when_available(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def __iter__(self):
            return iter(())

        def read(self):
            return b""

    monkeypatch.setattr(geo, "urlopen", lambda request, timeout: Response())
    monkeypatch.setattr(geo.json, "load", lambda response: {"country_name": "India", "city": "Mumbai", "region": "Maharashtra", "latitude": 19.076, "longitude": 72.8777})
    result = locate_ip("8.8.8.8")
    assert result["source"] == "online GeoIP"
    assert result["city"] == "Mumbai"
    assert result["accuracy_radius_km"] == 25


def test_geoip_can_be_disabled_for_offline_mode(monkeypatch):
    monkeypatch.setenv("GEOIP_LOOKUP", "off")
    assert locate_ip("8.8.8.8")["source"] == "offline fallback"


def test_hash_is_deterministic():
    assert evidence_hash({"b": 2, "a": 1}) == evidence_hash({"a": 1, "b": 2})
