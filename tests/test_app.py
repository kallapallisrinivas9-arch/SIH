from tests.conftest import csrf


def test_login_and_dashboard(client):
    token = csrf(client)
    response = client.post("/login", data={"email": "analyst@sih.local", "password": "Demo@12345", "csrf_token": token}, follow_redirects=True)
    assert response.status_code == 200
    assert b"SOC Command Center" in response.data
    assert b"/infrastructure" in response.data
    assert b'target="_blank"' in response.data


def test_infrastructure_page_opens_for_authenticated_user(client):
    token = csrf(client)
    client.post("/login", data={"email": "analyst@sih.local", "password": "Demo@12345", "csrf_token": token})
    response = client.get("/infrastructure")
    assert response.status_code == 200
    assert b"INFRASTRUCTURE INTELLIGENCE" in response.data
    assert b"185.220.101.44" in response.data


def test_analysis_creates_verifiable_case(client):
    token = csrf(client)
    client.post("/login", data={"email": "analyst@sih.local", "password": "Demo@12345", "csrf_token": token})
    response = client.post("/api/analyze", data={"subject": "Urgent verify account", "sender": "bad@micr0soft-support.com", "recipient": "x@acme.in", "body": "Click https://evil.example/verify immediately", "source_ip": "192.168.1.4"}, headers={"X-CSRF-Token": token})
    assert response.status_code == 200
    assert response.json["verdict"] == "Malicious"
    assert response.json["evidence_hash"]


def test_analysis_rejects_empty_required_fields(client):
    token = csrf(client)
    client.post("/login", data={"email": "analyst@sih.local", "password": "Demo@12345", "csrf_token": token})
    response = client.post("/api/analyze", json={}, headers={"X-CSRF-Token": token})
    assert response.status_code == 400
    assert "required" in response.json["error"]


def test_analysis_requires_authentication(client):
    token = csrf(client)
    response = client.post("/api/analyze", data={}, headers={"X-CSRF-Token": token})
    assert response.status_code == 302
