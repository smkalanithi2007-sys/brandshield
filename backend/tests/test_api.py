import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

import main
from database import SessionLocal
from models import Brand, Finding, ScanRun, User


@pytest.fixture
def client():
    with TestClient(main.app) as test_client:
        with SessionLocal() as db:
            db.execute(delete(Finding))
            db.execute(delete(ScanRun))
            db.execute(delete(Brand))
            db.execute(delete(User))
            db.commit()
        yield test_client


def register(client: TestClient, email: str) -> dict:
    response = client.post(
        "/api/auth/register",
        json={"email": email, "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 200, response.text
    return response.json()["user"]


def test_health_and_frontend_are_served_by_backend(client: TestClient) -> None:
    assert client.get("/health").json()["status"] == "ok"
    response = client.get("/")
    assert response.status_code == 200
    assert "LIVE THREAT-INTELLIGENCE SOURCES" in response.text


def test_accounts_brands_scans_and_findings_are_isolated(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = register(client, "owner@example.com")
    owner_cookie = client.cookies.get(main.SESSION_COOKIE)
    assert owner_cookie

    brand_response = client.post(
        "/api/brands",
        json={
            "name": "Example Brand",
            "domain": "https://example.com/about",
            "monitoring_interval_hours": 24,
            "external_lookup_consent": True,
        },
    )
    assert brand_response.status_code == 201, brand_response.text
    brand = brand_response.json()
    assert brand["domain"] == "example.com"
    assert brand["external_lookup_consent"] is True

    monkeypatch.setattr(
        main,
        "scan_brand",
        lambda _name, _domain: (
            [{
                "source": "Test provider",
                "category": "Test lead",
                "severity": "Informational",
                "title": "Unverified result",
                "url": "https://example.net/result",
                "details": "Test data only.",
            }],
            [{
                "provider": "Test provider",
                "status": "checked",
                "message": "Test response.",
                "matches": 1,
            }],
        ),
    )

    scan_response = client.post(f"/api/brands/{brand['id']}/scan")
    assert scan_response.status_code == 200, scan_response.text
    scan = scan_response.json()
    assert scan["scan_status"] == "completed"
    assert scan["findings"][0]["title"] == "Unverified result"
    assert client.get("/api/findings").json()["items"][0]["source"] == "Test provider"
    assert client.get("/api/reports").json()["total_findings"] == 1

    client.cookies.clear()
    other_user = register(client, "other@example.com")
    assert other_user["id"] != owner["id"]
    assert client.get("/api/brands").json()["items"] == []
    assert client.get("/api/findings").json()["items"] == []
    assert client.delete(f"/api/brands/{brand['id']}").status_code == 404

    client.cookies.set(main.SESSION_COOKIE, owner_cookie)
    assert len(client.get("/api/brands").json()["items"]) == 1


def test_one_off_scans_require_external_lookup_consent(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    register(client, "scan@example.com")
    monkeypatch.setattr(main, "scan_brand", lambda *_args: ([], []))

    response = client.post(
        "/api/scans",
        json={"brand_name": "Example Brand", "domain": "example.com"},
    )
    assert response.status_code == 400
    assert "Consent" in response.json()["detail"]

    accepted = client.post(
        "/api/scans",
        json={
            "brand_name": "Example Brand",
            "domain": "example.com",
            "external_lookup_consent": True,
        },
    )
    assert accepted.status_code == 200


def test_public_one_off_scan_does_not_require_login_or_save_results(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        main,
        "scan_brand",
        lambda _name, _domain: (
            [{
                "source": "Test provider",
                "category": "Test lead",
                "severity": "Informational",
                "title": "Unverified result",
                "url": "https://example.net/result",
                "details": "Test data only.",
            }],
            [{
                "provider": "Test provider",
                "status": "checked",
                "message": "Test response.",
                "matches": 1,
            }],
        ),
    )

    missing_consent = client.post(
        "/api/public/scans",
        json={"brand_name": "Example Brand", "domain": "example.com"},
    )
    assert missing_consent.status_code == 400

    response = client.post(
        "/api/public/scans",
        json={
            "brand_name": "Example Brand",
            "domain": "https://example.com/about",
            "external_lookup_consent": True,
        },
    )
    assert response.status_code == 200, response.text
    scan = response.json()
    assert scan["id"] is None
    assert scan["brand_name"] == "Example Brand"
    assert scan["domain"] == "example.com"
    assert scan["scan_status"] == "completed"
    assert scan["findings"][0]["title"] == "Unverified result"

    with SessionLocal() as db:
        assert db.query(ScanRun).count() == 0
        assert db.query(Finding).count() == 0


def test_domains_are_normalized_and_private_targets_rejected() -> None:
    assert main.normalize_domain("https://Example.COM/path") == "example.com"
    with pytest.raises(main.HTTPException) as error:
        main.normalize_domain("http://127.0.0.1")
    assert error.value.status_code == 400

    with pytest.raises(main.HTTPException):
        main.normalize_domain("https://user:password@example.com")
