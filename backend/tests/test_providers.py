from threading import Barrier

import providers
from providers import configured_sources


def test_provider_status_reports_unconfigured_secrets_explicitly(monkeypatch) -> None:
    monkeypatch.delenv("GOOGLE_WEBRISK_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)

    sources = {source["provider"]: source for source in configured_sources()}

    assert sources["Google Web Risk"]["status"] == "not_configured"
    assert sources["VirusTotal"]["status"] == "not_configured"
    assert sources["Brave Search"]["status"] == "not_configured"
    assert sources["Apple App Store Search"]["status"] == "configured"


def test_provider_lookups_run_concurrently(monkeypatch) -> None:
    barrier = Barrier(5)

    def completed(provider: str) -> tuple[providers.ProviderResult, list[dict]]:
        barrier.wait(timeout=2)
        return providers.ProviderResult(provider, "checked", "ok"), []

    monkeypatch.setattr(
        providers, "_check_webrisk",
        lambda _client, _url: completed("Google Web Risk"),
    )
    monkeypatch.setattr(
        providers, "_check_virustotal",
        lambda _client, _domain: completed("VirusTotal"),
    )
    monkeypatch.setattr(
        providers, "_brave_search",
        lambda _client, _query, _category: completed("Brave Search"),
    )
    monkeypatch.setattr(
        providers, "_apple_search",
        lambda _client, _brand_name: completed("Apple App Store Search"),
    )

    findings, results = providers.scan_brand("Example Brand", "example.com")

    assert findings == []
    assert [item["provider"] for item in results] == [
        "Google Web Risk",
        "VirusTotal",
        "Brave Search",
        "Brave Search",
        "Apple App Store Search",
    ]
    assert all(item["status"] == "checked" for item in results)
