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
