import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import quote

import httpx


@dataclass
class ProviderResult:
    provider: str
    status: str
    message: str
    matches: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def configured_sources() -> list[dict[str, str]]:
    return [
        {
            "provider": "Google Web Risk",
            "status": (
                "configured" if os.getenv("GOOGLE_WEBRISK_API_KEY")
                else "not_configured"
            ),
            "coverage": "Google's live unsafe-URL threat lists",
        },
        {
            "provider": "VirusTotal",
            "status": (
                "configured" if os.getenv("VIRUSTOTAL_API_KEY")
                else "not_configured"
            ),
            "coverage": (
                "Existing domain reputation reports; URLs are looked up, "
                "not submitted for public scanning"
            ),
        },
        {
            "provider": "Brave Search",
            "status": (
                "configured" if os.getenv("BRAVE_SEARCH_API_KEY")
                else "not_configured"
            ),
            "coverage": (
                "Search-result leads for social profiles and Google Play "
                "listings; results require human verification"
            ),
        },
        {
            "provider": "Apple App Store Search",
            "status": "configured",
            "coverage": "Public iTunes catalog search",
        },
    ]


def _error_message(response: httpx.Response) -> str:
    if response.status_code == 429:
        return "The provider rate limit was reached; retry later."
    if response.status_code in (401, 403):
        return "The provider rejected its API key or account permissions."
    return f"The provider returned HTTP {response.status_code}."


def _check_webrisk(client: httpx.Client, url: str) -> tuple[ProviderResult, list[dict]]:
    api_key = os.getenv("GOOGLE_WEBRISK_API_KEY")
    if not api_key:
        return (
            ProviderResult("Google Web Risk", "not_configured",
                           "Set GOOGLE_WEBRISK_API_KEY to enable URL checks."),
            [],
        )

    try:
        response = client.get(
            "https://webrisk.googleapis.com/v1/uris:search",
            params={
                "uri": url,
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                ],
                "key": api_key,
            },
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Web Risk response is not an object.")
        threat = payload.get("threat", {})
        if not isinstance(threat, dict):
            raise ValueError("Web Risk threat data is not an object.")
    except httpx.HTTPStatusError as error:
        return ProviderResult(
            "Google Web Risk", "unavailable",
            _error_message(error.response),
        ), []
    except (httpx.RequestError, ValueError, TypeError):
        return ProviderResult(
            "Google Web Risk", "unavailable",
            "The provider request or response could not be processed.",
        ), []

    if not threat:
        return ProviderResult(
            "Google Web Risk", "checked", "No threat match was returned."
        ), []

    types = threat.get("threatTypes", [])
    if not isinstance(types, list) or not all(
        isinstance(item, str) for item in types
    ):
        return ProviderResult(
            "Google Web Risk", "unavailable",
            "The provider returned an invalid threat-type list.",
        ), []
    return (
        ProviderResult("Google Web Risk", "checked",
                       f"Threat match returned: {', '.join(types)}.", 1),
        [{
            "source": "Google Web Risk",
            "category": "Known unsafe URL",
            "severity": "High",
            "title": "Google Web Risk returned a threat match",
            "url": url,
            "details": (
                "The submitted official-domain URL matched a configured "
                "Google Web Risk threat type: "
                f"{', '.join(types)}. Verify this result with the provider."
            ),
        }],
    )


def _check_virustotal(
    client: httpx.Client, domain: str
) -> tuple[ProviderResult, list[dict]]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return (
            ProviderResult("VirusTotal", "not_configured",
                           "Set VIRUSTOTAL_API_KEY to enable lookups."),
            [],
        )

    try:
        response = client.get(
            f"https://www.virustotal.com/api/v3/domains/{quote(domain, safe='')}",
            headers={"x-apikey": api_key},
        )
        if response.status_code == 404:
            return ProviderResult(
                "VirusTotal", "checked",
                "No existing domain report was found; this is not a clean verdict.",
            ), []
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("VirusTotal response is not an object.")
        attributes = payload["data"]["attributes"]
        if not isinstance(attributes, dict):
            raise ValueError("VirusTotal attributes are not an object.")
        stats = attributes.get("last_analysis_stats", {})
        if not isinstance(stats, dict):
            raise ValueError("VirusTotal statistics are not an object.")
    except httpx.HTTPStatusError as error:
        return ProviderResult(
            "VirusTotal", "unavailable", _error_message(error.response)
        ), []
    except (httpx.RequestError, ValueError, KeyError, TypeError):
        return ProviderResult(
            "VirusTotal", "unavailable",
            "The provider request or response could not be processed.",
        ), []

    try:
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
    except (TypeError, ValueError):
        return ProviderResult(
            "VirusTotal", "unavailable",
            "The provider returned invalid analysis counts.",
        ), []
    if malicious < 0 or suspicious < 0:
        return ProviderResult(
            "VirusTotal", "unavailable",
            "The provider returned invalid analysis counts.",
        ), []
    if malicious == 0 and suspicious == 0:
        return ProviderResult(
            "VirusTotal", "checked",
            "The existing report contains no malicious or suspicious detections.",
        ), []

    severity = "High" if malicious else "Medium"
    return (
        ProviderResult(
            "VirusTotal", "checked",
            f"Existing report: {malicious} malicious and {suspicious} "
            "suspicious engine results.",
            malicious + suspicious,
        ),
        [{
            "source": "VirusTotal",
            "category": "Domain reputation",
            "severity": severity,
            "title": f"Existing domain report has {malicious + suspicious} "
                     "detections",
            "url": f"https://www.virustotal.com/gui/domain/{quote(domain, safe='')}",
            "details": (
                f"Existing report counts: {malicious} malicious and "
                f"{suspicious} suspicious. Vendor results can disagree; "
                "review the provider report."
            ),
        }],
    )


def _brave_search(
    client: httpx.Client,
    query: str,
    category: str,
) -> tuple[ProviderResult, list[dict]]:
    api_key = os.getenv("BRAVE_SEARCH_API_KEY")
    provider = "Brave Search"
    if not api_key:
        return (
            ProviderResult(provider, "not_configured",
                           "Set BRAVE_SEARCH_API_KEY to enable search discovery."),
            [],
        )

    try:
        response = client.get(
            "https://api.search.brave.com/res/v1/web/search",
            params={"q": query, "count": 10},
            headers={"X-Subscription-Token": api_key},
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Brave Search response is not an object.")
        web = payload.get("web", {})
        if not isinstance(web, dict):
            raise ValueError("Brave Search results are not an object.")
        items = web.get("results", [])
        if not isinstance(items, list):
            raise ValueError("Brave Search results are not a list.")
    except httpx.HTTPStatusError as error:
        return ProviderResult(
            provider, "unavailable", _error_message(error.response)
        ), []
    except (httpx.RequestError, ValueError, TypeError):
        return ProviderResult(
            provider, "unavailable",
            "The provider request or response could not be processed.",
        ), []

    findings = []
    for item in items:
        if not isinstance(item, dict):
            continue
        result_url = item.get("url", "")
        if not result_url.startswith(("https://", "http://")):
            continue
        findings.append({
            "source": provider,
            "category": category,
            "severity": "Informational",
            "title": str(item.get("title") or "Search result")[:500],
            "url": result_url[:2000],
            "details": (
                "Unverified search-result lead. Search results do not prove "
                "impersonation, fraud, or app safety; investigate the "
                "publisher and evidence before acting. "
                f"{str(item.get('description') or '')[:1000]}"
            ),
        })

    return (
        ProviderResult(
            provider, "checked",
            f"Found {len(findings)} unverified search-result lead(s).",
            len(findings),
        ),
        findings,
    )


def _apple_search(
    client: httpx.Client, brand_name: str
) -> tuple[ProviderResult, list[dict]]:
    try:
        response = client.get(
            "https://itunes.apple.com/search",
            params={
                "term": brand_name,
                "entity": "software",
                "limit": 10,
            },
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Apple Search response is not an object.")
        items = payload.get("results", [])
        if not isinstance(items, list):
            raise ValueError("Apple Search results are not a list.")
    except httpx.HTTPStatusError as error:
        return ProviderResult(
            "Apple App Store Search", "unavailable",
            _error_message(error.response),
        ), []
    except (httpx.RequestError, ValueError, TypeError):
        return ProviderResult(
            "Apple App Store Search", "unavailable",
            "The provider request or response could not be processed.",
        ), []

    findings = [{
        "source": "Apple App Store Search",
        "category": "App-store candidate",
        "severity": "Informational",
        "title": str(item.get("trackName") or "App Store result")[:500],
        "url": str(item.get("trackViewUrl") or "")[:2000],
        "details": (
            "Unverified public catalog match. Confirm the developer/publisher "
            "and official links; a name match alone does not indicate a fake app."
        ),
    } for item in items
        if isinstance(item, dict)
        and str(item.get("trackViewUrl", "")).startswith("https://")]
    return (
        ProviderResult(
            "Apple App Store Search", "checked",
            f"Found {len(findings)} unverified catalog match(es).",
            len(findings),
        ),
        findings,
    )


def scan_brand(
    brand_name: str, domain: str
) -> tuple[list[dict], list[dict[str, Any]]]:
    findings: list[dict] = []
    results: list[ProviderResult] = []
    timeout = httpx.Timeout(10.0, connect=4.0)

    with httpx.Client(timeout=timeout, follow_redirects=False) as client,             ThreadPoolExecutor(max_workers=5) as executor:
        checks = []
        if domain:
            url = f"https://{domain}/"
            checks.extend((
                executor.submit(_check_webrisk, client, url),
                executor.submit(_check_virustotal, client, domain),
            ))
        else:
            results.extend((
                ProviderResult(
                    "Google Web Risk", "skipped",
                    "Add an official domain to check URL reputation.",
                ),
                ProviderResult(
                    "VirusTotal", "skipped",
                    "Add an official domain to check domain reputation.",
                ),
            ))

        social_query = (
            f'"{brand_name}" (site:instagram.com OR site:facebook.com OR '
            "site:tiktok.com OR site:x.com OR site:linkedin.com OR "
            "site:youtube.com)"
        )
        play_query = f'"{brand_name}" site:play.google.com/store/apps'
        checks.extend((
            executor.submit(
                _brave_search, client, social_query, "Social profile candidate"
            ),
            executor.submit(
                _brave_search, client, play_query, "Google Play listing candidate"
            ),
            executor.submit(_apple_search, client, brand_name),
        ))
        for check in checks:
            provider_result, provider_findings = check.result()
            results.append(provider_result)
            findings.extend(provider_findings)

    return findings, [item.as_dict() for item in results]
