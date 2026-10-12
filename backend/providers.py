import os
import re
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
            "details": f"Unverified catalog match. Listed publisher: {str(item.get('artistName') or 'Unknown publisher')[:300]}. Compare the developer and official links; a name match alone does not indicate a fake app.", []
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
            "details": f"Unverified catalog match. Listed publisher: {str(item.get('artistName') or 'Unknown publisher')[:300]}. Compare the developer and official links; a name match alone does not indicate a fake app.", []
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
            "details": f"Unverified catalog match. Listed publisher: {str(item.get('artistName') or 'Unknown publisher')[:300]}. Compare the developer and official links; a name match alone does not indicate a fake app.",
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
        "category": "App-store listing match",
        "severity": "Informational",
        "title": str(item.get("trackName") or "App Store result")[:500],
        "url": str(item.get("trackViewUrl") or "")[:2000],
        "details": f"Unverified catalog match. Listed publisher: {str(item.get('artistName') or 'Unknown publisher')[:300]}. Compare the developer and official links; a name match alone does not indicate a fake app.",
    } for item in items
        if isinstance(item, dict)
        and str(item.get("trackViewUrl", "")).startswith("https://") and re.sub(r"[^a-z0-9]", "", brand_name.casefold()) in re.sub(r"[^a-z0-9]", "", (str(item.get("trackName") or "") + " " + str(item.get("artistName") or "")).casefold())]
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
