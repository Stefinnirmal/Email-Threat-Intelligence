"""
Indicator Extractor Module
Extracts URLs, domains, IP addresses, and email addresses from email content.
"""

import re
from urllib.parse import urlparse
from typing import List, Dict, Set


# ── Regex patterns ────────────────────────────────────────────────────────────

URL_PATTERN = re.compile(
    r"(?:https?://|ftp://|www\.)"   # scheme or www
    r"(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)",
    re.IGNORECASE,
)

# More precise IPv4 pattern
IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b"
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

DOMAIN_FROM_EMAIL_PATTERN = re.compile(
    r"@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})"
)

# Private/reserved IP ranges
PRIVATE_IP_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^0\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^224\."),
    re.compile(r"^255\."),
    re.compile(r"^::1$"),
]

# URL shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.link", "tiny.cc", "rb.gy", "is.gd", "cutt.ly", "shorturl.at",
}

# Keywords that indicate suspicious URLs
SUSPICIOUS_URL_KEYWORDS = [
    "verify", "login", "secure", "account", "update", "confirm",
    "password", "reset", "suspended", "urgent", "alert", "warning",
    "claim", "prize", "winner", "reward", "free", "click", "signin",
]


def is_private_ip(ip: str) -> bool:
    """Check if an IP is in a private/reserved range."""
    return any(p.match(ip) for p in PRIVATE_IP_RANGES)


def is_ip_hostname(hostname: str) -> bool:
    """Check if a URL hostname is a raw IP address."""
    return bool(IPV4_PATTERN.fullmatch(hostname.strip()))


def analyze_url(url: str) -> Dict:
    """Parse and score a single URL for suspicious characteristics."""
    indicators = []
    risk_score = 0

    try:
        if not url.startswith(("http://", "https://", "ftp://")):
            url = "http://" + url
        parsed = urlparse(url)
    except Exception:
        return {
            "url": url,
            "domain": "parse_error",
            "scheme": "unknown",
            "path": "",
            "is_https": False,
            "is_ip_hostname": False,
            "is_shortener": False,
            "suspicious_indicators": ["URL parse error"],
            "risk_score": 1,
        }

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full_url = url

    is_https = scheme == "https"
    ip_host = is_ip_hostname(hostname)
    shortener = hostname in URL_SHORTENERS

    if not is_https:
        indicators.append("Uses HTTP (unencrypted)")
        risk_score += 1

    if ip_host:
        indicators.append("IP address used directly as hostname")
        risk_score += 2

    if shortener:
        indicators.append("URL shortener service detected")
        risk_score += 1

    if len(full_url) > 100:
        indicators.append(f"Unusually long URL ({len(full_url)} chars)")
        risk_score += 1

    subdomain_count = hostname.count(".") - 1 if hostname else 0
    if subdomain_count >= 3:
        indicators.append(f"Excessive subdomains ({subdomain_count})")
        risk_score += 1

    url_lower = full_url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in url_lower]
    if found_keywords:
        indicators.append(f"Suspicious keywords: {', '.join(found_keywords[:5])}")
        risk_score += 1

    # Check for unusual characters
    if "%" in path or "@" in hostname:
        indicators.append("Unusual encoding or @ in URL")
        risk_score += 1

    # Check for brand impersonation patterns (e.g., "paypal" in non-paypal domain)
    brands = ["paypal", "google", "microsoft", "apple", "amazon", "facebook",
              "netflix", "bank", "irs", "fedex", "dropbox", "icloud"]
    domain_lower = hostname.lower()
    for brand in brands:
        if brand in url_lower and not domain_lower.endswith(f"{brand}.com"):
            indicators.append(f"Possible brand impersonation: '{brand}'")
            risk_score += 2
            break

    return {
        "url": url,
        "domain": hostname,
        "scheme": scheme,
        "path": path,
        "is_https": is_https,
        "is_ip_hostname": ip_host,
        "is_shortener": shortener,
        "suspicious_indicators": indicators,
        "risk_score": risk_score,
    }


def extract_urls(text: str) -> List[Dict]:
    """Extract and analyze all URLs from text."""
    if not text:
        return []
    raw_urls = URL_PATTERN.findall(text)
    seen: Set[str] = set()
    results = []
    for url in raw_urls:
        # Normalize
        url = url.rstrip(".,;\"'><)}")
        if url in seen:
            continue
        seen.add(url)
        results.append(analyze_url(url))
    return results


def extract_ip_addresses(text: str, include_private: bool = False) -> List[str]:
    """Extract unique IP addresses from text."""
    if not text:
        return []
    ips = IPV4_PATTERN.findall(text)
    seen: Set[str] = set()
    result = []
    for ip in ips:
        if ip in seen:
            continue
        seen.add(ip)
        if not include_private and is_private_ip(ip):
            continue
        result.append(ip)
    return result


def extract_email_addresses(text: str) -> List[str]:
    """Extract unique email addresses from text."""
    if not text:
        return []
    emails = EMAIL_PATTERN.findall(text)
    return list(dict.fromkeys(emails))  # preserve order, deduplicate


def extract_domains_from_emails(text: str) -> List[str]:
    """Extract domains from email addresses in text."""
    if not text:
        return []
    domains = DOMAIN_FROM_EMAIL_PATTERN.findall(text)
    return list(dict.fromkeys(domains))


def extract_domains_from_urls(url_list: List[Dict]) -> List[str]:
    """Extract unique domains from analyzed URL list."""
    seen: Set[str] = set()
    result = []
    for url_info in url_list:
        domain = url_info.get("domain", "")
        if domain and domain != "parse_error" and domain not in seen:
            seen.add(domain)
            result.append(domain)
    return result


def extract_all_indicators(email_body: str, email_headers: str = "") -> Dict:
    """
    Master extraction function. Combines body + header analysis.

    Returns
    -------
    dict with:
        urls: list of analyzed URL dicts
        domains: list of unique domain strings
        ips: list of unique public IP strings
        email_addresses: list of unique email address strings
        ip_from_headers: list of IPs found in headers
        summary: counts dict
    """
    combined_text = f"{email_body}\n{email_headers}"

    urls = extract_urls(combined_text)
    ips_body = extract_ip_addresses(email_body)
    ips_headers = extract_ip_addresses(email_headers)
    email_addresses = extract_email_addresses(combined_text)

    # Merge IPs, deduplicate
    all_ips = list(dict.fromkeys(ips_body + ips_headers))

    # Domains from URLs + email addresses
    url_domains = extract_domains_from_urls(urls)
    email_domains = extract_domains_from_emails(combined_text)
    all_domains = list(dict.fromkeys(url_domains + email_domains))

    return {
        "urls": urls,
        "domains": all_domains,
        "ips": all_ips,
        "email_addresses": email_addresses,
        "ip_from_headers": list(dict.fromkeys(ips_headers)),
        "summary": {
            "url_count": len(urls),
            "domain_count": len(all_domains),
            "ip_count": len(all_ips),
            "email_count": len(email_addresses),
            "total": len(urls) + len(all_domains) + len(all_ips) + len(email_addresses),
        },
    }
