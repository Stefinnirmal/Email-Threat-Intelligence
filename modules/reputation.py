"""
Reputation Module
Checks domain and IP reputation using local prototype lists.
Supports external API integration via environment variables.
All prototype/demo results are clearly labeled.
"""

import os
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Prototype reputation lists ────────────────────────────────────────────────
# These are demonstration examples only. NOT real threat intelligence.

KNOWN_BAD_DOMAINS = {
    "suspicious-login.example",
    "paypal-secure-verify.net",
    "microsoftsecurity-alert.com",
    "prize-winner-claim.xyz",
    "bankofamerica-secure.ru",
    "email-upgrade-now.com",
    "accounts-google-reset.xyz",
    "refund-claim.net",
    "facebook-security-check.info",
    "free-iphone-giveaway.xyz",
    "netflix-billing-update.xyz",
    "irs-refund-claim.net",
    "amazon-account-verify.ru",
    "dropbox-renew.xyz",
    "wellsfargo-secure-login.com",
    "pending-payment-claim.xyz",
    "appleid-security-verify.net",
    "confirm-email-account.xyz",
    "secure-password-reset.info",
    "domain-renew-urgent.xyz",
    "account-verify-now.xyz",
    "billing-update-secure.net",
    "docusign-secure-view.ru",
    "crypto-wallet-verify.xyz",
    "lottery-winner.xyz",
    "fedex-delivery-reschedule.xyz",
    "ssa-alert-verify.net",
    "hr-portal-salary.xyz",
    "icloud-storage-upgrade.xyz",
    "irs-investigation-response.xyz",
}

KNOWN_SUSPICIOUS_DOMAINS = {
    "login-secure-account.com",
    "verify-account-now.net",
    "secure-update-required.com",
    "account-security-alert.info",
    "update-payment-info.xyz",
    "password-reset-secure.net",
}

KNOWN_BAD_IPS = {
    "185.220.101.1",
    "185.220.101.2",
    "192.42.116.1",
    "103.251.167.10",
    "45.142.212.100",
    "91.108.4.1",
}

KNOWN_SUSPICIOUS_IPS = {
    "198.51.100.1",
    "203.0.113.1",
    "198.51.100.50",
}

# TLDs often associated with abuse (not proof of maliciousness)
HIGH_RISK_TLDS = {".xyz", ".ru", ".tk", ".ml", ".ga", ".cf", ".pw", ".top", ".info"}

# Hosting/VPN/proxy indicators (by keyword in org/asn)
PROXY_KEYWORDS = [
    "tor", "vpn", "proxy", "anonymizer", "hosting", "datacenter",
    "linode", "digitalocean", "vultr", "hetzner", "ovh",
    "cloudflare", "fastly", "akamai", "amazon", "google", "microsoft",
]


def _check_domain_local(domain: str) -> Dict:
    """Check domain against local prototype reputation lists."""
    domain = domain.lower().strip()
    rep = "Unknown"
    details = []
    confidence = "Low"

    if domain in KNOWN_BAD_DOMAINS:
        rep = "Malicious"
        details.append("Listed in prototype malicious domain list")
        confidence = "Prototype"
    elif domain in KNOWN_SUSPICIOUS_DOMAINS:
        rep = "Suspicious"
        details.append("Listed in prototype suspicious domain list")
        confidence = "Prototype"
    else:
        # TLD analysis
        for tld in HIGH_RISK_TLDS:
            if domain.endswith(tld):
                details.append(f"High-risk TLD detected: {tld}")
                rep = "Suspicious"
                break

        # Keyword analysis
        suspicious_words = [
            "secure", "login", "verify", "account", "update",
            "confirm", "reset", "alert", "urgent", "claim",
        ]
        found = [w for w in suspicious_words if w in domain]
        if found:
            details.append(f"Suspicious keywords in domain: {', '.join(found)}")
            if rep == "Unknown":
                rep = "Suspicious"

        if rep == "Unknown":
            rep = "Unknown"

    return {
        "domain": domain,
        "reputation": rep,
        "source": "Prototype Local List",
        "confidence": confidence,
        "details": details,
        "is_prototype": True,
    }


def _check_ip_local(ip: str) -> Dict:
    """Check IP against local prototype reputation lists."""
    rep = "Unknown"
    details = []
    confidence = "Low"

    if ip in KNOWN_BAD_IPS:
        rep = "Malicious"
        details.append("Listed in prototype malicious IP list")
        confidence = "Prototype"
    elif ip in KNOWN_SUSPICIOUS_IPS:
        rep = "Suspicious"
        details.append("Listed in prototype suspicious IP list")
        confidence = "Prototype"

    return {
        "ip": ip,
        "reputation": rep,
        "source": "Prototype Local List",
        "confidence": confidence,
        "details": details,
        "is_prototype": True,
    }


def check_domain_reputation(domain: str) -> Dict:
    """
    Check reputation of a domain.
    Uses external API if REPUTATION_API_KEY is set, otherwise uses local prototype list.
    """
    if not domain:
        return {"domain": domain, "reputation": "Unknown", "error": "Empty domain"}

    api_key = os.environ.get("REPUTATION_API_KEY", "")

    if api_key:
        # Placeholder for external API integration
        # Example: VirusTotal, AbuseIPDB, etc.
        try:
            return _check_domain_via_api(domain, api_key)
        except Exception as e:
            logger.warning(f"External reputation API failed for domain {domain}: {e}")
            result = _check_domain_local(domain)
            result["api_fallback"] = True
            return result

    return _check_domain_local(domain)


def check_ip_reputation(ip: str) -> Dict:
    """
    Check reputation of an IP address.
    Uses external API if REPUTATION_API_KEY is set, otherwise uses local prototype list.
    """
    if not ip:
        return {"ip": ip, "reputation": "Unknown", "error": "Empty IP"}

    api_key = os.environ.get("REPUTATION_API_KEY", "")

    if api_key:
        try:
            return _check_ip_via_api(ip, api_key)
        except Exception as e:
            logger.warning(f"External reputation API failed for IP {ip}: {e}")
            result = _check_ip_local(ip)
            result["api_fallback"] = True
            return result

    return _check_ip_local(ip)


def _check_domain_via_api(domain: str, api_key: str) -> Dict:
    """
    Placeholder for external domain reputation API.
    Implement with VirusTotal, OTX, etc. when API key is available.
    """
    raise NotImplementedError("External API integration not yet configured")


def _check_ip_via_api(ip: str, api_key: str) -> Dict:
    """
    Placeholder for external IP reputation API.
    Implement with AbuseIPDB, VirusTotal, etc. when API key is available.
    """
    raise NotImplementedError("External API integration not yet configured")


def check_multiple_domains(domains: List[str]) -> Dict[str, Dict]:
    """Check reputation for multiple domains. Deduplicates."""
    results = {}
    seen = set()
    for domain in domains:
        d = domain.lower().strip() if domain else ""
        if not d or d in seen:
            continue
        seen.add(d)
        results[d] = check_domain_reputation(d)
    return results


def check_multiple_ips(ips: List[str]) -> Dict[str, Dict]:
    """Check reputation for multiple IPs. Deduplicates."""
    results = {}
    seen = set()
    for ip in ips:
        ip = ip.strip() if ip else ""
        if not ip or ip in seen:
            continue
        seen.add(ip)
        results[ip] = check_ip_reputation(ip)
    return results


def is_possible_proxy_infrastructure(org: str = "", asn_desc: str = "") -> bool:
    """Heuristic check if IP belongs to known hosting/proxy/VPN infrastructure."""
    combined = f"{org} {asn_desc}".lower()
    return any(kw in combined for kw in PROXY_KEYWORDS)
