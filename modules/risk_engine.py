"""
Risk Correlation Engine
Combines signals from ML, URL analysis, DNS, reputation, headers,
and geolocation to produce a final risk assessment.
"""

import logging
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

# ── Risk level thresholds ─────────────────────────────────────────────────────

RISK_LEVELS = {
    "CRITICAL": (80, "🔴"),
    "HIGH":     (55, "🟠"),
    "MEDIUM":   (30, "🟡"),
    "LOW":      (0,  "🟢"),
}

# ── Signal weights ─────────────────────────────────────────────────────────────

WEIGHTS = {
    # ML signal
    "ml_phishing_high":       25,   # ML prob >= 0.80
    "ml_phishing_medium":     15,   # ML prob >= 0.55
    "ml_suspicious":           8,   # ML prob >= 0.40

    # Reputation signals
    "domain_malicious":       20,
    "domain_suspicious":      10,
    "ip_malicious":           15,
    "ip_suspicious":           8,

    # URL signals
    "url_suspicious_high":    12,   # risk_score >= 4
    "url_suspicious_medium":   6,   # risk_score >= 2
    "url_uses_http":           3,
    "url_ip_hostname":         8,
    "url_brand_impersonation": 10,

    # Header authentication
    "spf_fail":                8,
    "spf_softfail":            4,
    "dkim_fail":               8,
    "dmarc_fail":              8,
    "header_mismatch":         6,
    "no_auth":                 5,

    # DNS signals
    "domain_nxdomain":         5,
    "dns_failure":             3,

    # Infrastructure signals
    "proxy_hosting":           3,
    "high_risk_tld":           4,

    # Indicator count
    "many_indicators":         5,   # > 5 indicators
}


def _score_ml(nlp_result: Dict) -> Tuple[int, List[str]]:
    """Score ML classification signal."""
    score = 0
    factors = []
    prob = nlp_result.get("threat_probability", 0.0)
    classification = nlp_result.get("classification", "Unknown")

    if prob >= 0.80:
        score += WEIGHTS["ml_phishing_high"]
        factors.append(f"High ML phishing probability ({prob:.0%})")
    elif prob >= 0.55:
        score += WEIGHTS["ml_phishing_medium"]
        factors.append(f"Moderate ML phishing probability ({prob:.0%})")
    elif prob >= 0.40:
        score += WEIGHTS["ml_suspicious"]
        factors.append(f"Suspicious ML classification ({prob:.0%})")

    return score, factors


def _score_urls(url_list: List[Dict]) -> Tuple[int, List[str]]:
    """Score URL analysis signals."""
    score = 0
    factors = []

    for url_info in url_list:
        rs = url_info.get("risk_score", 0)
        indicators = url_info.get("suspicious_indicators", [])
        url = url_info.get("url", "")[:60]

        if rs >= 4:
            score += WEIGHTS["url_suspicious_high"]
            factors.append(f"Highly suspicious URL: {url}...")
        elif rs >= 2:
            score += WEIGHTS["url_suspicious_medium"]
            factors.append(f"Suspicious URL pattern: {url}...")

        if url_info.get("is_ip_hostname"):
            score += WEIGHTS["url_ip_hostname"]
            factors.append(f"IP address used as URL hostname")

        if not url_info.get("is_https"):
            score += WEIGHTS["url_uses_http"]

        # Check for brand impersonation in indicators
        for ind in indicators:
            if "brand impersonation" in ind.lower():
                score += WEIGHTS["url_brand_impersonation"]
                factors.append(f"Brand impersonation detected in URL")
                break

    # Deduplicate factors
    return score, list(dict.fromkeys(factors))


def _score_reputation(domain_reputations: Dict, ip_reputations: Dict) -> Tuple[int, List[str]]:
    """Score reputation signals."""
    score = 0
    factors = []

    for domain, rep_info in domain_reputations.items():
        rep = rep_info.get("reputation", "Unknown")
        if rep == "Malicious":
            score += WEIGHTS["domain_malicious"]
            factors.append(f"Malicious domain reputation: {domain}")
        elif rep == "Suspicious":
            score += WEIGHTS["domain_suspicious"]
            factors.append(f"Suspicious domain reputation: {domain}")

    for ip, rep_info in ip_reputations.items():
        rep = rep_info.get("reputation", "Unknown")
        if rep == "Malicious":
            score += WEIGHTS["ip_malicious"]
            factors.append(f"Malicious IP reputation: {ip}")
        elif rep == "Suspicious":
            score += WEIGHTS["ip_suspicious"]
            factors.append(f"Suspicious IP reputation: {ip}")

    return score, factors


def _score_headers(header_analysis: Dict) -> Tuple[int, List[str]]:
    """Score header authentication signals."""
    score = 0
    factors = []

    spf = header_analysis.get("spf", "none")
    dkim = header_analysis.get("dkim", "none")
    dmarc = header_analysis.get("dmarc", "none")

    if spf == "fail":
        score += WEIGHTS["spf_fail"]
        factors.append("SPF authentication failure")
    elif spf == "softfail":
        score += WEIGHTS["spf_softfail"]
        factors.append("SPF soft failure")

    if dkim == "fail":
        score += WEIGHTS["dkim_fail"]
        factors.append("DKIM authentication failure")

    if dmarc == "fail":
        score += WEIGHTS["dmarc_fail"]
        factors.append("DMARC policy failure")

    if header_analysis.get("from_reply_to_mismatch"):
        score += WEIGHTS["header_mismatch"]
        factors.append(header_analysis.get("from_reply_to_mismatch_detail", "From/Reply-To mismatch"))

    if header_analysis.get("from_return_path_mismatch"):
        score += WEIGHTS["header_mismatch"]
        factors.append(header_analysis.get("from_return_path_mismatch_detail", "From/Return-Path mismatch"))

    if spf == "none" and dkim == "none":
        score += WEIGHTS["no_auth"]
        factors.append("No email authentication configured")

    return score, factors


def _score_dns(dns_results: Dict) -> Tuple[int, List[str]]:
    """Score DNS analysis signals."""
    score = 0
    factors = []

    for domain, dns_info in dns_results.items():
        status = dns_info.get("status", "")
        if "NXDOMAIN" in status:
            score += WEIGHTS["domain_nxdomain"]
            factors.append(f"Domain does not exist (NXDOMAIN): {domain}")
        elif "fail" in status.lower() or "unable" in status.lower():
            score += WEIGHTS["dns_failure"]

    return score, factors


def _score_geo(geo_results: Dict) -> Tuple[int, List[str]]:
    """Score geolocation/infrastructure signals."""
    score = 0
    factors = []

    for ip, geo in geo_results.items():
        if geo.get("is_proxy_or_hosting"):
            score += WEIGHTS["proxy_hosting"]
            factors.append(f"Possible hosting/proxy infrastructure: {ip}")

    return score, factors


def _score_domains(domains: List[str]) -> Tuple[int, List[str]]:
    """Score domain characteristics."""
    score = 0
    factors = []

    HIGH_RISK_TLDS = {".xyz", ".ru", ".tk", ".ml", ".ga", ".cf", ".pw", ".top"}
    for domain in domains:
        for tld in HIGH_RISK_TLDS:
            if domain.lower().endswith(tld):
                score += WEIGHTS["high_risk_tld"]
                factors.append(f"High-risk TLD domain: {domain}")
                break  # one flag per domain

    return score, factors


def _score_indicator_count(indicators: Dict) -> Tuple[int, List[str]]:
    """Penalize high indicator count."""
    score = 0
    factors = []
    total = indicators.get("summary", {}).get("total", 0)
    if total > 5:
        score += WEIGHTS["many_indicators"]
        factors.append(f"High number of suspicious indicators extracted ({total})")
    return score, factors


def determine_risk_level(total_score: int) -> Tuple[str, str]:
    """Convert numeric score to risk level and icon."""
    for level, (threshold, icon) in RISK_LEVELS.items():
        if total_score >= threshold:
            return level, icon
    return "LOW", "🟢"


def correlate_risk(
    nlp_result: Dict,
    indicators: Dict,
    dns_results: Dict,
    domain_reputations: Dict,
    ip_reputations: Dict,
    header_analysis: Dict,
    geo_results: Dict,
) -> Dict:
    """
    Master risk correlation function.

    Combines all signals into a final risk assessment.

    Returns
    -------
    dict with:
        risk_level: str (CRITICAL / HIGH / MEDIUM / LOW)
        risk_icon: str
        total_score: int
        max_score: int
        score_percentage: float
        risk_factors: list[str]
        risk_breakdown: dict of category -> score
        summary: str
    """

    all_factors = []
    breakdown = {}

    # ML signal
    s, f = _score_ml(nlp_result)
    breakdown["ML Classification"] = s
    all_factors.extend(f)

    # URL signals
    urls = indicators.get("urls", [])
    s, f = _score_urls(urls)
    breakdown["URL Analysis"] = s
    all_factors.extend(f)

    # Reputation
    s, f = _score_reputation(domain_reputations, ip_reputations)
    breakdown["Reputation"] = s
    all_factors.extend(f)

    # Headers
    s, f = _score_headers(header_analysis)
    breakdown["Header Authentication"] = s
    all_factors.extend(f)

    # DNS
    s, f = _score_dns(dns_results)
    breakdown["DNS Analysis"] = s
    all_factors.extend(f)

    # Geolocation
    s, f = _score_geo(geo_results)
    breakdown["Infrastructure"] = s
    all_factors.extend(f)

    # Domain TLD
    domains = indicators.get("domains", [])
    s, f = _score_domains(domains)
    breakdown["Domain Characteristics"] = s
    all_factors.extend(f)

    # Indicator count
    s, f = _score_indicator_count(indicators)
    breakdown["Indicator Count"] = s
    all_factors.extend(f)

    total_score = sum(breakdown.values())
    total_score = min(total_score, 100)  # cap at 100

    risk_level, risk_icon = determine_risk_level(total_score)

    # Generate summary
    classification = nlp_result.get("classification", "Unknown")
    prob = nlp_result.get("threat_probability", 0.0)

    summary_parts = [f"ML Classification: {classification} ({prob:.0%})"]
    if all_factors:
        summary_parts.append(f"{len(all_factors)} risk factor(s) identified")

    return {
        "risk_level": risk_level,
        "risk_icon": risk_icon,
        "total_score": total_score,
        "max_score": 100,
        "score_percentage": total_score,
        "risk_factors": all_factors,
        "risk_breakdown": breakdown,
        "summary": " | ".join(summary_parts),
        "classification": classification,
        "threat_probability": prob,
    }
