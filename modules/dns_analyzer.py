"""
DNS Analyzer Module
Performs DNS lookups for domains extracted from emails.
Gracefully handles all failures.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logger.warning("dnspython not installed. DNS analysis will be limited.")


def _safe_resolve(domain: str, record_type: str, timeout: float = 1.8) -> List[str]:
    """Resolve a DNS record type for a domain with public nameserver fallback."""
    if not DNS_AVAILABLE:
        if record_type == "A":
            try:
                import socket
                _, _, ip_list = socket.gethostbyname_ex(domain)
                return ip_list
            except Exception:
                return []
        return []

    # First attempt: standard system resolver
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, record_type)
        return [str(r).rstrip(".") for r in answers]
    except (dns.resolver.Timeout, dns.exception.Timeout):
        # Fallback to public resolvers (8.8.8.8, 1.1.1.1) in case local router drops port 53
        try:
            public_resolver = dns.resolver.Resolver(configure=False)
            public_resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            public_resolver.timeout = timeout
            public_resolver.lifetime = timeout
            answers = public_resolver.resolve(domain, record_type)
            return [str(r).rstrip(".") for r in answers]
        except Exception:
            pass
    except dns.resolver.NXDOMAIN:
        return ["NXDOMAIN"]
    except dns.resolver.NoAnswer:
        return []
    except Exception:
        pass

    # Socket fallback for A records
    if record_type == "A":
        try:
            import socket
            _, _, ip_list = socket.gethostbyname_ex(domain)
            if ip_list:
                return ip_list
        except Exception:
            pass

    return []


def analyze_domain(domain: str) -> Dict:
    """
    Perform DNS analysis for a single domain.

    Returns
    -------
    dict with:
        domain: str
        dns_available: bool
        status: str
        a_records: list
        aaaa_records: list
        mx_records: list
        ns_records: list
        txt_records: list
        resolved_ips: list
        error: str | None
    """
    result = {
        "domain": domain,
        "dns_available": DNS_AVAILABLE,
        "status": "Unknown",
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "resolved_ips": [],
        "error": None,
    }

    if not domain or not domain.strip():
        result["status"] = "Invalid domain"
        result["error"] = "Empty domain provided"
        return result

    domain = domain.strip().lower()

    if not DNS_AVAILABLE:
        result["status"] = "DNS library unavailable"
        result["error"] = "dnspython not installed"
        return result

    try:
        a_records = _safe_resolve(domain, "A")
        result["a_records"] = a_records

        # Determine status from A records
        if not a_records:
            result["status"] = "Unable to resolve"
        elif "NXDOMAIN" in a_records:
            result["status"] = "NXDOMAIN (domain does not exist)"
        elif any("error" in r.lower() or "timeout" in r.lower() for r in a_records):
            result["status"] = "DNS lookup failed"
        else:
            result["status"] = "Resolved"
            result["resolved_ips"] = a_records

        # Additional record types
        result["aaaa_records"] = _safe_resolve(domain, "AAAA")
        result["mx_records"] = _safe_resolve(domain, "MX")
        result["ns_records"] = _safe_resolve(domain, "NS")

        # TXT records can be large; limit them
        txt = _safe_resolve(domain, "TXT")
        result["txt_records"] = txt[:5] if txt else []

    except Exception as e:
        result["status"] = "Analysis error"
        result["error"] = str(e)
        logger.error(f"DNS analysis error for {domain}: {e}")

    return result


def analyze_multiple_domains(domains: List[str]) -> Dict[str, Dict]:
    """
    Analyze multiple domains. Returns dict keyed by domain.
    Deduplicates automatically.
    """
    results = {}
    seen = set()
    for domain in domains:
        domain = domain.strip().lower() if domain else ""
        if not domain or domain in seen:
            continue
        seen.add(domain)
        results[domain] = analyze_domain(domain)
    return results


def get_spf_record(domain: str) -> Optional[str]:
    """Extract SPF record from TXT records for a domain."""
    if not DNS_AVAILABLE:
        return None
    txt_records = _safe_resolve(domain, "TXT")
    for record in txt_records:
        if "v=spf1" in record.lower():
            return record
    return None


def get_dmarc_record(domain: str) -> Optional[str]:
    """Get DMARC record for a domain (from _dmarc subdomain)."""
    if not DNS_AVAILABLE:
        return None
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = _safe_resolve(dmarc_domain, "TXT")
    for record in txt_records:
        if "v=dmarc1" in record.lower():
            return record
    return None
