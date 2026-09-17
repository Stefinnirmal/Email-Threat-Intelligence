"""
Header Analyzer Module
Analyzes email headers for SPF, DKIM, DMARC authentication results
and extracts IPs from Received headers.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Regex for IP extraction from Received headers
RECEIVED_IP_PATTERN = re.compile(
    r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]|"
    r"from\s+\S+\s+\(.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE,
)

GENERIC_IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b"
)

# Private IP ranges
PRIVATE_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^0\."),
    re.compile(r"^169\.254\."),
]


def is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_RANGES)


def parse_spf_result(auth_results: str) -> str:
    """Extract SPF result from Authentication-Results header."""
    if not auth_results:
        return "none"
    auth_lower = auth_results.lower()

    # Look for explicit spf= result
    spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", auth_lower)
    if spf_match:
        return spf_match.group(1)

    # Check Received-SPF header style
    if "spf" in auth_lower:
        for result in ["pass", "fail", "softfail", "neutral", "none"]:
            if result in auth_lower:
                return result

    return "none"


def parse_dkim_result(auth_results: str) -> str:
    """Extract DKIM result from Authentication-Results header."""
    if not auth_results:
        return "none"
    auth_lower = auth_results.lower()

    dkim_match = re.search(r"dkim=(pass|fail|neutral|none|temperror|permerror)", auth_lower)
    if dkim_match:
        return dkim_match.group(1)

    return "none"


def parse_dmarc_result(auth_results: str) -> str:
    """Extract DMARC result from Authentication-Results header."""
    if not auth_results:
        return "none"
    auth_lower = auth_results.lower()

    dmarc_match = re.search(r"dmarc=(pass|fail|none|bestguesspass|temperror|permerror)", auth_lower)
    if dmarc_match:
        return dmarc_match.group(1)

    return "none"


def extract_ips_from_received(received_headers: List[str]) -> List[str]:
    """Extract public IP addresses from Received headers."""
    ips = []
    seen = set()

    for header in received_headers:
        # Find IPs in brackets [x.x.x.x]
        bracket_ips = re.findall(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", header)
        # Find IPs in general text
        general_ips = GENERIC_IP_PATTERN.findall(header)

        all_ips = bracket_ips + general_ips
        for ip in all_ips:
            if ip not in seen and not is_private_ip(ip):
                seen.add(ip)
                ips.append(ip)

    return ips


def analyze_from_reply_to_mismatch(email_from: str, reply_to: str) -> Tuple[bool, str]:
    """Check if From and Reply-To domains differ (common in phishing)."""
    if not email_from or not reply_to:
        return False, ""
    if reply_to == "Not available":
        return False, ""

    from_domain = re.search(r"@([\w.\-]+)", email_from)
    reply_domain = re.search(r"@([\w.\-]+)", reply_to)

    if from_domain and reply_domain:
        fd = from_domain.group(1).lower()
        rd = reply_domain.group(1).lower()
        if fd != rd:
            return True, f"From domain ({fd}) differs from Reply-To domain ({rd})"

    return False, ""


def analyze_return_path_mismatch(email_from: str, return_path: str) -> Tuple[bool, str]:
    """Check if From and Return-Path domains differ."""
    if not email_from or not return_path:
        return False, ""
    if return_path == "Not available":
        return False, ""

    from_domain = re.search(r"@([\w.\-]+)", email_from)
    rp_domain = re.search(r"@([\w.\-]+)", return_path)

    if from_domain and rp_domain:
        fd = from_domain.group(1).lower()
        rd = rp_domain.group(1).lower()
        if fd != rd:
            return True, f"From domain ({fd}) differs from Return-Path domain ({rd})"

    return False, ""


_rdns_cache: Dict[str, str] = {}


def resolve_reverse_dns(ip: str, demo_mode: bool = False) -> str:
    """
    Resolve an IP address to its Reverse DNS (PTR) hostname.
    Caches results to prevent duplicate network calls.
    """
    if not ip or is_private_ip(ip):
        return "Internal / Private IP"
    if ip in _rdns_cache:
        return _rdns_cache[ip]
    if demo_mode:
        cleaned = ip.replace(".", "-")
        res = f"mail-{cleaned}.in-addr.arpa.net"
        _rdns_cache[ip] = res
        return res
    try:
        import socket
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(1.8)
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            _rdns_cache[ip] = hostname
            return hostname
        finally:
            socket.setdefaulttimeout(orig_timeout)
    except Exception:
        _rdns_cache[ip] = "No PTR record"
        return "No PTR record"


def extract_originating_client_ip(raw_headers: dict, auth_results_raw: str = "") -> Optional[str]:
    """
    Extract explicit client origin IP addresses from common client headers.
    Checks: X-Originating-IP, X-Sender-IP, X-Remote-IP, X-Client-IP, and client-ip in SPF/Auth.
    """
    client_header_keys = [
        "x-originating-ip",
        "x-sender-ip",
        "x-remote-ip",
        "x-client-ip",
    ]
    for key, val in raw_headers.items():
        if key.lower() in client_header_keys:
            m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", str(val))
            if m:
                candidate = m.group(1)
                if not is_private_ip(candidate):
                    return candidate

    if auth_results_raw:
        client_ip_match = re.search(r"client-ip=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", auth_results_raw, re.IGNORECASE)
        if client_ip_match:
            candidate = client_ip_match.group(1)
            if not is_private_ip(candidate):
                return candidate

    return None


def parse_received_hops(received_headers: List[str], demo_mode: bool = False) -> List[dict]:
    """
    Parse Received headers into structured chronological hops.
    The oldest hop (Hop 1) represents the initial server that accepted the email from the sender.
    """
    hops = []
    # Received headers in email are newest-to-oldest.
    # Reversing gives chronological delivery: Hop 1 = origin, Hop N = recipient.
    chronological = list(reversed(received_headers))

    for idx, header in enumerate(chronological, 1):
        clean_header = " ".join(header.split())

        from_m = re.search(r"from\s+([^\s\(]+(?:\s*\([^\)]*\))?)", clean_header, re.IGNORECASE)
        from_host = from_m.group(1).strip() if from_m else "Unknown sender server"

        by_m = re.search(r"by\s+([^\s;]+)", clean_header, re.IGNORECASE)
        by_host = by_m.group(1).strip() if by_m else "Unknown receiving server"

        proto_m = re.search(r"with\s+([A-Za-z0-9\-]+)", clean_header, re.IGNORECASE)
        protocol = proto_m.group(1).upper() if proto_m else "SMTP"

        id_m = re.search(r"id\s+([^\s;]+)", clean_header, re.IGNORECASE)
        hop_id = id_m.group(1) if id_m else "N/A"

        date_m = re.search(
            r"(?:;\s*|\n\s*)([A-Za-z]{3},\s*\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+[0-9:]+(?:\s+[-+0-9]+(?:\s*\([A-Za-z]+\))?)?)",
            clean_header
        )
        timestamp = date_m.group(1).strip() if date_m else "N/A"

        bracket_ips = re.findall(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", clean_header)
        general_ips = GENERIC_IP_PATTERN.findall(clean_header)
        all_raw_ips = list(dict.fromkeys(bracket_ips + general_ips))

        public_ips = [ip for ip in all_raw_ips if not is_private_ip(ip)]
        primary_public_ip = public_ips[0] if public_ips else None
        rdns = resolve_reverse_dns(primary_public_ip, demo_mode=demo_mode) if primary_public_ip else "N/A"

        hops.append({
            "hop_number": idx,
            "from_host": from_host,
            "by_host": by_host,
            "protocol": protocol,
            "hop_id": hop_id,
            "timestamp": timestamp,
            "public_ip": primary_public_ip,
            "all_ips": all_raw_ips,
            "reverse_dns": rdns,
            "is_private_only": len(public_ips) == 0 and len(all_raw_ips) > 0,
            "raw": header.strip(),
        })

    return hops


def analyze_headers(parsed_email: dict, demo_mode: bool = False) -> dict:
    """
    Comprehensive header analysis.

    Parameters
    ----------
    parsed_email : dict
        Output from email_parser.parse_email()
    demo_mode : bool
        Whether to use simulated data for lookups

    Returns
    -------
    dict with authentication, origin server, and hop routing results
    """
    result = {
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
        "spf_details": "",
        "dkim_details": "",
        "dmarc_details": "",
        "received_ips": [],
        "hop_count": 0,
        "from_reply_to_mismatch": False,
        "from_reply_to_mismatch_detail": "",
        "from_return_path_mismatch": False,
        "from_return_path_mismatch_detail": "",
        "suspicious_header_flags": [],
        "auth_results_raw": "",
        "origin_client_ip": None,
        "origin_server_ip": None,
        "origin_server_hostname": "Not resolved",
        "hops": [],
    }

    auth_results = parsed_email.get("authentication_results", "")
    if not auth_results or auth_results == "Not available":
        auth_results = ""

    # Parse from raw headers too
    raw_headers = parsed_email.get("raw_headers", {})
    if not auth_results:
        for key, val in raw_headers.items():
            if "authentication" in key.lower():
                auth_results = val
                break

    # Also check Received-SPF header
    received_spf = ""
    for key, val in raw_headers.items():
        if key.lower() == "received-spf":
            received_spf = val
            break

    combined_auth = f"{auth_results} {received_spf}"
    result["auth_results_raw"] = combined_auth.strip()

    result["spf"] = parse_spf_result(combined_auth)
    result["dkim"] = parse_dkim_result(combined_auth)
    result["dmarc"] = parse_dmarc_result(combined_auth)

    # Extract IPs from Received headers
    received_headers = parsed_email.get("received_headers", [])
    result["received_ips"] = extract_ips_from_received(received_headers)
    result["hop_count"] = len(received_headers)

    # Extract client origin IP
    result["origin_client_ip"] = extract_originating_client_ip(raw_headers, combined_auth)

    # Parse structured chronological hops
    hops = parse_received_hops(received_headers, demo_mode=demo_mode)
    result["hops"] = hops

    # Determine primary originating server IP candidate
    origin_server_ip = None
    for h in hops:
        if h.get("public_ip"):
            origin_server_ip = h["public_ip"]
            break
    if not origin_server_ip and result["received_ips"]:
        origin_server_ip = result["received_ips"][-1]
    if not origin_server_ip and result["origin_client_ip"]:
        origin_server_ip = result["origin_client_ip"]

    result["origin_server_ip"] = origin_server_ip
    result["origin_server_hostname"] = resolve_reverse_dns(origin_server_ip, demo_mode=demo_mode) if origin_server_ip else "No server IP found"

    # Header mismatches
    email_from = parsed_email.get("from", "")
    reply_to = parsed_email.get("reply_to", "")
    return_path = parsed_email.get("return_path", "")

    mismatch_rt, mismatch_rt_detail = analyze_from_reply_to_mismatch(email_from, reply_to)
    result["from_reply_to_mismatch"] = mismatch_rt
    result["from_reply_to_mismatch_detail"] = mismatch_rt_detail

    mismatch_rp, mismatch_rp_detail = analyze_return_path_mismatch(email_from, return_path)
    result["from_return_path_mismatch"] = mismatch_rp
    result["from_return_path_mismatch_detail"] = mismatch_rp_detail

    # Collect suspicious header flags
    flags = []
    if result["spf"] in ("fail", "softfail"):
        flags.append(f"SPF {result['spf'].upper()}")
    if result["dkim"] == "fail":
        flags.append("DKIM FAIL")
    if result["dmarc"] == "fail":
        flags.append("DMARC FAIL")
    if mismatch_rt:
        flags.append("From/Reply-To domain mismatch")
    if mismatch_rp:
        flags.append("From/Return-Path domain mismatch")
    if result["spf"] == "none" and result["dkim"] == "none":
        flags.append("No email authentication present")

    result["suspicious_header_flags"] = flags

    return result


def get_auth_status_color(status: str) -> str:
    """Return a display color/indicator for auth status."""
    status = status.lower()
    if status == "pass":
        return "✅"
    elif status in ("fail", "softfail"):
        return "❌"
    elif status == "neutral":
        return "⚪"
    else:
        return "⚠️"
