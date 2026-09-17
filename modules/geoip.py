"""
GeoIP Module
Approximate IP geolocation using ip-api.com (free, no key required for basic use)
or a fallback demo mode.

IMPORTANT DISCLAIMER:
GeoIP identifies the approximate location associated with an IP address.
It does NOT identify the attacker's exact physical location.
VPNs, proxies, Tor, cloud servers, and compromised systems may affect accuracy.
"""

import os
import logging
import time
import ipaddress
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests library not available. GeoIP will use demo mode.")

# Rate limiting: ip-api.com allows 45 requests/minute on free tier
_last_request_time = 0.0
_MIN_REQUEST_INTERVAL = 1.4  # seconds between requests

# Cache to avoid duplicate lookups
_geoip_cache: Dict[str, Dict] = {}

GEOIP_DISCLAIMER = (
    "GeoIP identifies the approximate location associated with an IP address. "
    "It does not identify the attacker's exact physical location. "
    "VPNs, proxies, Tor, cloud servers, and compromised systems may affect accuracy."
)


def _rate_limit():
    """Simple rate limiter for free API tier."""
    global _last_request_time
    now = time.time()
    elapsed = now - _last_request_time
    if elapsed < _MIN_REQUEST_INTERVAL:
        time.sleep(_MIN_REQUEST_INTERVAL - elapsed)
    _last_request_time = time.time()


def _lookup_via_ipapi(ip: str) -> Dict:
    """Query ip-api.com for geolocation data (free, no key required)."""
    _rate_limit()
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query,proxy,hosting"

    response = requests.get(url, timeout=8)
    response.raise_for_status()
    data = response.json()

    if data.get("status") != "success":
        raise ValueError(f"ip-api.com returned: {data.get('message', 'unknown error')}")

    asn_raw = data.get("as", "")
    asn_number = ""
    asn_desc = asn_raw
    if asn_raw and " " in asn_raw:
        parts = asn_raw.split(" ", 1)
        asn_number = parts[0]
        asn_desc = parts[1]

    is_proxy = data.get("proxy", False) or data.get("hosting", False)

    return {
        "ip": ip,
        "country": data.get("country", "Unknown"),
        "region": data.get("regionName", "Unknown"),
        "city": data.get("city", "Unknown"),
        "zip": data.get("zip", ""),
        "latitude": data.get("lat"),
        "longitude": data.get("lon"),
        "isp": data.get("isp", "Unknown"),
        "organization": data.get("org", "Unknown"),
        "asn": asn_number,
        "asn_description": asn_desc,
        "is_proxy_or_hosting": is_proxy,
        "source": "ip-api.com (approximate)",
        "disclaimer": GEOIP_DISCLAIMER,
        "error": None,
    }


def _demo_geoip(ip: str) -> Dict:
    """Return clearly labeled demo/prototype geolocation data."""
    # Deterministic demo data based on first octet
    demo_locations = {
        "1": ("United States", "California", "Los Angeles", 34.05, -118.24),
        "5": ("Germany", "Bavaria", "Munich", 48.14, 11.58),
        "45": ("Netherlands", "Noord-Holland", "Amsterdam", 52.37, 4.90),
        "91": ("France", "Île-de-France", "Paris", 48.86, 2.35),
        "103": ("Singapore", "Central Region", "Singapore", 1.35, 103.82),
        "185": ("Russia", "Moscow Oblast", "Moscow", 55.75, 37.62),
        "192": ("United Kingdom", "England", "London", 51.51, -0.13),
        "198": ("Canada", "Ontario", "Toronto", 43.65, -79.38),
        "203": ("Australia", "New South Wales", "Sydney", -33.87, 151.21),
    }

    first_octet = ip.split(".")[0] if ip and "." in ip else "1"
    country, region, city, lat, lon = demo_locations.get(
        first_octet, ("United States", "Virginia", "Ashburn", 39.04, -77.49)
    )

    return {
        "ip": ip,
        "country": country,
        "region": region,
        "city": city,
        "zip": "",
        "latitude": lat,
        "longitude": lon,
        "isp": "Demo ISP (Prototype)",
        "organization": "Demo Organization (Prototype)",
        "asn": "AS00000",
        "asn_description": "PROTOTYPE-ASN (Demo data only)",
        "is_proxy_or_hosting": False,
        "source": "⚠ PROTOTYPE DEMO DATA — Not real geolocation",
        "disclaimer": GEOIP_DISCLAIMER,
        "is_demo": True,
        "error": None,
    }


def geolocate_ip(ip: str, demo_mode: bool = False) -> Dict:
    """
    Geolocate a single IP address.

    Parameters
    ----------
    ip : str
        Public IPv4 address
    demo_mode : bool
        If True, skip real API and use demo data

    Returns
    -------
    dict with location data and disclaimer
    """
    if not ip or not ip.strip():
        return {"ip": ip, "error": "Empty IP", "disclaimer": GEOIP_DISCLAIMER}

    ip = ip.strip()
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "error": "Invalid IP address", "is_demo": False, "disclaimer": GEOIP_DISCLAIMER}
    if not ip_obj.is_global:
        return {"ip": ip, "error": "Private/reserved IP; public GeoIP is not applicable", "is_demo": False, "disclaimer": GEOIP_DISCLAIMER}

    # Check cache first
    cache_key = f"{'demo' if demo_mode else 'real'}_{ip}"
    if cache_key in _geoip_cache:
        return _geoip_cache[cache_key]

    if demo_mode:
        result = _demo_geoip(ip)
        _geoip_cache[cache_key] = result
        return result

    # Try real API
    if REQUESTS_AVAILABLE:
        # Check for custom GeoIP API key
        api_key = os.environ.get("GEOIP_API_KEY", "")

        try:
            result = _lookup_via_ipapi(ip)
            _geoip_cache[cache_key] = result
            return result
        except Exception as e:
            logger.warning(f"GeoIP lookup failed for {ip}: {e}")
            result = {
                "ip": ip,
                "error": str(e),
                "is_demo": False,
                "source": "Live GeoIP lookup failed",
                "disclaimer": GEOIP_DISCLAIMER,
            }
            _geoip_cache[cache_key] = result
            return result
    else:
        result = {
            "ip": ip,
            "error": "requests library unavailable; install dependencies",
            "is_demo": False,
            "source": "Live GeoIP unavailable",
            "disclaimer": GEOIP_DISCLAIMER,
        }
        _geoip_cache[cache_key] = result
        return result


def geolocate_multiple(ips: List[str], demo_mode: bool = False) -> Dict[str, Dict]:
    """Geolocate multiple IPs. Deduplicates and caches."""
    results = {}
    seen = set()
    for ip in ips:
        ip = ip.strip() if ip else ""
        if not ip or ip in seen:
            continue
        seen.add(ip)
        results[ip] = geolocate_ip(ip, demo_mode=demo_mode)
    return results


def format_location_string(geo: Dict) -> str:
    """Format geo result into a readable location string."""
    parts = []
    if geo.get("city") and geo["city"] != "Unknown":
        parts.append(geo["city"])
    if geo.get("region") and geo["region"] != "Unknown":
        parts.append(geo["region"])
    if geo.get("country") and geo["country"] != "Unknown":
        parts.append(geo["country"])
    return ", ".join(parts) if parts else "Unknown location"
