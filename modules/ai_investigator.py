"""OpenAI-powered email threat investigation.

The AI receives structured evidence extracted by the local analysis pipeline.
It does not discover a sender's physical location and must not infer one.
"""
import os
from typing import Any, Dict


def is_configured() -> bool:
    return bool(os.getenv("OPENAI_API_KEY"))


def _compact_evidence(result: Dict[str, Any]) -> Dict[str, Any]:
    parsed = result.get("parsed", {})
    headers = result.get("header_analysis", {})
    indicators = result.get("indicators", {})
    geo = result.get("geo", {})
    return {
        "email": {
            "from": parsed.get("from"),
            "to": parsed.get("to"),
            "subject": parsed.get("subject"),
            "date": parsed.get("date"),
            "reply_to": parsed.get("reply_to"),
            "return_path": parsed.get("return_path"),
        },
        "authentication": {
            "spf": headers.get("spf"),
            "dkim": headers.get("dkim"),
            "dmarc": headers.get("dmarc"),
            "received_ips": headers.get("received_ips", []),
            "hop_count": headers.get("hop_count", 0),
            "flags": headers.get("suspicious_header_flags", []),
        },
        "ip_evidence": {
            "all_ips": indicators.get("ips", []),
            "header_ips": indicators.get("ip_from_headers", []),
            "geolocation": geo,
        },
        "indicators": {
            "urls": indicators.get("urls", [])[:20],
            "domains": indicators.get("domains", [])[:20],
            "email_addresses": indicators.get("email_addresses", [])[:20],
        },
        "ml": result.get("nlp", {}),
        "risk": result.get("risk", {}),
        "dns": result.get("dns", {}),
        "reputation": {
            "domains": result.get("domain_reputations", {}),
            "ips": result.get("ip_reputations", {}),
        },
    }


def investigate(result: Dict[str, Any]) -> Dict[str, Any]:
    """Return an AI investigation or a clear configuration/error result."""
    if not is_configured():
        return {
            "ok": False,
            "error": "OPENAI_API_KEY is not configured. Add it to your environment or .env file.",
            "text": "",
        }

    try:
        from openai import OpenAI
    except ImportError:
        return {
            "ok": False,
            "error": "The OpenAI package is not installed. Run: pip install -r requirements.txt",
            "text": "",
        }

    model = os.getenv("OPENAI_MODEL", "gpt-5.6-luna")
    evidence = _compact_evidence(result)
    body = (result.get("parsed", {}).get("body") or "")[:12000]
    evidence["email_body_excerpt"] = body

    instructions = """You are an email threat-intelligence analyst assisting a defensive investigation.
Analyze only the supplied evidence. Be factual and clearly separate observed evidence from inference.

Critical location rule: an email can expose relay/sending infrastructure IPs, but an IP geolocation result is
only an approximate network/infrastructure location. Never claim that it is the sender's exact physical location.
Explain that VPNs, proxies, Tor, cloud hosting, NAT, compromised systems, and forged/spoofed headers can make
IP-based attribution inaccurate. Treat the oldest public Received-header IP as an origin-IP CANDIDATE only,
not proof of the sender's device or physical location.

Return a concise report with these headings:
1. Executive finding
2. Sender and routing evidence
3. IP and approximate infrastructure location
4. Authentication (SPF/DKIM/DMARC)
5. Suspicious indicators
6. What the evidence proves / does not prove
7. Recommended defensive next steps
Do not invent missing facts. If there is no public IP, say so."""

    prompt = "STRUCTURED EVIDENCE:\n" + __import__("json").dumps(evidence, indent=2, default=str)

    try:
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        response = client.responses.create(
            model=model,
            instructions=instructions,
            input=prompt,
        )
        return {"ok": True, "error": None, "model": model, "text": response.output_text}
    except Exception as exc:
        return {"ok": False, "error": f"OpenAI request failed: {exc}", "text": "", "model": model}
