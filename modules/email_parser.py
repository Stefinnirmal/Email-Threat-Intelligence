"""
Email Parser Module
Parses raw email text or .eml files and extracts structured fields.
"""

import email
import email.policy
from email import message_from_string, message_from_bytes
from email.header import decode_header
import re
from typing import Optional


def safe_decode_header(header_value: str) -> str:
    """Safely decode encoded email headers."""
    if not header_value:
        return "Not available"
    try:
        decoded_parts = decode_header(header_value)
        result = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                charset = charset or "utf-8"
                try:
                    result.append(part.decode(charset, errors="replace"))
                except Exception:
                    result.append(part.decode("utf-8", errors="replace"))
            else:
                result.append(str(part))
        return " ".join(result).strip()
    except Exception:
        return str(header_value)


def extract_body(msg) -> str:
    """Extract plain text body from email message."""
    body = ""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))
                if content_type == "text/plain" and "attachment" not in disposition:
                    try:
                        charset = part.get_content_charset() or "utf-8"
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode(charset, errors="replace")
                    except Exception:
                        body += str(part.get_payload())
                elif content_type == "text/html" and "attachment" not in disposition and not body:
                    try:
                        charset = part.get_content_charset() or "utf-8"
                        payload = part.get_payload(decode=True)
                        if payload:
                            html = payload.decode(charset, errors="replace")
                            # Strip basic HTML tags
                            clean = re.sub(r"<[^>]+>", " ", html)
                            clean = re.sub(r"\s+", " ", clean).strip()
                            body += clean
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    body = payload.decode(charset, errors="replace")
                else:
                    body = str(msg.get_payload())
            except Exception:
                body = str(msg.get_payload())
    except Exception as e:
        body = f"[Body extraction error: {e}]"
    return body.strip() if body else "Not available"


def get_received_headers(msg) -> list:
    """Extract all Received headers in order."""
    received = []
    try:
        for key, value in msg.items():
            if key.lower() == "received":
                received.append(value.strip())
    except Exception:
        pass
    return received


def get_header_safe(msg, header_name: str) -> str:
    """Safely get and decode a header value."""
    try:
        val = msg.get(header_name)
        if val:
            return safe_decode_header(val)
    except Exception:
        pass
    return "Not available"


def parse_email(raw_email: str) -> dict:
    """
    Parse raw email string and return structured dict with all fields.

    Parameters
    ----------
    raw_email : str
        Raw email content (headers + body) or plain body text.

    Returns
    -------
    dict
        Structured email fields.
    """
    result = {
        "from": "Not available",
        "to": "Not available",
        "subject": "Not available",
        "date": "Not available",
        "message_id": "Not available",
        "reply_to": "Not available",
        "return_path": "Not available",
        "body": "Not available",
        "received_headers": [],
        "authentication_results": "Not available",
        "raw_headers": {},
        "all_headers": [],
        "parse_error": None,
    }

    if not raw_email or not raw_email.strip():
        result["parse_error"] = "Empty input"
        result["body"] = raw_email or ""
        return result

    try:
        # Try parsing as a proper email message
        msg = message_from_string(raw_email, policy=email.policy.compat32)

        result["from"] = get_header_safe(msg, "From")
        result["to"] = get_header_safe(msg, "To")
        result["subject"] = get_header_safe(msg, "Subject")
        result["date"] = get_header_safe(msg, "Date")
        result["message_id"] = get_header_safe(msg, "Message-ID")
        result["reply_to"] = get_header_safe(msg, "Reply-To")
        result["return_path"] = get_header_safe(msg, "Return-Path")
        result["authentication_results"] = get_header_safe(msg, "Authentication-Results")

        result["body"] = extract_body(msg)
        result["received_headers"] = get_received_headers(msg)

        # Collect all headers
        raw_headers = {}
        all_headers = []
        for key, value in msg.items():
            safe_val = safe_decode_header(value)
            raw_headers[key] = safe_val
            all_headers.append((key, safe_val))
        result["raw_headers"] = raw_headers
        result["all_headers"] = all_headers

        # If body still "Not available" but we have payload, treat whole input as body
        if result["body"] == "Not available" or not result["body"]:
            result["body"] = raw_email

    except Exception as e:
        result["parse_error"] = str(e)
        result["body"] = raw_email

    return result


def parse_eml_bytes(eml_bytes: bytes) -> dict:
    """Parse email from raw bytes (e.g., uploaded .eml file)."""
    try:
        raw = eml_bytes.decode("utf-8", errors="replace")
        return parse_email(raw)
    except Exception as e:
        return {
            "from": "Not available",
            "to": "Not available",
            "subject": "Not available",
            "date": "Not available",
            "message_id": "Not available",
            "reply_to": "Not available",
            "return_path": "Not available",
            "body": eml_bytes.decode("utf-8", errors="replace") if eml_bytes else "",
            "received_headers": [],
            "authentication_results": "Not available",
            "raw_headers": {},
            "all_headers": [],
            "parse_error": str(e),
        }
