"""
Email Threat Intelligence & Investigation System
Main Streamlit Application

Run with:  streamlit run app.py
"""

import sys
import os
import json
import datetime
import traceback
from pathlib import Path

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

import streamlit as st

# ── Page config (MUST be first Streamlit call) ────────────────────────────────
st.set_page_config(
    page_title="Email Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Module imports ─────────────────────────────────────────────────────────────
from modules.email_parser import parse_email, parse_eml_bytes
from modules.nlp_classifier import classify_email, get_model, force_retrain
from modules.indicator_extractor import extract_all_indicators
from modules.dns_analyzer import analyze_multiple_domains
from modules.reputation import check_multiple_domains, check_multiple_ips
from modules.geoip import geolocate_multiple, GEOIP_DISCLAIMER, format_location_string
from modules.header_analyzer import analyze_headers, get_auth_status_color, resolve_reverse_dns
from modules.risk_engine import correlate_risk
from modules.ai_investigator import investigate as ai_investigate, is_configured as ai_is_configured

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except ImportError:
    pass

# ── Sample content ─────────────────────────────────────────────────────────────
PHISHING_SAMPLE_PATH = ROOT / "samples" / "phishing.eml"
BENIGN_SAMPLE_PATH = ROOT / "samples" / "benign.eml"


def load_sample(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception as e:
        return f"Error loading sample: {e}"


# ── Custom CSS ─────────────────────────────────────────────────────────────────
def inject_css():
    st.markdown("""
<style>
/* ── Custom Scrollbar ── */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}
::-webkit-scrollbar-track {
    background: #0d1117;
}
::-webkit-scrollbar-thumb {
    background: #21262d;
    border-radius: 4px;
    border: 1px solid #30363d;
}
::-webkit-scrollbar-thumb:hover {
    background: #388bfd;
}

/* ── Keyframe Animations ── */
@keyframes titleGlow {
    0% { background-position: 0% 50%; }
    50% { background-position: 100% 50%; }
    100% { background-position: 0% 50%; }
}

/* ── Dark theme base ── */
[data-testid="stAppViewContainer"] {
    background-color: #0d1117;
    color: #c9d1d9;
}
[data-testid="stSidebar"] {
    background-color: #161b22;
    border-right: 1px solid #30363d;
}
[data-testid="stHeader"] {
    background-color: rgba(13, 17, 23, 0.85);
    backdrop-filter: blur(8px);
}

/* ── Main title with dynamic gradient ── */
.main-title {
    text-align: center;
    padding: 14px 0 10px 0;
    position: relative;
}
.main-title h1 {
    font-size: 2.35rem;
    font-weight: 800;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin: 0;
    background: linear-gradient(120deg, #58a6ff 0%, #79c0ff 25%, #388bfd 50%, #bc8cff 75%, #58a6ff 100%);
    background-size: 250% auto;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    animation: titleGlow 8s ease infinite;
    text-shadow: 0 0 35px rgba(56, 139, 253, 0.25);
}
.main-title .subtitle {
    color: #8b949e;
    font-size: 0.95rem;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    margin-top: 6px;
    font-weight: 500;
    transition: color 0.3s ease;
}
.main-title:hover .subtitle {
    color: #c9d1d9;
}
.main-title .tagline {
    color: #388bfd;
    font-size: 0.85rem;
    letter-spacing: 0.08em;
    margin-top: 4px;
    font-weight: 400;
}

/* ── Cards with Interactive Elevation ── */
.threat-card {
    background: linear-gradient(180deg, #161b22 0%, #11151c 100%);
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 18px 20px;
    margin: 8px 0;
    text-align: center;
    position: relative;
    overflow: hidden;
    transition: all 0.28s cubic-bezier(0.16, 1, 0.3, 1);
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}
.threat-card::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, rgba(56, 139, 253, 0.4), transparent);
    opacity: 0;
    transition: opacity 0.3s ease;
}
.threat-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 10px 24px -4px rgba(0, 0, 0, 0.6), 0 0 16px rgba(56, 139, 253, 0.18);
    border-color: #58a6ff;
}
.threat-card:hover::before {
    opacity: 1;
}
.threat-card h2 {
    margin: 4px 0;
    font-size: 2.1rem;
    font-weight: 700;
    letter-spacing: 0.02em;
    transition: transform 0.2s ease;
}
.threat-card:hover h2 {
    transform: scale(1.03);
}
.threat-card p {
    margin: 2px 0;
    color: #8b949e;
    font-size: 0.85rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
}

/* ── Risk level colors & glowing hover ── */
.risk-critical {
    border-color: #f85149 !important;
    color: #f85149;
    box-shadow: 0 0 12px rgba(248, 81, 73, 0.15);
}
.risk-critical:hover {
    box-shadow: 0 12px 28px -4px rgba(248, 81, 73, 0.35), 0 0 20px rgba(248, 81, 73, 0.25) !important;
    border-color: #ff7b72 !important;
}

.risk-high {
    border-color: #e3b341 !important;
    color: #e3b341;
    box-shadow: 0 0 12px rgba(227, 179, 65, 0.15);
}
.risk-high:hover {
    box-shadow: 0 12px 28px -4px rgba(227, 179, 65, 0.35), 0 0 20px rgba(227, 179, 65, 0.25) !important;
    border-color: #f1e05a !important;
}

.risk-medium {
    border-color: #d29922 !important;
    color: #d29922;
    box-shadow: 0 0 12px rgba(210, 153, 34, 0.12);
}
.risk-medium:hover {
    box-shadow: 0 12px 28px -4px rgba(210, 153, 34, 0.3), 0 0 18px rgba(210, 153, 34, 0.2) !important;
    border-color: #e3b341 !important;
}

.risk-low {
    border-color: #3fb950 !important;
    color: #3fb950;
    box-shadow: 0 0 12px rgba(63, 185, 80, 0.15);
}
.risk-low:hover {
    box-shadow: 0 12px 28px -4px rgba(63, 185, 80, 0.35), 0 0 20px rgba(63, 185, 80, 0.25) !important;
    border-color: #56d364 !important;
}

/* ── Section header with interactive hover ── */
.section-header {
    background: linear-gradient(90deg, rgba(56, 139, 253, 0.14) 0%, rgba(22, 27, 34, 0.7) 100%);
    border-left: 4px solid #388bfd;
    padding: 10px 16px;
    margin: 22px 0 12px 0;
    border-radius: 0 8px 8px 0;
    font-size: 1rem;
    font-weight: 700;
    color: #58a6ff;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    transition: all 0.25s ease;
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.2);
}
.section-header:hover {
    border-left-color: #79c0ff;
    padding-left: 20px;
    background: linear-gradient(90deg, rgba(88, 166, 255, 0.22) 0%, rgba(22, 27, 34, 0.85) 100%);
    color: #79c0ff;
    box-shadow: 0 4px 14px rgba(56, 139, 253, 0.15);
}

/* ── Interactive Badges ── */
.badge {
    display: inline-block;
    padding: 3px 12px;
    border-radius: 14px;
    font-size: 0.78rem;
    font-weight: 600;
    margin: 3px;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    cursor: default;
}
.badge:hover {
    transform: translateY(-2px) scale(1.06);
}
.badge-red     { background: #3d1a1a; color: #f85149; border: 1px solid #f85149; }
.badge-red:hover { box-shadow: 0 3px 10px rgba(248, 81, 73, 0.4); }

.badge-orange  { background: #2d1f00; color: #e3b341; border: 1px solid #e3b341; }
.badge-orange:hover { box-shadow: 0 3px 10px rgba(227, 179, 65, 0.4); }

.badge-yellow  { background: #2d2200; color: #d29922; border: 1px solid #d29922; }
.badge-yellow:hover { box-shadow: 0 3px 10px rgba(210, 153, 34, 0.4); }

.badge-green   { background: #0d2a0d; color: #3fb950; border: 1px solid #3fb950; }
.badge-green:hover { box-shadow: 0 3px 10px rgba(63, 185, 80, 0.4); }

.badge-blue    { background: #0d1f3c; color: #58a6ff; border: 1px solid #58a6ff; }
.badge-blue:hover { box-shadow: 0 3px 10px rgba(88, 166, 255, 0.4); }

.badge-gray    { background: #1f2428; color: #8b949e; border: 1px solid #30363d; }
.badge-gray:hover { box-shadow: 0 3px 10px rgba(139, 148, 158, 0.3); border-color: #8b949e; }

/* ── Auth pill ── */
.auth-pass   { color: #3fb950; font-weight: 700; transition: text-shadow 0.2s ease; }
.auth-pass:hover { text-shadow: 0 0 8px rgba(63, 185, 80, 0.6); }
.auth-fail   { color: #f85149; font-weight: 700; transition: text-shadow 0.2s ease; }
.auth-fail:hover { text-shadow: 0 0 8px rgba(248, 81, 73, 0.6); }
.auth-soft   { color: #e3b341; font-weight: 700; transition: text-shadow 0.2s ease; }
.auth-soft:hover { text-shadow: 0 0 8px rgba(227, 179, 65, 0.6); }
.auth-none   { color: #8b949e; font-weight: 700; }

/* ── Info, Warning & Disclaimer Boxes with Interactive Hover ── */
.info-box {
    background: #161b22;
    border: 1px solid #30363d;
    border-left: 4px solid #388bfd;
    border-radius: 8px;
    padding: 14px 18px;
    margin: 10px 0;
    font-size: 0.9rem;
    color: #c9d1d9;
    transition: all 0.25s ease;
}
.info-box:hover {
    border-color: #58a6ff;
    border-left-color: #58a6ff;
    transform: translateX(4px);
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.35);
}

.warning-box {
    background: #231904;
    border: 1px solid #e3b341;
    border-left: 4px solid #e3b341;
    border-radius: 8px;
    padding: 12px 16px;
    margin: 10px 0;
    font-size: 0.88rem;
    color: #e3b341;
    transition: all 0.25s ease;
}
.warning-box:hover {
    border-color: #f1e05a;
    border-left-color: #f1e05a;
    transform: translateX(4px);
    box-shadow: 0 4px 14px rgba(227, 179, 65, 0.2);
}

.disclaimer-box {
    background: #0d1f3c;
    border: 1px solid #388bfd;
    border-left: 4px solid #388bfd;
    border-radius: 8px;
    padding: 10px 16px;
    margin: 8px 0;
    font-size: 0.82rem;
    color: #8b949e;
    transition: all 0.25s ease;
}
.disclaimer-box:hover {
    border-color: #79c0ff;
    border-left-color: #79c0ff;
    color: #c9d1d9;
    transform: translateX(4px);
}

/* ── Interactive Buttons ── */
.stButton > button {
    border-radius: 8px;
    font-weight: 600;
    letter-spacing: 0.04em;
    padding: 0.55rem 1.25rem;
    transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
    position: relative;
    overflow: hidden;
    border: 1px solid #30363d;
}
.stButton > button:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.4), 0 0 12px rgba(88, 166, 255, 0.2);
    border-color: #58a6ff;
}
.stButton > button:active {
    transform: translateY(1px) scale(0.98);
}
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #238636 0%, #2ea043 100%);
    border: 1px solid #3fb950;
    color: #ffffff;
    box-shadow: 0 3px 12px rgba(35, 134, 54, 0.3);
}
.stButton > button[kind="primary"]:hover {
    background: linear-gradient(135deg, #2ea043 0%, #3fb950 100%);
    border-color: #56d364;
    box-shadow: 0 6px 22px rgba(46, 160, 67, 0.5), 0 0 16px rgba(63, 185, 80, 0.35);
    transform: translateY(-2px);
}

/* ── Interactive Text Area & Inputs ── */
.stTextArea textarea {
    background-color: #161b22 !important;
    color: #c9d1d9 !important;
    border: 1px solid #30363d !important;
    border-radius: 8px !important;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 0.88rem;
    transition: all 0.25s ease !important;
}
.stTextArea textarea:focus {
    border-color: #58a6ff !important;
    box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.25) !important;
    background-color: #0d1117 !important;
}
.stTextInput input {
    background-color: #161b22 !important;
    color: #c9d1d9 !important;
    border: 1px solid #30363d !important;
    border-radius: 8px !important;
    transition: all 0.25s ease !important;
}
.stTextInput input:focus {
    border-color: #58a6ff !important;
    box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.25) !important;
}

/* ── File Uploader Drag & Drop Area ── */
[data-testid="stFileUploader"] {
    border-radius: 8px;
    transition: all 0.25s ease;
}
[data-testid="stFileUploader"] section {
    background-color: #161b22 !important;
    border: 2px dashed #30363d !important;
    border-radius: 8px !important;
    transition: all 0.25s ease !important;
}
[data-testid="stFileUploader"] section:hover {
    border-color: #58a6ff !important;
    background-color: rgba(56, 139, 253, 0.05) !important;
    box-shadow: 0 0 14px rgba(56, 139, 253, 0.15) !important;
}

/* ── Interactive Navigation Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    gap: 4px;
    border-bottom: 1px solid #30363d;
}
.stTabs [data-baseweb="tab"] {
    color: #8b949e;
    font-size: 0.92rem;
    font-weight: 500;
    padding: 8px 16px;
    border-radius: 6px 6px 0 0;
    transition: all 0.2s ease;
    border: 1px solid transparent;
    border-bottom: none;
}
.stTabs [data-baseweb="tab"]:hover {
    color: #c9d1d9;
    background: rgba(56, 139, 253, 0.08);
}
.stTabs [aria-selected="true"] {
    color: #58a6ff !important;
    background: rgba(56, 139, 253, 0.12) !important;
    border-bottom: 3px solid #58a6ff !important;
    box-shadow: 0 3px 12px rgba(88, 166, 255, 0.3);
    font-weight: 600;
}

/* ── Interactive Expanders ── */
[data-testid="stExpander"] {
    background-color: #161b22 !important;
    border: 1px solid #30363d !important;
    border-radius: 8px !important;
    transition: all 0.25s ease !important;
    margin-bottom: 8px !important;
}
[data-testid="stExpander"]:hover {
    border-color: #58a6ff !important;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.35) !important;
}
[data-testid="stExpander"] summary {
    font-weight: 600 !important;
    transition: color 0.2s ease !important;
}
[data-testid="stExpander"] summary:hover {
    color: #58a6ff !important;
}

/* ── Metrics ── */
div[data-testid="stMetricValue"] {
    font-size: 1.65rem !important;
    font-weight: 700;
    letter-spacing: 0.02em;
    transition: transform 0.2s ease;
}
[data-testid="stMetric"]:hover div[data-testid="stMetricValue"] {
    transform: scale(1.04);
}

/* ── Interactive Tables / Dataframes ── */
[data-testid="stDataFrame"], .stTable {
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid #30363d;
    transition: border-color 0.25s ease;
}
[data-testid="stDataFrame"]:hover, .stTable:hover {
    border-color: #58a6ff;
}
</style>
""", unsafe_allow_html=True)


# ── Session state init ─────────────────────────────────────────────────────────
def init_session_state():
    defaults = {
        "email_text": "",
        "email_paste_input": "",
        "uploaded_file_name": None,
        "uploaded_file_text": "",
        "input_source": "paste",
        "uploader_id": 0,
        "analysis_result": None,
        "analysis_state": "IDLE",   # IDLE | ANALYZING | COMPLETE | ERROR
        "demo_mode": False,
        "model_status": "Not loaded",
        "error_message": "",
        "ai_investigation": None,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


# ── Analysis pipeline ─────────────────────────────────────────────────────────
def run_analysis(email_text: str, demo_mode: bool) -> dict:
    """Execute the complete analysis pipeline. Returns result dict."""
    result = {
        "email_text": email_text,
        "parsed": {},
        "nlp": {},
        "indicators": {},
        "dns": {},
        "domain_reputations": {},
        "ip_reputations": {},
        "header_analysis": {},
        "geo": {},
        "risk": {},
        "errors": [],
        "demo_mode": demo_mode,
        "timestamp": datetime.datetime.now().isoformat(),
    }

    # 1. Parse email
    try:
        result["parsed"] = parse_email(email_text)
    except Exception as e:
        result["errors"].append(f"Email parsing: {e}")
        result["parsed"] = {
            "from": "Not available", "to": "Not available",
            "subject": "Not available", "date": "Not available",
            "message_id": "Not available", "reply_to": "Not available",
            "return_path": "Not available",
            "body": email_text,
            "received_headers": [], "authentication_results": "Not available",
            "raw_headers": {}, "all_headers": [],
        }

    body = result["parsed"].get("body", email_text) or email_text
    received_raw = " ".join(result["parsed"].get("received_headers", []))
    headers_text = received_raw + " " + result["parsed"].get("authentication_results", "")

    # 2. NLP classification
    try:
        result["nlp"] = classify_email(body + " " + result["parsed"].get("subject", ""))
    except Exception as e:
        result["errors"].append(f"NLP classification: {e}")
        result["nlp"] = {
            "classification": "Unknown",
            "threat_probability": 0.0,
            "phishing_probability": 0.0,
            "benign_probability": 1.0,
            "suspicious_terms_found": [],
            "model_name": "TF-IDF + Logistic Regression",
            "error": str(e),
        }

    # 3. Indicator extraction
    try:
        result["indicators"] = extract_all_indicators(body, headers_text)
    except Exception as e:
        result["errors"].append(f"Indicator extraction: {e}")
        result["indicators"] = {
            "urls": [], "domains": [], "ips": [],
            "email_addresses": [], "ip_from_headers": [],
            "summary": {"url_count": 0, "domain_count": 0, "ip_count": 0, "email_count": 0, "total": 0},
        }

    # 4. Header analysis
    try:
        result["header_analysis"] = analyze_headers(result["parsed"], demo_mode=demo_mode)
        # Add IPs from headers and client origin to main IP list
        header_ips = list(result["header_analysis"].get("received_ips", []))
        client_ip = result["header_analysis"].get("origin_client_ip")
        if client_ip and client_ip not in header_ips:
            header_ips.append(client_ip)
        existing_ips = result["indicators"].get("ips", [])
        all_ips = list(dict.fromkeys(existing_ips + header_ips))
        result["indicators"]["ips"] = all_ips
        result["indicators"]["ip_from_headers"] = header_ips
    except Exception as e:
        result["errors"].append(f"Header analysis: {e}")
        result["header_analysis"] = {
            "spf": "none", "dkim": "none", "dmarc": "none",
            "received_ips": [], "hop_count": 0,
            "from_reply_to_mismatch": False, "from_return_path_mismatch": False,
            "suspicious_header_flags": [],
            "origin_client_ip": None,
            "origin_server_ip": None,
            "origin_server_hostname": "Not available",
            "hops": [],
        }

    # 5. DNS analysis
    try:
        domains = result["indicators"].get("domains", [])
        if not demo_mode and domains:
            result["dns"] = analyze_multiple_domains(domains[:5])  # limit for speed
        else:
            result["dns"] = {}

        # Add IPs resolved from domains so they get geolocated and mapped in the UI
        for dom, d_info in result.get("dns", {}).items():
            for a_rec in d_info.get("a_records", []):
                import re as _re
                if _re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", a_rec):
                    if a_rec not in result["indicators"]["ips"]:
                        result["indicators"]["ips"].append(a_rec)
    except Exception as e:
        result["errors"].append(f"DNS analysis: {e}")
        result["dns"] = {}

    # 6. Domain reputation
    try:
        domains = result["indicators"].get("domains", [])
        result["domain_reputations"] = check_multiple_domains(domains)
    except Exception as e:
        result["errors"].append(f"Domain reputation: {e}")
        result["domain_reputations"] = {}

    # 7. IP reputation
    try:
        ips = result["indicators"].get("ips", [])
        result["ip_reputations"] = check_multiple_ips(ips)
    except Exception as e:
        result["errors"].append(f"IP reputation: {e}")
        result["ip_reputations"] = {}

    # 8. GeoIP
    try:
        ips = result["indicators"].get("ips", [])
        if ips:
            result["geo"] = geolocate_multiple(ips, demo_mode=demo_mode)
        else:
            result["geo"] = {}
    except Exception as e:
        result["errors"].append(f"GeoIP: {e}")
        result["geo"] = {}

    # 9. Enrich Origin Server Candidate & Hops with GeoIP metadata
    origin_ip = result["header_analysis"].get("origin_server_ip")
    if not origin_ip:
        received_ips = result["header_analysis"].get("received_ips", [])
        origin_ip = received_ips[-1] if received_ips else None
        result["header_analysis"]["origin_server_ip"] = origin_ip

    result["header_analysis"]["origin_ip_candidate"] = origin_ip
    result["header_analysis"]["origin_geo"] = result["geo"].get(origin_ip, {}) if origin_ip else {}
    result["header_analysis"]["origin_ip_note"] = (
        f"Primary originating server IP detected in Received headers. Hostname: {result['header_analysis'].get('origin_server_hostname', 'N/A')}."
        if origin_ip else "No public Received-header IP available."
    )

    # Attach geo information to each structured hop
    for hop in result["header_analysis"].get("hops", []):
        p_ip = hop.get("public_ip")
        hop["geo"] = result["geo"].get(p_ip, {}) if p_ip else {}

    # 10. Risk correlation
    try:
        result["risk"] = correlate_risk(
            nlp_result=result["nlp"],
            indicators=result["indicators"],
            dns_results=result["dns"],
            domain_reputations=result["domain_reputations"],
            ip_reputations=result["ip_reputations"],
            header_analysis=result["header_analysis"],
            geo_results=result["geo"],
        )
    except Exception as e:
        result["errors"].append(f"Risk correlation: {e}")
        result["risk"] = {
            "risk_level": "UNKNOWN",
            "risk_icon": "⚪",
            "total_score": 0,
            "score_percentage": 0,
            "risk_factors": [],
            "risk_breakdown": {},
            "classification": result["nlp"].get("classification", "Unknown"),
            "threat_probability": result["nlp"].get("threat_probability", 0.0),
        }

    return result


# ── UI helpers ─────────────────────────────────────────────────────────────────
def risk_color_class(level: str) -> str:
    return {
        "CRITICAL": "risk-critical",
        "HIGH": "risk-high",
        "MEDIUM": "risk-medium",
        "LOW": "risk-low",
    }.get(level, "risk-low")


def rep_badge(reputation: str) -> str:
    badge_map = {
        "Malicious":  "badge-red",
        "Suspicious": "badge-orange",
        "Clean":      "badge-green",
        "Unknown":    "badge-gray",
    }
    cls = badge_map.get(reputation, "badge-gray")
    return f'<span class="badge {cls}">{reputation}</span>'


def auth_color(status: str) -> str:
    s = status.lower()
    if s == "pass":    return "auth-pass"
    if s == "fail":    return "auth-fail"
    if s == "softfail": return "auth-soft"
    return "auth-none"


def section(title: str):
    st.markdown(f'<div class="section-header">⬡ {title}</div>', unsafe_allow_html=True)


def generate_report(result: dict) -> str:
    """Generate a plain-text downloadable report."""
    lines = []
    lines.append("=" * 70)
    lines.append("EMAIL THREAT INTELLIGENCE & INVESTIGATION REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated: {result.get('timestamp', 'N/A')}")
    lines.append(f"Demo Mode: {'ON' if result.get('demo_mode') else 'OFF'}")
    lines.append("")

    # Risk summary
    risk = result.get("risk", {})
    lines.append("── FINAL RISK ASSESSMENT ──────────────────────────────────────────")
    lines.append(f"  Threat Level     : {risk.get('risk_level', 'UNKNOWN')}")
    lines.append(f"  Classification   : {risk.get('classification', 'Unknown')}")
    lines.append(f"  Threat Probability: {risk.get('threat_probability', 0):.0%}")
    lines.append(f"  Risk Score       : {risk.get('total_score', 0)}/100")
    lines.append("")

    if risk.get("risk_factors"):
        lines.append("Risk Factors:")
        for f in risk["risk_factors"]:
            lines.append(f"  ✓ {f}")
    lines.append("")

    # Email details
    parsed = result.get("parsed", {})
    lines.append("── EMAIL DETAILS ──────────────────────────────────────────────────")
    lines.append(f"  From        : {parsed.get('from', 'N/A')}")
    lines.append(f"  To          : {parsed.get('to', 'N/A')}")
    lines.append(f"  Subject     : {parsed.get('subject', 'N/A')}")
    lines.append(f"  Date        : {parsed.get('date', 'N/A')}")
    lines.append(f"  Message-ID  : {parsed.get('message_id', 'N/A')}")
    lines.append(f"  Reply-To    : {parsed.get('reply_to', 'N/A')}")
    lines.append(f"  Return-Path : {parsed.get('return_path', 'N/A')}")
    lines.append("")

    # NLP
    nlp = result.get("nlp", {})
    lines.append("── NLP ANALYSIS ───────────────────────────────────────────────────")
    lines.append(f"  Model           : {nlp.get('model_name', 'N/A')}")
    lines.append(f"  Classification  : {nlp.get('classification', 'N/A')}")
    lines.append(f"  Threat Probability: {nlp.get('threat_probability', 0):.1%}")
    terms = nlp.get("suspicious_terms_found", [])
    lines.append(f"  Suspicious Terms: {', '.join(terms) if terms else 'None'}")
    lines.append("")

    # Indicators
    ind = result.get("indicators", {})
    lines.append("── EXTRACTED INDICATORS ───────────────────────────────────────────")
    lines.append(f"  URLs Extracted   : {len(ind.get('urls', []))}")
    for u in ind.get("urls", []):
        lines.append(f"    - {u.get('url', '')}")
    lines.append(f"  Domains          : {', '.join(ind.get('domains', [])) or 'None'}")
    lines.append(f"  IP Addresses     : {', '.join(ind.get('ips', [])) or 'None'}")
    lines.append(f"  Email Addresses  : {', '.join(ind.get('email_addresses', [])) or 'None'}")
    lines.append("")

    # Headers & Origin Server Tracking
    ha = result.get("header_analysis", {})
    lines.append("── EMAIL AUTHENTICATION & SENDER SERVER ORIGIN ───────────────────")
    lines.append(f"  SPF   : {ha.get('spf', 'none').upper()}")
    lines.append(f"  DKIM  : {ha.get('dkim', 'none').upper()}")
    lines.append(f"  DMARC : {ha.get('dmarc', 'none').upper()}")
    lines.append(f"  Origin Server IP    : {ha.get('origin_server_ip') or 'Not detected'}")
    lines.append(f"  Reverse DNS (PTR)   : {ha.get('origin_server_hostname', 'N/A')}")
    origin_geo = ha.get("origin_geo", {})
    if origin_geo:
        lines.append(f"  Server Location     : {origin_geo.get('city', 'Unknown')}, {origin_geo.get('region', 'Unknown')}, {origin_geo.get('country', 'Unknown')}")
        lines.append(f"  Server ISP & Org    : {origin_geo.get('isp', 'Unknown')} | {origin_geo.get('organization', 'Unknown')}")
        lines.append(f"  Server ASN          : {origin_geo.get('asn', 'N/A')} {origin_geo.get('asn_description', '')}")
    if ha.get("origin_client_ip"):
        lines.append(f"  Client Origin IP    : {ha.get('origin_client_ip')} (X-Originating-IP / Auth)")
    lines.append(f"  Total Received Hops : {ha.get('hop_count', 0)}")
    hops = ha.get("hops", [])
    if hops:
        lines.append("  Chronological Delivery Path:")
        for h in hops:
            lines.append(f"    - Hop {h.get('hop_number')}: {h.get('from_host')} -> {h.get('by_host')} [{h.get('public_ip') or 'Internal'}] ({h.get('reverse_dns', 'N/A')})")
    lines.append("")

    # DNS
    dns = result.get("dns", {})
    if dns:
        lines.append("── DNS ANALYSIS ───────────────────────────────────────────────────")
        for domain, info in dns.items():
            lines.append(f"  {domain}: {info.get('status', 'N/A')}")
            if info.get("a_records"):
                lines.append(f"    A: {', '.join(info['a_records'])}")
            if info.get("mx_records"):
                lines.append(f"    MX: {', '.join(info['mx_records'])}")
        lines.append("")

    # Reputation
    dr = result.get("domain_reputations", {})
    ir = result.get("ip_reputations", {})
    if dr or ir:
        lines.append("── REPUTATION ─────────────────────────────────────────────────────")
        for domain, rep in dr.items():
            lines.append(f"  Domain {domain}: {rep.get('reputation', 'Unknown')} [{rep.get('source', '')}]")
        for ip, rep in ir.items():
            lines.append(f"  IP {ip}: {rep.get('reputation', 'Unknown')} [{rep.get('source', '')}]")
        lines.append("")

    # GeoIP
    geo = result.get("geo", {})
    if geo:
        lines.append("── GEOLOCATION (APPROXIMATE) ──────────────────────────────────────")
        lines.append(f"  NOTE: {GEOIP_DISCLAIMER}")
        lines.append("")
        for ip, g in geo.items():
            lines.append(f"  IP: {ip}")
            lines.append(f"    Location: {g.get('city', '')}, {g.get('region', '')}, {g.get('country', '')}")
            lines.append(f"    ISP: {g.get('isp', 'N/A')}")
            lines.append(f"    ASN: {g.get('asn', 'N/A')} {g.get('asn_description', '')}")
            lines.append(f"    Source: {g.get('source', 'N/A')}")
        lines.append("")

    # Errors
    errors = result.get("errors", [])
    if errors:
        lines.append("── ANALYSIS ERRORS / WARNINGS ─────────────────────────────────────")
        for e in errors:
            lines.append(f"  ⚠ {e}")
        lines.append("")

    lines.append("=" * 70)
    lines.append("DISCLAIMER: This is a prototype tool for demonstration purposes.")
    lines.append("Results should not be used as sole basis for security decisions.")
    lines.append("Prototype reputation results are NOT real threat intelligence.")
    lines.append("IP geolocation is approximate and may not reflect attacker location.")
    lines.append("=" * 70)

    return "\n".join(lines)


# ── Sidebar ───────────────────────────────────────────────────────────────────
def render_sidebar():
    with st.sidebar:
        st.markdown("### 🛡️ ETI System")
        st.markdown("---")

        # Demo mode toggle
        demo = st.toggle(
            "Demo Mode",
            value=st.session_state.demo_mode,
            key="demo_toggle",
            help="Demo mode uses simulated GeoIP and skips live DNS. Turn OFF for real public-IP GeoIP lookups.",
        )
        st.session_state.demo_mode = demo

        if demo:
            st.markdown('<div class="warning-box">⚠ Demo Mode ON — Using local/simulated data</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="info-box">🌐 Live Mode — Real DNS queries active</div>', unsafe_allow_html=True)

        st.markdown("---")

        # Sample loaders
        st.markdown("**Load Sample Email**")

        def load_phishing_sample():
            sample = load_sample(PHISHING_SAMPLE_PATH)
            st.session_state.email_paste_input = sample
            st.session_state.email_text = sample
            st.session_state.input_source = "paste"
            st.session_state.analysis_result = None
            st.session_state.ai_investigation = None
            st.session_state.analysis_state = "IDLE"

        def load_benign_sample():
            sample = load_sample(BENIGN_SAMPLE_PATH)
            st.session_state.email_paste_input = sample
            st.session_state.email_text = sample
            st.session_state.input_source = "paste"
            st.session_state.analysis_result = None
            st.session_state.ai_investigation = None
            st.session_state.analysis_state = "IDLE"

        col1, col2 = st.columns(2)
        with col1:
            st.button("🎣 Phishing", key="phishing_sample_btn", on_click=load_phishing_sample, use_container_width=True)
        with col2:
            st.button("✅ Benign", key="benign_sample_btn", on_click=load_benign_sample, use_container_width=True)

        st.markdown("---")

        # Model info
        st.markdown("**Model Status**")
        try:
            get_model()
            st.success("✅ Model ready")
        except Exception as e:
            st.error(f"❌ Model error: {str(e)[:40]}")

        if st.button("🔄 Retrain Model", key="retrain_btn", use_container_width=True):
            with st.spinner("Retraining..."):
                r = force_retrain()
            if r["success"]:
                st.success(r["message"])
            else:
                st.error(r["message"])

        st.markdown("---")
        st.markdown("**Environment**")
        rep_key = "✅ Set" if os.environ.get("REPUTATION_API_KEY") else "❌ Not set"
        geo_key = "🌐 Built-in ip-api"
        openai_key = "✅ Set" if ai_is_configured() else "❌ Not set"
        st.markdown(f"REPUTATION_API_KEY: {rep_key}")
        st.markdown(f"GeoIP: {geo_key}")
        st.markdown(f"OPENAI_API_KEY: {openai_key}")

        st.markdown("---")
        st.caption("Email Threat Intelligence System v1.0 | Prototype")
        st.caption("⚠ Not for production use")


# ── Main sections ─────────────────────────────────────────────────────────────
def render_header():
    st.markdown("""
<div class="main-title">
  <h1>🛡️ Email Threat Intelligence</h1>
  <div class="subtitle">&amp; Investigation System</div>
  <div class="tagline">Analyze &bull; Investigate &bull; Correlate &bull; Assess</div>
</div>
""", unsafe_allow_html=True)
    st.markdown("---")


def render_input_section():
    section("Email Input")

    tab_paste, tab_upload = st.tabs(["📋 Paste Email", "📁 Upload .eml"])

    def on_paste_changed():
        st.session_state.input_source = "paste"
        st.session_state.analysis_result = None
        st.session_state.ai_investigation = None
        st.session_state.analysis_state = "IDLE"

    def on_upload_changed():
        st.session_state.input_source = "upload"
        st.session_state.analysis_result = None
        st.session_state.ai_investigation = None
        st.session_state.analysis_state = "IDLE"

    with tab_paste:
        st.text_area(
            "Paste email content here (headers + body or plain body):",
            height=220,
            key="email_paste_input",
            on_change=on_paste_changed,
            placeholder="Paste full email content including headers...\n\nOr use the sidebar to load a sample email.",
        )

    with tab_upload:
        uploader_key = "eml_uploader" if st.session_state.get("uploader_id", 0) == 0 else f"eml_uploader_{st.session_state.uploader_id}"
        uploaded = st.file_uploader(
            "Upload Email (.eml)",
            type=["eml", "txt"],
            key=uploader_key,
            on_change=on_upload_changed,
        )
        if uploaded is not None:
            raw_bytes = uploaded.getvalue()
            raw_text = raw_bytes.decode("utf-8", errors="replace")
            st.session_state.uploaded_file_name = uploaded.name
            st.session_state.uploaded_file_text = raw_text
            st.success(f"✅ Loaded: {uploaded.name} ({len(raw_bytes):,} bytes)")
            with st.expander("📄 View Uploaded Content", expanded=False):
                st.code(raw_text[:2000] + ("\n... [truncated]" if len(raw_text) > 2000 else ""), language="text")
        else:
            st.session_state.uploaded_file_name = None
            st.session_state.uploaded_file_text = ""
            if st.session_state.get("input_source") == "upload":
                st.session_state.input_source = "paste"

    # Synchronize email_text based on active input source
    pasted_text = st.session_state.get("email_paste_input", "")
    uploaded_text = st.session_state.get("uploaded_file_text", "")

    if st.session_state.get("input_source") == "upload" and uploaded_text:
        st.session_state.email_text = uploaded_text
    elif st.session_state.get("input_source") == "paste" and pasted_text.strip():
        st.session_state.email_text = pasted_text
    elif uploaded_text:
        st.session_state.email_text = uploaded_text
    else:
        st.session_state.email_text = pasted_text

    def handle_clear():
        st.session_state.email_text = ""
        st.session_state.email_paste_input = ""
        st.session_state.uploaded_file_name = None
        st.session_state.uploaded_file_text = ""
        st.session_state.input_source = "paste"
        st.session_state.analysis_result = None
        st.session_state.ai_investigation = None
        st.session_state.analysis_state = "IDLE"
        st.session_state.error_message = ""
        st.session_state.uploader_id = st.session_state.get("uploader_id", 0) + 1

    # Action buttons
    st.markdown("")
    col_analyze, col_rerun, col_clear = st.columns([2, 1, 1])

    with col_analyze:
        analyze_clicked = st.button(
            "🔍 ANALYZE EMAIL",
            key="analyze_btn",
            type="primary",
            use_container_width=True,
        )

    with col_rerun:
        rerun_clicked = st.button(
            "🔁 Re-run",
            key="rerun_btn",
            use_container_width=True,
            disabled=(not st.session_state.email_text.strip()),
        )

    with col_clear:
        st.button(
            "🗑️ Clear",
            key="clear_btn",
            on_click=handle_clear,
            use_container_width=True,
        )

    # Handle analyze / re-run
    trigger_analysis = analyze_clicked or rerun_clicked

    if trigger_analysis:
        if not st.session_state.email_text.strip():
            st.warning("⚠️ Please paste an email or upload a .eml file first.")
        else:
            st.session_state.analysis_state = "ANALYZING"
            with st.spinner("🔍 Analyzing email... Please wait."):
                try:
                    result = run_analysis(
                        st.session_state.email_text,
                        st.session_state.demo_mode,
                    )
                    st.session_state.analysis_result = result
                    st.session_state.analysis_state = "COMPLETE"
                    if result.get("errors"):
                        st.session_state.error_message = "; ".join(result["errors"][:3])
                except Exception as e:
                    st.session_state.analysis_state = "ERROR"
                    st.session_state.error_message = str(e)
                    st.session_state.analysis_result = None
            st.rerun()


def render_status_banner():
    state = st.session_state.analysis_state
    if state == "COMPLETE":
        errors = st.session_state.analysis_result.get("errors", []) if st.session_state.analysis_result else []
        if errors:
            st.markdown(
                '<div class="warning-box">⚠️ Analysis completed with limited information. '
                'Some enrichment services were unavailable.</div>',
                unsafe_allow_html=True,
            )
        else:
            st.success("✅ Analysis complete")
    elif state == "ERROR":
        st.error(f"❌ Analysis failed: {st.session_state.error_message}")
    elif state == "IDLE" and not st.session_state.email_text:
        st.markdown(
            '<div class="info-box">ℹ️ Load a sample email from the sidebar or paste/upload an email, then click <b>ANALYZE EMAIL</b>.</div>',
            unsafe_allow_html=True,
        )


def render_executive_summary(result: dict):
    section("Executive Summary")
    risk = result.get("risk", {})
    nlp = result.get("nlp", {})
    indicators = result.get("indicators", {})

    risk_level = risk.get("risk_level", "UNKNOWN")
    risk_icon = risk.get("risk_icon", "⚪")
    threat_prob = nlp.get("threat_probability", 0.0)
    classification = nlp.get("classification", "Unknown")
    total_indicators = indicators.get("summary", {}).get("total", 0)
    risk_css = risk_color_class(risk_level)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
<div class="threat-card {risk_css}">
  <p>Threat Level</p>
  <h2>{risk_icon} {risk_level}</h2>
</div>""", unsafe_allow_html=True)

    with col2:
        prob_pct = f"{threat_prob:.0%}"
        st.markdown(f"""
<div class="threat-card">
  <p>Threat Probability</p>
  <h2>{prob_pct}</h2>
</div>""", unsafe_allow_html=True)

    with col3:
        cls_icon = "🎣" if classification == "Phishing" else ("⚠️" if classification == "Suspicious" else "✅")
        st.markdown(f"""
<div class="threat-card">
  <p>Classification</p>
  <h2>{cls_icon} {classification}</h2>
</div>""", unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
<div class="threat-card">
  <p>Indicators Found</p>
  <h2>🔎 {total_indicators}</h2>
</div>""", unsafe_allow_html=True)


def render_email_details(result: dict):
    section("Email Details")
    parsed = result.get("parsed", {})

    col1, col2 = st.columns(2)
    fields_left = [
        ("From", parsed.get("from", "Not available")),
        ("To", parsed.get("to", "Not available")),
        ("Subject", parsed.get("subject", "Not available")),
        ("Date", parsed.get("date", "Not available")),
    ]
    fields_right = [
        ("Message-ID", parsed.get("message_id", "Not available")),
        ("Reply-To", parsed.get("reply_to", "Not available")),
        ("Return-Path", parsed.get("return_path", "Not available")),
        ("Hop Count", str(len(parsed.get("received_headers", [])))),
    ]

    with col1:
        for label, value in fields_left:
            st.markdown(f"**{label}:** `{value}`")
    with col2:
        for label, value in fields_right:
            st.markdown(f"**{label}:** `{value}`")

    with st.expander("📧 Email Body Preview"):
        body = parsed.get("body", "Not available") or "Not available"
        st.text_area("Body", value=body[:3000] + ("..." if len(body) > 3000 else ""),
                     height=180, disabled=True, key="body_preview")


def render_sender_server_section(result: dict):
    section("Sender Server Origin & Route Tracking")

    ha = result.get("header_analysis", {})
    origin_ip = ha.get("origin_server_ip")
    origin_hostname = ha.get("origin_server_hostname", "Not resolved")
    origin_geo = ha.get("origin_geo", {})
    origin_client_ip = ha.get("origin_client_ip")
    hops = ha.get("hops", [])
    demo_mode = result.get("demo_mode", False)

    if not origin_ip and not hops:
        st.info("No Received headers or server routing hops were found in this email.")
        return

    # 1. Primary Origin Server Card
    st.markdown("#### 🧭 Originating Mail Server Profile")
    st.caption("Identified from the earliest hop in the Received-header chain.")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
<div class="threat-card" style="padding: 12px 14px;">
  <p>Origin Server IP</p>
  <h3 style="margin: 4px 0; font-size: 1.25rem; color: #58a6ff;">{origin_ip or 'Unknown'}</h3>
</div>""", unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
<div class="threat-card" style="padding: 12px 14px;">
  <p>Reverse DNS (PTR)</p>
  <h3 style="margin: 4px 0; font-size: 0.95rem; color: #c9d1d9; word-break: break-all;">{origin_hostname}</h3>
</div>""", unsafe_allow_html=True)

    with col3:
        loc = format_location_string(origin_geo) if origin_geo else "Unknown"
        st.markdown(f"""
<div class="threat-card" style="padding: 12px 14px;">
  <p>Physical Location</p>
  <h3 style="margin: 4px 0; font-size: 1.05rem; color: #3fb950;">📍 {loc}</h3>
</div>""", unsafe_allow_html=True)

    with col4:
        isp_name = origin_geo.get("isp", "Unknown") if origin_geo else "Unknown"
        asn_val = origin_geo.get("asn", "") if origin_geo else ""
        asn_str = f"({asn_val})" if asn_val else ""
        st.markdown(f"""
<div class="threat-card" style="padding: 12px 14px;">
  <p>Hosting / ISP</p>
  <h3 style="margin: 4px 0; font-size: 0.95rem; color: #e3b341; word-break: break-word;">🏢 {isp_name} {asn_str}</h3>
</div>""", unsafe_allow_html=True)

    # Client IP highlight if detected
    if origin_client_ip:
        client_geo = result.get("geo", {}).get(origin_client_ip, {})
        client_loc = format_location_string(client_geo) if client_geo else "Location lookup unavailable"
        st.markdown(
            f'<div class="info-box">📍 <b>Sender Device / Client Origin IP:</b> <code>{origin_client_ip}</code> '
            f'(Extracted from explicit client headers like <i>X-Originating-IP</i> or authentication results). '
            f'<b>Client Location:</b> {client_loc}.</div>',
            unsafe_allow_html=True
        )

    # Server Threat / Authentication Checks
    spf_status = ha.get("spf", "none").lower()
    is_tor_or_proxy = origin_geo.get("is_proxy_or_hosting", False) or "tor" in origin_hostname.lower()

    if is_tor_or_proxy:
        st.markdown(
            '<div class="warning-box">⚠️ <b>Anonymization / Proxy / Tor Server:</b> The originating server IP or hostname '
            'is flagged as an anonymization service (Tor exit node, VPN, or public cloud host). '
            'The real sender is likely routing traffic through this intermediary server.</div>',
            unsafe_allow_html=True
        )

    if spf_status in ("fail", "softfail"):
        st.markdown(
            f'<div class="warning-box">❌ <b>SPF Alignment Failure:</b> The sender domain does not designate server '
            f'<code>{origin_ip}</code> as an authorized outbound mail server (SPF {spf_status.upper()}). '
            f'This email may be spoofed!</div>',
            unsafe_allow_html=True
        )
    elif spf_status == "pass":
        st.markdown(
            f'<div class="info-box">✅ <b>SPF Aligned:</b> Server <code>{origin_ip}</code> is authorized by the sender '
            f'domain\'s SPF DNS record.</div>',
            unsafe_allow_html=True
        )

    # 2. Chronological Hop-by-Hop Route Trace Table
    st.markdown("#### 🛤️ Chronological Delivery Route (Hop-by-Hop)")
    st.caption("Reconstructed in order of transmission from the sender's mail system (Hop 1) to the destination server.")

    if hops:
        hop_rows = []
        for h in hops:
            h_num = h.get("hop_number", 1)
            h_role = "🚀 Origin Server" if h_num == 1 else ("🏁 Destination MX" if h_num == len(hops) else "🔄 Intermediate Relay")
            h_ip = h.get("public_ip") or ("Internal / LAN" if h.get("is_private_only") else "N/A")
            h_rdns = h.get("reverse_dns", "N/A")
            h_loc = format_location_string(h.get("geo", {})) if h.get("geo") else ("Internal Network" if h.get("is_private_only") else "Unknown")
            h_isp = h.get("geo", {}).get("isp", "N/A") if h.get("geo") else "N/A"

            hop_rows.append({
                "Hop": f"#{h_num}",
                "Stage": h_role,
                "Sender / From Host": h.get("from_host", "N/A")[:35],
                "Receiving / By Host": h.get("by_host", "N/A")[:35],
                "IP Address": h_ip,
                "Reverse DNS (PTR)": h_rdns[:35],
                "Location": h_loc,
                "ISP / Provider": h_isp[:25],
                "Protocol": h.get("protocol", "SMTP"),
                "Timestamp": h.get("timestamp", "N/A")[:25],
            })

        import pandas as pd
        df_hops = pd.DataFrame(hop_rows)
        st.dataframe(df_hops, use_container_width=True, hide_index=True)

    # 3. Interactive Route Map
    map_points = []
    if hops:
        for h in hops:
            g = h.get("geo", {})
            lat = g.get("latitude")
            lon = g.get("longitude")
            if lat is not None and lon is not None:
                map_points.append({"lat": lat, "lon": lon})

    if not map_points and origin_geo:
        lat = origin_geo.get("latitude")
        lon = origin_geo.get("longitude")
        if lat is not None and lon is not None:
            map_points.append({"lat": lat, "lon": lon})

    if map_points:
        st.markdown("#### 🗺️ Geographic Route Map")
        import pandas as pd
        map_df = pd.DataFrame(map_points)
        st.map(map_df, zoom=2, use_container_width=True)
        st.caption(f"Visualizing {len(map_points)} physical server location(s) traversed along the transmission route.")

    st.markdown("---")


def render_nlp_section(result: dict):
    section("NLP Analysis")
    nlp = result.get("nlp", {})

    col1, col2 = st.columns([1, 1])
    with col1:
        classification = nlp.get("classification", "Unknown")
        prob = nlp.get("threat_probability", 0.0)
        model_name = nlp.get("model_name", "N/A")

        cls_color = {"Phishing": "🔴", "Suspicious": "🟡", "Benign": "🟢", "Unknown": "⚪"}.get(classification, "⚪")
        st.markdown(f"**Classification:** {cls_color} **{classification}**")
        st.markdown(f"**Threat Probability:** `{prob:.1%}`")
        st.markdown(f"**Model:** `{model_name}`")

        if nlp.get("error"):
            st.warning(f"⚠ Classifier note: {nlp['error']}")

        st.markdown(
            '<div class="disclaimer-box">ℹ️ Prototype ML dataset is small. '
            'Probability is indicative, not a guaranteed measure of maliciousness.</div>',
            unsafe_allow_html=True
        )

    with col2:
        st.markdown("**Threat Probability**")
        bar_color = "#f85149" if prob >= 0.65 else ("#e3b341" if prob >= 0.40 else "#3fb950")
        st.markdown(f"""
<div style="background:#21262d;border-radius:6px;height:24px;overflow:hidden;margin:4px 0 10px 0;">
  <div style="background:{bar_color};width:{prob*100:.0f}%;height:100%;border-radius:6px;
              display:flex;align-items:center;justify-content:center;color:#0d1117;
              font-weight:700;font-size:0.85rem;">
    {prob*100:.0f}%
  </div>
</div>""", unsafe_allow_html=True)

        phish_p = nlp.get("phishing_probability", prob)
        benign_p = nlp.get("benign_probability", 1 - prob)
        st.markdown(f"Phishing probability: **{phish_p:.1%}**")
        st.markdown(f"Benign probability: **{benign_p:.1%}**")

    terms = nlp.get("suspicious_terms_found", [])
    if terms:
        st.markdown("**Observed Suspicious Terms** *(for explainability — ML decision is independent)*")
        badges = " ".join(f'<span class="badge badge-orange">{t}</span>' for t in terms)
        st.markdown(badges, unsafe_allow_html=True)


def render_indicators_section(result: dict):
    section("Extracted Indicators")
    indicators = result.get("indicators", {})
    summary = indicators.get("summary", {})

    s_col1, s_col2, s_col3, s_col4 = st.columns(4)
    s_col1.metric("URLs", summary.get("url_count", 0))
    s_col2.metric("Domains", summary.get("domain_count", 0))
    s_col3.metric("IPs", summary.get("ip_count", 0))
    s_col4.metric("Emails", summary.get("email_count", 0))

    tab_urls, tab_domains, tab_ips, tab_emails = st.tabs(["🔗 URLs", "🌐 Domains", "📡 IPs", "📧 Email Addresses"])

    with tab_urls:
        urls = indicators.get("urls", [])
        if not urls:
            st.info("No URLs extracted.")
        else:
            for u in urls:
                risk_score = u.get("risk_score", 0)
                badge_cls = "badge-red" if risk_score >= 4 else ("badge-orange" if risk_score >= 2 else "badge-green")
                inds = u.get("suspicious_indicators", [])
                with st.expander(f"{'🔴' if risk_score >= 4 else '🟡' if risk_score >= 2 else '🟢'} {u.get('url', '')[:70]}"):
                    c1, c2 = st.columns(2)
                    c1.markdown(f"**Domain:** `{u.get('domain', 'N/A')}`")
                    c1.markdown(f"**Scheme:** `{u.get('scheme', 'N/A')}`")
                    c1.markdown(f"**Path:** `{u.get('path', '/') or '/'}`")
                    c2.markdown(f"**HTTPS:** {'✅' if u.get('is_https') else '❌'}")
                    c2.markdown(f"**IP Hostname:** {'⚠️ Yes' if u.get('is_ip_hostname') else 'No'}")
                    c2.markdown(f"**URL Shortener:** {'⚠️ Yes' if u.get('is_shortener') else 'No'}")
                    if inds:
                        st.markdown("**Suspicious Indicators:**")
                        for i in inds:
                            st.markdown(f"  • {i}")

    with tab_domains:
        domains = indicators.get("domains", [])
        if not domains:
            st.info("No domains extracted.")
        else:
            dr = result.get("domain_reputations", {})
            for d in domains:
                rep_info = dr.get(d, {})
                rep = rep_info.get("reputation", "Unknown")
                badge = rep_badge(rep)
                st.markdown(f"`{d}` {badge}", unsafe_allow_html=True)

    with tab_ips:
        ips = indicators.get("ips", [])
        if not ips:
            st.info("No public IP addresses extracted.")
        else:
            ir = result.get("ip_reputations", {})
            header_ips = indicators.get("ip_from_headers", [])
            for ip in ips:
                rep_info = ir.get(ip, {})
                rep = rep_info.get("reputation", "Unknown")
                badge = rep_badge(rep)
                source_label = " *(from headers)*" if ip in header_ips else ""
                st.markdown(f"`{ip}` {badge}{source_label}", unsafe_allow_html=True)

    with tab_emails:
        email_addrs = indicators.get("email_addresses", [])
        if not email_addrs:
            st.info("No email addresses extracted.")
        else:
            for e in email_addrs:
                st.markdown(f"• `{e}`")


def render_infrastructure_section(result: dict):
    section("Infrastructure Investigation")

    dns_results = result.get("dns", {})
    demo_mode = result.get("demo_mode", True)

    col_dns, col_geo = st.columns(2)

    with col_dns:
        st.markdown("#### 🔍 DNS Analysis")
        if demo_mode:
            st.markdown('<div class="warning-box">⚠ Demo Mode: DNS lookups skipped. Disable Demo Mode for live DNS.</div>', unsafe_allow_html=True)
        elif not dns_results:
            st.info("No domains to analyze or DNS library unavailable.")
        else:
            for domain, info in dns_results.items():
                status = info.get("status", "Unknown")
                status_icon = "✅" if status == "Resolved" else "❌"
                with st.expander(f"{status_icon} {domain} — {status}"):
                    a = info.get("a_records", [])
                    mx = info.get("mx_records", [])
                    ns = info.get("ns_records", [])
                    st.markdown(f"**Status:** `{status}`")
                    st.markdown(f"**A Records:** `{', '.join(a) if a else 'None'}`")
                    st.markdown(f"**MX Records:** `{', '.join(mx) if mx else 'None'}`")
                    st.markdown(f"**NS Records:** `{', '.join(ns) if ns else 'None'}`")
                    aaaa = info.get("aaaa_records", [])
                    if aaaa:
                        st.markdown(f"**AAAA Records:** `{', '.join(aaaa)}`")

    with col_geo:
        st.markdown("#### 🌍 Approximate IP Infrastructure Location")
        st.markdown(
            f'<div class="disclaimer-box">⚠ {GEOIP_DISCLAIMER}</div>',
            unsafe_allow_html=True
        )

        geo_results = result.get("geo", {})
        if not geo_results:
            st.info("No public IPs to geolocate.")
        else:
            for ip, geo in geo_results.items():
                if geo.get("is_demo") or "PROTOTYPE" in geo.get("source", ""):
                    badge_src = '<span class="badge badge-yellow">Prototype Demo Data</span>'
                else:
                    badge_src = '<span class="badge badge-blue">ip-api.com</span>'

                st.markdown(f"**IP:** `{ip}` {badge_src}", unsafe_allow_html=True)

                if geo.get("error") and not geo.get("country"):
                    st.markdown(f"  ⚠ {geo['error']}")
                    continue

                c1, c2 = st.columns(2)
                c1.markdown(f"**Country:** {geo.get('country', 'Unknown')}")
                c1.markdown(f"**Region:** {geo.get('region', 'Unknown')}")
                c1.markdown(f"**City:** {geo.get('city', 'Unknown')}")
                c2.markdown(f"**ISP:** {geo.get('isp', 'Unknown')}")
                c2.markdown(f"**ASN:** {geo.get('asn', 'N/A')}")
                c2.markdown(f"**Org:** {geo.get('organization', 'Unknown')}")

                if ip == result.get("header_analysis", {}).get("origin_ip_candidate"):
                    st.markdown(
                        '<div class="info-box">🧭 <b>Origin IP candidate:</b> this is the oldest public IP found in the Received-header chain. '
                        "It is only a routing candidate and does not prove the sender's device or physical location.</div>",
                        unsafe_allow_html=True
                    )

                if geo.get("is_proxy_or_hosting"):
                    st.markdown(
                        '<div class="warning-box">⚠ Possible anonymization/proxy infrastructure detected. '
                        'Geolocation may represent the intermediary server rather than the attacker.</div>',
                        unsafe_allow_html=True
                    )

                # Map
                lat = geo.get("latitude")
                lon = geo.get("longitude")
                if lat and lon:
                    import pandas as pd
                    map_df = pd.DataFrame({"lat": [lat], "lon": [lon]})
                    st.map(map_df, zoom=3, use_container_width=True)

                st.markdown("---")

    # WHOIS placeholder
    with st.expander("📋 WHOIS / Domain Information"):
        st.markdown(
            '<div class="info-box">ℹ WHOIS lookup is not included in this prototype to avoid external service dependencies. '
            'In production, integrate with python-whois or a WHOIS API. WHOIS data may be redacted (GDPR).</div>',
            unsafe_allow_html=True
        )
        domains = result.get("indicators", {}).get("domains", [])
        if domains:
            st.markdown("**Domains to investigate:**")
            for d in domains:
                st.markdown(f"  • `{d}` — [Look up on whois.domaintools.com](https://whois.domaintools.com/{d})")


def render_reputation_section(result: dict):
    section("Reputation Intelligence")

    st.markdown(
        '<div class="disclaimer-box">⚠ Prototype Reputation — Results use local demonstration lists, NOT real threat intelligence. '
        'Set REPUTATION_API_KEY environment variable to enable external API.</div>',
        unsafe_allow_html=True
    )

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 🌐 Domain Reputation")
        dr = result.get("domain_reputations", {})
        if not dr:
            st.info("No domains to check.")
        else:
            for domain, rep_info in dr.items():
                rep = rep_info.get("reputation", "Unknown")
                icon = {"Malicious": "🔴", "Suspicious": "🟡", "Clean": "🟢", "Unknown": "⚪"}.get(rep, "⚪")
                badge = rep_badge(rep)
                st.markdown(f"{icon} `{domain}` {badge}", unsafe_allow_html=True)
                details = rep_info.get("details", [])
                for d in details:
                    st.caption(f"  ↳ {d}")

    with col2:
        st.markdown("#### 📡 IP Reputation")
        ir = result.get("ip_reputations", {})
        if not ir:
            st.info("No IPs to check.")
        else:
            for ip, rep_info in ir.items():
                rep = rep_info.get("reputation", "Unknown")
                icon = {"Malicious": "🔴", "Suspicious": "🟡", "Clean": "🟢", "Unknown": "⚪"}.get(rep, "⚪")
                badge = rep_badge(rep)
                st.markdown(f"{icon} `{ip}` {badge}", unsafe_allow_html=True)
                details = rep_info.get("details", [])
                for d in details:
                    st.caption(f"  ↳ {d}")


def render_header_security_section(result: dict):
    section("Email Header Security")
    ha = result.get("header_analysis", {})

    col_auth, col_flags = st.columns([1, 1])

    with col_auth:
        st.markdown("#### Authentication Results")

        def auth_row(protocol: str, status: str):
            icon = get_auth_status_color(status)
            css = auth_color(status)
            st.markdown(
                f"**{protocol}:** <span class='{css}'>{icon} {status.upper()}</span>",
                unsafe_allow_html=True
            )

        auth_row("SPF", ha.get("spf", "none"))
        auth_row("DKIM", ha.get("dkim", "none"))
        auth_row("DMARC", ha.get("dmarc", "none"))

        st.markdown("")
        raw = ha.get("auth_results_raw", "")
        if raw and raw.strip():
            with st.expander("Raw Authentication-Results"):
                st.code(raw.strip(), language=None)

    with col_flags:
        st.markdown("#### Header Flags")
        flags = ha.get("suspicious_header_flags", [])
        if flags:
            for f in flags:
                st.markdown(f"⚠️ {f}")
        else:
            st.success("✅ No suspicious header flags detected")

        received_ips = ha.get("received_ips", [])
        if received_ips:
            st.markdown(f"**IPs in Received headers:** `{', '.join(received_ips)}`")

        hop_count = ha.get("hop_count", 0)
        if hop_count:
            st.markdown(f"**Email hops:** `{hop_count}`")

    st.markdown(
        '<div class="disclaimer-box">ℹ Authentication failures indicate configuration issues or '
        'potential spoofing. They are NOT alone conclusive evidence of malicious intent.</div>',
        unsafe_allow_html=True
    )


def render_final_assessment(result: dict):
    section("Final Threat Assessment")
    risk = result.get("risk", {})

    risk_level = risk.get("risk_level", "UNKNOWN")
    risk_icon = risk.get("risk_icon", "⚪")
    risk_css = risk_color_class(risk_level)
    classification = risk.get("classification", "Unknown")
    prob = risk.get("threat_probability", 0.0)
    score = risk.get("total_score", 0)
    factors = risk.get("risk_factors", [])
    breakdown = risk.get("risk_breakdown", {})

    # Main assessment card
    st.markdown(f"""
<div class="threat-card {risk_css}" style="text-align:left;padding:24px 28px;">
  <p style="font-size:0.8rem;letter-spacing:0.1em;">FINAL ASSESSMENT</p>
  <h2 style="font-size:2.5rem;">{risk_icon} {risk_level}</h2>
  <p style="font-size:1rem;color:#c9d1d9;">Classification: <strong>{classification}</strong> &nbsp;|&nbsp; Probability: <strong>{prob:.0%}</strong> &nbsp;|&nbsp; Risk Score: <strong>{score}/100</strong></p>
</div>""", unsafe_allow_html=True)

    st.markdown("")
    col_factors, col_breakdown = st.columns([3, 2])

    with col_factors:
        st.markdown("**Risk Factors:**")
        if factors:
            for f in factors:
                st.markdown(f"✓ {f}")
        else:
            st.markdown("*No significant risk factors identified.*")

    with col_breakdown:
        st.markdown("**Score Breakdown:**")
        for category, cat_score in sorted(breakdown.items(), key=lambda x: -x[1]):
            if cat_score > 0:
                pct = min(cat_score / 25 * 100, 100)
                color = "#f85149" if cat_score >= 15 else ("#e3b341" if cat_score >= 8 else "#3fb950")
                st.markdown(f"""
<div style="margin:3px 0;">
  <span style="font-size:0.8rem;color:#8b949e;">{category}</span>
  <div style="background:#21262d;border-radius:4px;height:16px;overflow:hidden;">
    <div style="background:{color};width:{pct:.0f}%;height:100%;"></div>
  </div>
  <span style="font-size:0.75rem;color:#8b949e;">{cat_score} pts</span>
</div>""", unsafe_allow_html=True)

    # OpenAI investigation
    st.markdown("---")
    st.markdown("### 🤖 AI Threat Investigation")
    st.markdown(
        '<div class="disclaimer-box">AI analyzes the evidence already extracted by this application. '
        "It cannot determine a sender's exact physical location; IP geolocation is approximate infrastructure location.</div>",
        unsafe_allow_html=True
    )
    if not ai_is_configured():
        st.info("Add OPENAI_API_KEY to your environment or .env file to enable AI investigation.")
    else:
        if st.button("🤖 Analyze with ChatGPT", key="ai_investigate_btn", use_container_width=False):
            with st.spinner("🤖 Generating AI investigation..."):
                st.session_state.ai_investigation = ai_investigate(result)
        ai_result = st.session_state.get("ai_investigation")
        if ai_result:
            if ai_result.get("ok"):
                st.markdown(f"**Model:** `{ai_result.get('model', 'OpenAI')}`")
                st.markdown(ai_result.get("text", ""))
            else:
                st.error(ai_result.get("error", "AI investigation failed."))

    # Export
    st.markdown("---")
    report_text = generate_report(result)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    st.download_button(
        label="📥 Export Report",
        data=report_text,
        file_name=f"threat_report_{ts}.txt",
        mime="text/plain",
        key="export_btn",
        use_container_width=False,
    )

    # Demo mode notice
    if result.get("demo_mode"):
        st.markdown(
            '<div class="warning-box">⚠ This analysis was run in Demo Mode. '
            'Reputation results are prototype/local data. GeoIP data is simulated. '
            'DNS lookups were skipped. Results are for demonstration only.</div>',
            unsafe_allow_html=True
        )

    # Errors
    errors = result.get("errors", [])
    if errors:
        with st.expander(f"⚠️ {len(errors)} Analysis Warning(s)"):
            for e in errors:
                st.warning(e)


# ── Main app ──────────────────────────────────────────────────────────────────
def main():
    init_session_state()
    inject_css()
    render_sidebar()
    render_header()
    render_input_section()
    render_status_banner()

    result = st.session_state.analysis_result
    if result:
        render_executive_summary(result)
        render_email_details(result)
        render_sender_server_section(result)
        render_nlp_section(result)
        render_indicators_section(result)
        render_infrastructure_section(result)
        render_reputation_section(result)
        render_header_security_section(result)
        render_final_assessment(result)


if __name__ == "__main__":
    main()
