"""Verification script — run once to check all modules work correctly."""
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, ".")

errors = []

def ok(label, detail=""):
    print(f"  [PASS] {label}" + (f" — {detail}" if detail else ""))

def fail(label, err):
    print(f"  [FAIL] {label} — {err}")
    errors.append((label, err))

print("=" * 55)
print("Email Threat Intelligence — Module Verification")
print("=" * 55)
print()

# 1. email_parser
try:
    from modules.email_parser import parse_email
    with open("samples/phishing.eml") as f:
        raw = f.read()
    parsed = parse_email(raw)
    subj = parsed["subject"][:45]
    ok("email_parser (phishing)", f"Subject: {subj}")
except Exception as e:
    fail("email_parser", e)
    parsed = {"body": "", "received_headers": [], "subject": "", "from": "",
              "reply_to": "Not available", "return_path": "Not available",
              "authentication_results": "Not available", "raw_headers": {}, "all_headers": []}

# 2. benign parse
try:
    with open("samples/benign.eml") as f:
        benign_raw = f.read()
    benign_parsed = parse_email(benign_raw)
    ok("email_parser (benign)", f"From: {benign_parsed['from'][:40]}")
except Exception as e:
    fail("email_parser (benign)", e)
    benign_parsed = parsed

# 3. nlp_classifier
try:
    from modules.nlp_classifier import classify_email, get_model
    model = get_model()
    r = classify_email(parsed["body"])
    ok("nlp_classifier (phishing)", f"{r['classification']} @ {r['threat_probability']:.1%}")
    br = classify_email(benign_parsed["body"])
    ok("nlp_classifier (benign)", f"{br['classification']} @ {br['threat_probability']:.1%}")
except Exception as e:
    fail("nlp_classifier", e)
    r = {"classification": "Unknown", "threat_probability": 0.0, "phishing_probability": 0.0,
         "benign_probability": 1.0, "suspicious_terms_found": [], "model_name": "N/A", "error": str(e)}

# 4. indicator_extractor
try:
    from modules.indicator_extractor import extract_all_indicators
    headers_text = " ".join(parsed["received_headers"])
    ind = extract_all_indicators(parsed["body"], headers_text)
    ok("indicator_extractor",
       f"URLs={len(ind['urls'])} Domains={len(ind['domains'])} IPs={len(ind['ips'])}")
except Exception as e:
    fail("indicator_extractor", e)
    ind = {"urls": [], "domains": [], "ips": [], "email_addresses": [],
           "ip_from_headers": [], "summary": {"total": 0}}

# 5. header_analyzer
try:
    from modules.header_analyzer import analyze_headers, resolve_reverse_dns
    ha = analyze_headers(parsed, demo_mode=True)
    assert ha.get("origin_server_ip"), "Missing origin_server_ip"
    assert ha.get("origin_client_ip") == "185.220.101.1", f"Expected client IP 185.220.101.1, got {ha.get('origin_client_ip')}"
    assert len(ha.get("hops", [])) == 2, f"Expected 2 hops, got {len(ha.get('hops', []))}"
    rdns_sample = resolve_reverse_dns("8.8.8.8", demo_mode=True)
    ok("header_analyzer (origin tracking)",
       f"OriginServer={ha['origin_server_ip']} Hostname={ha['origin_server_hostname'][:25]} ClientIP={ha['origin_client_ip']} Hops={len(ha['hops'])}")
except Exception as e:
    fail("header_analyzer", e)
    ha = {"spf": "none", "dkim": "none", "dmarc": "none", "received_ips": [],
          "hop_count": 0, "from_reply_to_mismatch": False, "from_return_path_mismatch": False,
          "suspicious_header_flags": [], "auth_results_raw": "", "hops": []}

# 6. dns_analyzer
try:
    from modules.dns_analyzer import analyze_domain
    # Test with a known-resolvable domain (won't crash if offline)
    res = analyze_domain("example.com")
    ok("dns_analyzer", f"example.com -> {res['status']}")
except Exception as e:
    fail("dns_analyzer", e)

# 7. reputation
try:
    from modules.reputation import check_multiple_domains, check_multiple_ips
    dr = check_multiple_domains(ind["domains"][:3])
    ir = check_multiple_ips(ind["ips"][:3])
    top = list(dr.values())[0]["reputation"] if dr else "N/A"
    ok("reputation", f"Domain rep sample: {top}")
except Exception as e:
    fail("reputation", e)
    dr, ir = {}, {}

# 8. geoip (demo mode only)
try:
    from modules.geoip import geolocate_ip
    test_ip = ind["ips"][0] if ind["ips"] else "185.220.101.1"
    geo = geolocate_ip(test_ip, demo_mode=True)
    ok("geoip (demo)", f"{test_ip} -> {geo['city']}, {geo['country']}")
    geo_results = {geo["ip"]: geo}
except Exception as e:
    fail("geoip", e)
    geo_results = {}

# 9. risk_engine
try:
    from modules.risk_engine import correlate_risk
    risk = correlate_risk(r, ind, {}, dr, ir, ha, geo_results)
    ok("risk_engine", f"{risk['risk_icon']} {risk['risk_level']} (score={risk['total_score']})")
    print()
    print("  Risk factors found:")
    for f in risk["risk_factors"][:5]:
        print(f"    - {f}")
except Exception as e:
    fail("risk_engine", e)

# 10. Empty email edge case
try:
    from modules.email_parser import parse_email as pe
    empty = pe("")
    empty_nlp = classify_email("")
    ok("edge case: empty email", f"classify={empty_nlp['classification']}")
except Exception as e:
    fail("edge case: empty email", e)

# Summary
print()
print("=" * 55)
if errors:
    print(f"RESULT: {len(errors)} FAILURE(S):")
    for lbl, err in errors:
        print(f"  - {lbl}: {err}")
    sys.exit(1)
else:
    print("RESULT: ALL CHECKS PASSED")
    print("Run:  streamlit run app.py")
print("=" * 55)
