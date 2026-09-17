# Email Threat Intelligence & Investigation System

> **Prototype / Demo** — A working end-to-end cybersecurity email investigation tool.
>
> Analyze • Investigate • Correlate • Assess

---

## 1. Project Overview

This prototype simulates a Security Operations Center (SOC) email investigation workflow.
It accepts a raw email (pasted text or `.eml` upload), runs it through an NLP+ML classifier,
extracts technical indicators, performs DNS lookups, checks reputation, approximates IP
geolocation, analyzes email authentication headers, and produces a final risk assessment —
all displayed in a dark cybersecurity-style Streamlit dashboard.

---

## 2. Architecture

```
Email Input (paste / .eml upload)
        ↓
Email Parsing          modules/email_parser.py
        ↓
NLP + TF-IDF           modules/nlp_classifier.py
        ↓
Scikit-learn           LogisticRegression → predict_proba()
        ↓
Indicator Extraction   modules/indicator_extractor.py
  URLs / Domains / IPs / Email addresses
        ↓
Header Analysis        modules/header_analyzer.py
  SPF / DKIM / DMARC / Received IPs
        ↓
DNS Analysis           modules/dns_analyzer.py
  A / AAAA / MX / NS records
        ↓
Reputation Check       modules/reputation.py
  Domain + IP reputation (local prototype list / API)
        ↓
IP Geolocation         modules/geoip.py
  ip-api.com (live) or deterministic demo data
        ↓
Risk Correlation       modules/risk_engine.py
  Weighted multi-signal scoring → LOW / MEDIUM / HIGH / CRITICAL
        ↓
Streamlit Dashboard    app.py
  Executive Summary, Indicators, Infrastructure, Headers, Final Assessment
```

---

## 3. Technologies

| Component | Library |
|---|---|
| Web UI | Streamlit |
| ML | Scikit-learn (LogisticRegression) |
| NLP features | TF-IDF (TfidfVectorizer) |
| Email parsing | Python `email` stdlib |
| DNS | dnspython |
| HTTP / GeoIP | requests |
| Data | pandas |

---

## 4. Project Structure

```
email-threat-intelligence/
├── app.py                    Main Streamlit application
├── requirements.txt
├── README.md
├── data/
│   └── emails.csv            Training dataset (55 labeled emails)
├── models/
│   └── phishing_model.pkl    Auto-generated on first run
├── modules/
│   ├── __init__.py
│   ├── email_parser.py       Header + body extraction
│   ├── nlp_classifier.py     TF-IDF + Logistic Regression
│   ├── indicator_extractor.py URLs / domains / IPs / emails
│   ├── dns_analyzer.py       DNS record lookups
│   ├── reputation.py         Domain + IP reputation
│   ├── geoip.py              IP geolocation
│   ├── header_analyzer.py    SPF / DKIM / DMARC analysis
│   └── risk_engine.py        Multi-signal risk scoring
└── samples/
    ├── phishing.eml          Sample phishing email
    └── benign.eml            Sample benign email
```

---

## 5. Installation

```bash
cd email-threat-intelligence
pip install -r requirements.txt
```

Python 3.9+ recommended.

---

## 6. Running

```bash
streamlit run app.py
```

Open `http://localhost:8501` in your browser.

The ML model trains automatically from `data/emails.csv` on first run and is cached
to `models/phishing_model.pkl`.

---

## 7. ML Workflow

1. `data/emails.csv` contains 55 labeled emails (`text`, `label` — 1=Phishing, 0=Benign).
2. On startup, if `models/phishing_model.pkl` is missing, the model is trained automatically.
3. Pipeline: `TfidfVectorizer(ngram_range=(1,2), max_features=5000)` → `LogisticRegression`.
4. `predict_proba()` returns phishing probability (0–1).
5. Thresholds: ≥ 0.65 = Phishing, ≥ 0.40 = Suspicious, < 0.40 = Benign.
6. Suspicious terms are shown for explainability but do NOT drive the ML decision.
7. Use the **Retrain Model** button in the sidebar to retrain after adding new data.

---

## 8. Indicator Extraction

- **URLs**: Regex extraction + `urllib.parse` analysis. Each URL is scored for:
  HTTP vs HTTPS, IP hostname, URL shortener, length, subdomain count, keyword presence,
  brand impersonation patterns.
- **Domains**: Extracted from URLs and email addresses.
- **IPs**: IPv4 from body and Received headers. Private ranges excluded.
- **Email addresses**: Regex extraction from full email text.

---

## 9. DNS Investigation

Powered by `dnspython`. Retrieves A, AAAA, MX, NS, TXT records per domain.
Failures (NXDOMAIN, timeout, library missing) are caught and displayed gracefully.

DNS lookups are **skipped in Demo Mode** to ensure reliable offline operation.
Toggle Demo Mode OFF in the sidebar to enable live DNS.

---

## 10. Reputation

**Local prototype lists** are used by default. These are clearly labeled:
- `modules/reputation.py` → `KNOWN_BAD_DOMAINS`, `KNOWN_BAD_IPS`, `KNOWN_SUSPICIOUS_DOMAINS`
- These are demonstration fixtures, NOT real threat intelligence.

**External API**: Set `REPUTATION_API_KEY` environment variable to enable integration
with VirusTotal, AbuseIPDB, or similar. Stub functions are ready in `reputation.py`.

---

## 11. IP Geolocation

Uses `ip-api.com` (free tier, no key required) in live mode.
Falls back to deterministic demo data if the API is unavailable or in Demo Mode.

**Important**: Results show `Approximate IP Infrastructure Location`.
The system never claims to identify the attacker's physical location.

---

## 12. Risk Scoring

`modules/risk_engine.py` combines weighted signals:

| Signal | Max Weight |
|---|---|
| ML phishing probability | 25 |
| Domain reputation malicious | 20 |
| IP reputation malicious | 15 |
| SPF/DKIM/DMARC failures | 8 each |
| URL suspicious score | 12 |
| Brand impersonation | 10 |
| IP hostname in URL | 8 |
| Header mismatches | 6 each |
| High-risk TLD | 4 |
| No authentication | 5 |

Thresholds: CRITICAL ≥ 80, HIGH ≥ 55, MEDIUM ≥ 30, LOW < 30.

---

## 13. Demo Mode

**Demo Mode ON** (default):
- GeoIP uses local deterministic data (clearly labeled as prototype)
- DNS lookups skipped
- Reputation uses local lists
- No external API calls

**Demo Mode OFF**:
- Live DNS queries via dnspython
- GeoIP via ip-api.com (free)
- API keys from environment variables if set

Toggle in the sidebar.

---

## 14. API Configuration

Set these environment variables before running for external enrichment:

```bash
# Windows PowerShell
$env:REPUTATION_API_KEY = "your_api_key_here"
$env:GEOIP_API_KEY = "your_api_key_here"

# Linux/macOS
export REPUTATION_API_KEY="your_api_key_here"
export GEOIP_API_KEY="your_api_key_here"
```

API keys are never hard-coded. The application works without them using local/demo data.

---

## 15. Limitations

- **Prototype ML dataset**: 55 emails. Accuracy is demonstrative, not production-grade.
- **ML probability**: Indicative only. Not a guaranteed measure of maliciousness.
- **IP geolocation**: Approximate. Accuracy varies by IP. Not attacker attribution.
- **VPN/Proxy/Tor**: Attackers using anonymization tools will show infrastructure location, not true origin.
- **WHOIS**: Not implemented. GDPR privacy protection often redacts WHOIS data anyway.
- **Reputation lists**: Local demonstration fixtures. Not real threat intelligence.
- **DNS**: Requires `dnspython` installed and network access (live mode only).
- **A suspicious indicator is not proof of malicious intent or attacker attribution.**
- This tool identifies suspicious infrastructure patterns. Investigation and human judgment are required.

---

## 16. Future Improvements

- Integrate VirusTotal / AbuseIPDB / OTX APIs for real reputation data
- Add python-whois for domain registration lookups
- Expand training dataset with public phishing corpora (PhishTank, etc.)
- Add DKIM signature verification
- Add attachment analysis (file type, hash, malware scanning)
- Add URL screenshot / sandbox detonation
- Export to PDF / JSON / STIX
- Add historical analysis and case management
- Integrate threat intelligence feeds (MISP, OpenCTI)
- Add IPv6 support

## OpenAI / ChatGPT Integration (added)

The application now includes an optional **AI Threat Investigation** section. It sends structured evidence extracted by the local pipeline to OpenAI's Responses API and displays a human-readable investigation in Streamlit.

### Setup

1. Create an OpenAI API key.
2. Copy `.env.example` to `.env`.
3. Set `OPENAI_API_KEY` in `.env`.
4. Optionally change `OPENAI_MODEL` (default: `gpt-5.6-luna`).
5. Install dependencies:

```bash
pip install -r requirements.txt
```

6. Start the application:

```bash
streamlit run app.py
```

### IP and location behavior

- The app extracts public IP addresses from `Received` headers.
- The oldest public `Received` IP is shown as an **origin IP candidate** only.
- Live mode performs approximate IP geolocation using ip-api.com.
- Demo mode uses clearly labeled simulated GeoIP data.
- Live GeoIP failures no longer silently fall back to fake locations.
- IP geolocation does **not** provide an exact physical sender location. VPNs, proxies, Tor, cloud hosting, NAT, compromised systems, and forged headers can affect attribution.

### AI safety / privacy note

Only send email data to OpenAI if your organization is authorized to do so and your handling of the email is permitted. The AI report is an interpretation of supplied evidence, not proof of identity or physical location.
