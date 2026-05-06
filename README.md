# Google-Web-Scan Extension

A WHOIS-based website safety scanner built as a Chrome Extension with a local Python backend. It scans the domain of your currently active tab, performs a WHOIS lookup, analyses the result, and returns a clear safety classification, a 0–100 risk score, and a readable WHOIS summary.

---

## Features

- **One-click scanning** — press *Run WHOIS Scan* from any tab
- **Three-tier classification** — `safe`, `suspicious`, or `unsafe`
- **0–100 risk score** with an animated progress bar
- **Detailed reasoning** — every point added to the score is explained
- **WHOIS summary** — creation date, expiry date, last updated, and registrar
- **Conservative scoring** — when in doubt, scores higher to protect users
- **Graceful error handling** — privacy-protected or unknown WHOIS records are flagged as inconclusive rather than crashing

---

## Folder Structure

```
google-web-scan/
│
├── backend/
│   ├── app.py               # Flask API server (entry point)
│   ├── whois_scanner.py     # WHOIS lookup + URL parsing
│   ├── scorer.py            # Risk scoring engine
│   ├── requirements.txt     # Python dependencies
│   └── tests/
│       └── test_scorer.py   # 15 unit tests for the scoring engine
│
├── extension/
│   ├── manifest.json        # Chrome Extension Manifest V3
│   ├── popup.html           # Extension popup UI
│   ├── popup.js             # UI logic + backend communication
│   ├── styles.css           # Dark terminal aesthetic styling
│   └── icons/
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
│
└── README.md
```

---

## Setup Instructions

### Prerequisites

- Python 3.10 or higher
- Google Chrome browser
- A working internet connection (for WHOIS lookups)

---

### 1. Set Up the Python Backend

```bash
# Navigate to the backend folder
cd google-web-scan/backend

# (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate        # macOS / Linux
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt
```

---

### 2. Run the Backend Server

```bash
python app.py
```

You should see:

```
=======================================================
  Google-Web-Scan backend running on port 5000
  Press Ctrl+C to stop.
=======================================================
```

 **Keep this terminal open while using the extension.** The extension cannot work without the backend running.

---

### 3. Load the Chrome Extension

1. Open Chrome and go to `chrome://extensions`
2. Enable **Developer mode** (toggle in the top-right corner)
3. Click **Load unpacked**
4. Select the `google-web-scan/extension` folder
5. The extension icon will appear in your Chrome toolbar

---

### 4. Run a Scan

1. Navigate to any website (e.g., `https://github.com`)
2. Click the **Google-Web-Scan** extension icon
3. Click **Run WHOIS Scan**
4. Results appear within a few seconds

---

## Running Tests

```bash
cd google-web-scan/backend
python -m pytest tests/test_scorer.py -v
```

The test suite covers 15 scenarios including safe domains, suspicious domains, unsafe domains, and edge cases (missing fields, list-typed dates, score capping).

---

## How the Risk Score Works

The score runs from **0 (no risk)** to **100 (maximum risk)**. The scoring is **conservative** — ambiguous or missing information adds risk rather than being ignored.

### Scoring Factors

| Factor | Max Points | Notes |
|---|---|---|
| Missing WHOIS fields | +10 each (max 30) | Creation date, expiry date, or registrar absent |
| Domain age | +35 | Domains under 30 days old score maximum |
| Days until expiry | +20 | Expired or expiring within 30 days |
| Registration length | +15 | Under 1 year total registered period |
| Unknown registrar | +10 | Not on the known-trusted registrar list |
| High-risk TLD | +10 | `.tk`, `.xyz`, `.top`, `.click`, etc. |
| Few name servers | +5 | Zero or only one name server |

### Classification Thresholds

| Score Range | Classification |
|---|---|
| 0 – 15 | Safe |
| 16 – 45 | Suspicious |
| 46 – 100 | Unsafe |

### Example Results

| Domain | Expected Score | Classification |
|---|---|---|
| `github.com` (est. 2007, MarkMonitor) | ~5 | Safe |
| `google.com` (est. 1997, MarkMonitor) | ~0 | Safe |
| `somedomain.xyz` (< 6 months old) | ~50–65 | Unsafe |
| `sketchy-login.tk` (< 30 days old) | ~70–85 | Unsafe |

---

## Limitations of WHOIS-Based Scanning

WHOIS data is a useful starting signal, but it has real limitations you should be aware of:

1. **WHOIS privacy services** — Many legitimate registrars (and all bad actors) use privacy protection that redacts contact info and sometimes dates. A privacy-shielded domain is treated as *inconclusive*, not automatically dangerous.

2. **Not real-time threat intelligence** — WHOIS tells you about registration details, not whether a site currently hosts malware or is on a blocklist. A years-old domain can be compromised.

3. **New legitimate domains** — Startups and new projects register fresh domains every day. A new domain isn't *proof* of malice — it's a risk signal, not a verdict.

4. **WHOIS data accuracy** — Registrant-supplied data is not always verified. A malicious actor can register with false info.

5. **Rate limiting** — WHOIS servers rate-limit repeated queries. Scanning many domains quickly may result in lookup failures.

6. **TLD coverage** — Some country-code TLDs (ccTLDs) don't expose full WHOIS data or use different formats that `python-whois` may not fully parse.

7. **No content analysis** — This tool does not visit the page, analyse JavaScript, check SSL certificates, or scan for phishing content. Use it alongside (not instead of) other security tools.

**This tool is intended as a supplementary research aid, not a definitive security verdict.**

---

## Tech Stack

| Component | Technology |
|---|---|
| Extension frontend | Vanilla HTML / CSS / JavaScript, Chrome Manifest V3 |
| Backend | Python 3, Flask, flask-cors |
| WHOIS lookups | `python-whois` library |
| Testing | `pytest` |

---

## License

MIT License — free to use, modify, and distribute.
