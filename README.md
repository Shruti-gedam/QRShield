# 🛡 QRShield

**Context-Aware Framework for QR-Based Payment Fraud and Deception Detection**

Rule-based heuristic analysis — no ML, fully transparent decisions.

---

## Features

| Module | What it checks |
|---|---|
| **QR Decoder** | pyzbar (primary) + OpenCV adaptive-threshold fallback |
| **Payload Parser** | UPI, HTTPS, deep-links, vCard, WiFi, Geo, plain text |
| **URL Analyzer** | Scheme, homoglyphs, punycode, brand spoofing, redirect chain, DNS, Safe Browsing/VT (optional) |
| **Context Engine** | Temporal (late-night IST), Geo (high-risk countries), Device (headless UA), Network (public Wi-Fi), Velocity |
| **Risk Engine** | Aggregates all signals → score 0–100 → SAFE / SUSPICIOUS / HIGH_RISK / CRITICAL |

---

## Quick Start

```bash
# 1. Clone / enter project
cd qrshield

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy env file (edit API keys if needed)
copy .env.example .env

# 4. Run
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Open **http://localhost:8000** for the web UI.  
API docs at **http://localhost:8000/docs**.

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/scan/upload` | Multipart image upload |
| `POST` | `/api/scan/base64` | Base64 image in JSON body |
| `POST` | `/api/scan/payload` | Pre-decoded QR string |
| `GET`  | `/api/health` | Dependency health check |
| `GET`  | `/api/info` | Framework metadata |

### Example — analyse a UPI payload

```bash
curl -X POST http://localhost:8000/api/scan/payload \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "upi://pay?pa=merchant@okicici&pn=Shop&am=150&cu=INR",
    "context": { "country_code": "IN", "device_type": "mobile" }
  }'
```

### Example — upload a QR image

```bash
curl -X POST http://localhost:8000/api/scan/upload \
  -F "file=@qr_code.png" \
  -F 'context_json={"country_code":"IN","is_wifi":true,"wifi_ssid":"Airport Free"}'
```

---

## Risk Score Bands

| Score | Verdict | Meaning |
|---|---|---|
| 0 – 29 | ✅ SAFE | No significant signals |
| 30 – 59 | ⚠️ SUSPICIOUS | Review before paying |
| 60 – 79 | 🚨 HIGH RISK | Strong fraud indicators — verify carefully |
| 80 – 100 | 🛑 CRITICAL | Do not proceed |

Thresholds are configurable via `.env`:
```
RISK_THRESHOLD_LOW=30
RISK_THRESHOLD_MEDIUM=60
RISK_THRESHOLD_HIGH=80
```

---

## Optional API Keys

Add to `.env` for enhanced detection:

```
SAFE_BROWSING_API_KEY=<Google Safe Browsing v4 key>
VIRUSTOTAL_API_KEY=<VirusTotal v3 key>
```

Without keys the framework still runs all local heuristic checks.

---

## Project Structure

```
qrshield/
├── app/
│   ├── main.py               # FastAPI app factory
│   ├── config.py             # Settings (pydantic-settings)
│   ├── api/
│   │   ├── routes.py         # REST endpoints
│   │   └── schemas.py        # Pydantic request/response models
│   └── core/
│       ├── pipeline.py       # Async orchestrator
│       ├── qr_decoder.py     # Image → payload
│       ├── payload_parser.py # Format-specific parsers
│       ├── url_analyzer.py   # URL heuristics + redirect chain
│       ├── context_engine.py # Temporal/geo/device/network/velocity
│       └── risk_engine.py    # Score aggregation + verdict
├── static/
│   ├── css/style.css
│   └── js/app.js
├── templates/
│   └── index.html
├── smoke_test.py             # End-to-end pipeline test
├── requirements.txt
└── .env.example
```
