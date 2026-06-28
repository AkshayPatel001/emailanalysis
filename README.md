# 🛡️ Email Analysis Tool

Professional-grade email analysis utility for SOC analysts. Analyze suspicious emails, detect phishing attempts, extract IOCs, map to MITRE ATT&CK, and generate investigation reports.

## Features

- **Email Parsing** — Upload `.eml`, `.msg` files or paste raw headers
- **Header Analysis** — SPF/DKIM/DMARC verification, sender spoofing detection
- **Phishing Detection** — Urgency language, credential harvesting, BEC, brand impersonation
- **URL Analysis** — Suspicious TLDs, shorteners, punycode, typosquatting detection
- **Attachment Analysis** — Hash computation, executable/macro/script detection
- **IOC Extraction** — IPs, domains, URLs, hashes, emails with defanging
- **Risk Scoring** — Weighted 0-100 risk score with Clean/Suspicious/Malicious verdict
- **MITRE ATT&CK Mapping** — Auto-maps findings to ATT&CK techniques
- **Threat Intelligence** — VirusTotal, AbuseIPDB, AlienVault OTX, URLScan.io, Google Safe Browsing
- **Report Generation** — PDF, JSON, CSV export
- **Case Management** — Status tracking, analyst notes, severity classification

## Quick Start

### 1. Clone and configure

```bash
cp .env.example .env
# Edit .env with your database password and optional API keys
```

### 2. Start with Docker Compose

```bash
docker-compose up --build
```

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000/api/docs
- **Database**: PostgreSQL on port 5432

### 3. Local Development (without Docker)

**Backend:**
```bash
cd backend
pip install -r requirements.txt
# Start PostgreSQL separately, update DATABASE_URL in .env
uvicorn app.main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

### 4. Run Tests

```bash
cd backend
python3 -m pytest tests/ -v
```

## Architecture

| Layer | Technology |
|-------|-----------|
| Frontend | React 19 + Tailwind CSS v4 + Vite |
| Backend | Python FastAPI |
| Database | PostgreSQL 16 |
| Deployment | Docker Compose |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/analyze/upload` | Upload .eml/.msg file |
| POST | `/api/analyze/headers` | Analyze raw headers |
| GET | `/api/analyze/{case_id}` | Get analysis result |
| GET | `/api/cases` | List all cases |
| PATCH | `/api/cases/{case_id}` | Update case |
| POST | `/api/reports/generate` | Generate report |
| POST | `/api/ioc/check` | Check IOC against APIs |
| GET | `/api/ioc/export/{case_id}` | Export IOCs |
| GET | `/api/settings` | Get settings |
| PATCH | `/api/settings` | Update settings |

## API Keys (Optional)

Add to `.env` to enable threat intelligence enrichment:

- `VIRUSTOTAL_API_KEY` — File/URL/IP reputation
- `ABUSEIPDB_API_KEY` — IP abuse reports
- `ALIENVAULT_OTX_API_KEY` — Threat indicator pulses
- `URLSCAN_API_KEY` — URL scanning
- `GOOGLE_SAFEBROWSING_API_KEY` — URL threat matching

## License

Personal SOC tool.