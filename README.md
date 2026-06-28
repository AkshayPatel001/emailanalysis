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

## **IMAGES**
-DASHBOARD
<img width="2549" height="1377" alt="Screenshot From 2026-06-28 01-46-00" src="https://github.com/user-attachments/assets/e4f46605-56c6-470e-af0d-2cc076203c65" />

-UPLOAD EMAIL
<img width="2549" height="1377" alt="Screenshot From 2026-06-28 01-46-12" src="https://github.com/user-attachments/assets/f535e434-d8e0-4676-83ba-2fbe4856bdc7" />

-CASES/PREVIOUS SCANS
<img width="2549" height="1377" alt="Screenshot From 2026-06-28 01-46-14" src="https://github.com/user-attachments/assets/9a2dceb1-9aae-40b8-b777-4d20e5639d02" />

-SETTINGS
<img width="2549" height="1377" alt="Screenshot From 2026-06-28 01-46-28" src="https://github.com/user-attachments/assets/89df7b6f-778e-4ed2-97ba-d475b3e20563" />
<img width="2549" height="1377" alt="Screenshot From 2026-06-28 01-46-32" src="https://github.com/user-attachments/assets/afbf2c16-2de6-4217-b471-12b445e5b72f" />


-EMAIL SCAN RESULT
  -Summary (Gives you summary of email)
  <img width="2549" height="1377" alt="Screenshot From 2026-06-28 01-46-40" src="https://github.com/user-attachments/assets/a77ffbf9-8a9c-4d12-bdd4-40a7797468cc" />

  -Headers (Header info of email)
  <img width="2557" height="1386" alt="Screenshot From 2026-06-28 01-46-49" src="https://github.com/user-attachments/assets/542f8a78-e754-4a7d-a49b-1802f6e4a6ec" />

  -Phishing 
  <img width="2557" height="1386" alt="Screenshot From 2026-06-28 01-46-54" src="https://github.com/user-attachments/assets/96ca4859-f291-4490-9666-85df05916c1a" />

  -URLS
  <img width="2557" height="1386" alt="Screenshot From 2026-06-28 01-46-57" src="https://github.com/user-attachments/assets/49840b4b-548c-47d2-ba34-539fbe4e81dc" />

  -Attachments
<img width="2557" height="1386" alt="Screenshot From 2026-06-28 01-47-04" src="https://github.com/user-attachments/assets/69f00b1c-3e7b-4fee-a8b8-1d7866718555" />

  -YARA Rules
  <img width="2557" height="1386" alt="Screenshot From 2026-06-28 01-47-06" src="https://github.com/user-attachments/assets/6ea4a61c-6633-4269-b11c-2f46e7ba317a" />

  -IOCs
  <img width="2557" height="1386" alt="Screenshot From 2026-06-28 01-47-10" src="https://github.com/user-attachments/assets/74f368e7-51a4-4607-8f94-014fb6079f38" />

  -MITRE
  <img width="2557" height="1386" alt="Screenshot From 2026-06-28 01-47-13" src="https://github.com/user-attachments/assets/82f40a98-ddd5-4f72-8af0-e33bbc69e146" />

  -ACTIONS (Currently supports M365 Purge Email, which will delete this from MS)
 <img width="2558" height="1386" alt="Screenshot From 2026-06-28 01-47-24" src="https://github.com/user-attachments/assets/e1271c3f-85ca-4236-a81a-7919bfbd6485" />
 

