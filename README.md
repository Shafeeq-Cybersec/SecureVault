<div align="center">

# 🔐 SecureVault

**Find secrets before attackers do.**

SecureVault scans any public GitHub repository for accidentally committed API keys, tokens, and credentials. Every finding gets a confidence score built from entropy analysis, file-path context, and structural validation — so you know which alerts are real and which are test fixtures.

[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=white)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Vite](https://img.shields.io/badge/Vite-8-646CFF?style=flat-square&logo=vite&logoColor=white)](https://vitejs.dev)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.138-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)

[🚀 Live Demo](https://secure-vault-bay-six.vercel.app) · [🐛 Report Bug](../../issues) · [✨ Request Feature](../../issues)

</div>

---

## Screenshots

> _Add a screenshot of the idle hero page and one of the results view here._

---

## What it detects

| Secret type | Severity | Validated by |
|---|---|---|
| AWS Access Key ID | 🔴 Critical | `AKIA`/`ASIA`/`AROA` prefix + length |
| AWS Secret Access Key | 🟠 High | Length + charset |
| GitHub Personal Access Token | 🟠 High | `ghp_`/`gho_`/`ghu_`/`ghs_` prefix + length |
| GitHub Fine-Grained PAT | 🟠 High | `github_pat_` prefix |
| Google API Key | 🟠 High | `AIza` prefix + length |
| Stripe Secret Key | 🟠 High | `sk_live_`/`sk_test_` prefix + length |
| Stripe Publishable Key | 🟡 Medium | `pk_live_`/`pk_test_` prefix |
| Slack Token | 🟠 High | `xox[bpoa]-` regex |
| Private Key (PEM) | 🔴 Critical | `BEGIN ... PRIVATE KEY` header |
| JWT | 🟡 Medium | Base64 header decoded — must contain `"alg"` |
| Database connection string | 🟠 High | URL with literal password credential |
| Hardcoded API key / password | 🟡 Medium | Keyword + entropy heuristic |

Every finding also carries a **confidence score (1–99 %)** derived from Shannon entropy, variable-name context, file-path context (test fixtures, docs, examples each get a ceiling), and structural format validation. Severity is the impact *if real*; confidence is the likelihood it *is* real — they're tracked separately.

---

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | React 18 · TypeScript · Vite 8 |
| Styling | CSS custom properties (no framework) · Inter + JetBrains Mono |
| Backend | Python 3.12 · FastAPI · Pydantic v2 |
| HTTP client | httpx (async) |
| GitHub API | Git Trees API (recursive, 1 request) + Contents API |
| Deployment | Vercel (frontend) · Railway / Render (backend) |

---

## Getting started

### Prerequisites

- Node.js ≥ 20 and npm
- Python 3.12+

### 1 — Clone

```bash
git clone https://github.com/your-username/securevault.git
cd securevault
```

### 2 — Backend

```bash
cd server

# Create and activate a virtual environment
py -3.12 -m venv .venv          # Windows
python3.12 -m venv .venv        # macOS / Linux

.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux

# Install dependencies
pip install -r requirements-dev.txt

# Start the dev server
uvicorn main:app --reload --port 8000
```

API is live at **http://localhost:8000** — interactive docs at `/docs`.

### 3 — Frontend

```bash
cd client
cp .env.example .env   # or: copy .env.example .env (Windows cmd)
npm install
npm run dev
```

Open **http://localhost:5173**.

### 4 — Optional: GitHub token

Without a token you get 60 unauthenticated API requests per hour (enough for small repos). For large or private repos, create a [fine-grained PAT](https://github.com/settings/tokens?type=beta) with **Contents: read** scope and paste it into the token field in the header.

---

## Deployment

### Frontend → Vercel

1. Push the repo to GitHub.
2. Import the project in [vercel.com](https://vercel.com) — set the **root directory** to `client`.
3. Add an environment variable in the Vercel dashboard:
   ```
   VITE_API_URL = https://your-backend.railway.app
   ```
4. Deploy. `client/vercel.json` handles the SPA rewrite and build config automatically.

### Backend → Railway

1. Create a new project in [railway.app](https://railway.app) from your GitHub repo — set the **root directory** to `server`.
2. Railway detects the `Dockerfile` automatically.
3. Add environment variables in the Railway dashboard:
   ```
   CORS_ORIGINS = https://your-app.vercel.app
   ```
   `PORT` is injected by Railway automatically.
4. Copy the generated Railway domain and paste it into Vercel's `VITE_API_URL`.

### Backend → Render (alternative)

1. New Web Service → connect your repo → set **Root Directory** to `server`.
2. Render detects the `Dockerfile` automatically.
3. Add the same `CORS_ORIGINS` environment variable.
4. The free tier spins down after inactivity — expect a ~30 s cold start on the first request.

---

## Environment variables

### Backend (`server/.env.example`)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8000` | Port the server listens on. Injected automatically by Railway/Render. |
| `CORS_ORIGINS` | `http://localhost:5173,...` | Comma-separated list of allowed frontend origins. Set to your Vercel URL in production. |

### Frontend (`client/.env.example`)

| Variable | Default | Description |
|---|---|---|
| `VITE_API_URL` | `http://localhost:8000` | Base URL of the FastAPI backend. Set to your Railway/Render URL in production via the Vercel dashboard. |

---

## Project structure

```
securevault/
├── client/                   # React + Vite frontend
│   ├── vercel.json           # Vercel deployment config
│   ├── .env.example
│   └── src/
│       ├── api.ts            # fetch wrapper + typed errors
│       ├── types.ts          # Finding, ScanResult, Severity
│       ├── components/       # UI components
│       ├── hooks/            # useChecklist, useCountUp
│       └── lib/              # export, storage, validate
│
└── server/                   # FastAPI backend
    ├── Dockerfile
    ├── requirements.txt      # production deps
    ├── requirements-dev.txt  # + pytest
    ├── .env.example
    ├── main.py
    └── securevault/
        ├── patterns.py       # detection rules
        ├── scoring.py        # multi-signal confidence engine
        ├── scanner.py        # detect → score → redact
        ├── github_client.py  # rate-limit-aware GitHub API client
        └── scan_service.py   # async orchestrator
```

---

## Running tests

```bash
cd server
pip install -r requirements-dev.txt
pytest tests/ -v
```

18 tests covering detection, redaction, confidence scoring, false-positive suppression, and severity/confidence decoupling.

---

## Security notes

- The GitHub token is used only to set an `Authorization: Bearer` header. It is never stored, logged, or returned to the frontend.
- Matched secret values are always redacted before leaving the backend — responses contain only `first6****last4` previews.
- No live credential verification is performed (the scanner does structural validation only, never calls AWS/GitHub/Stripe APIs to check if a key is active).

---

## License

MIT
