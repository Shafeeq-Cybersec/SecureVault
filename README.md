<div align="center">

# 🔐 SecureVault

**Find secrets before attackers do.**

SecureVault scans any public GitHub repository for accidentally committed API keys, tokens, and credentials. Every finding gets a confidence score built from entropy analysis, file-path context, and structural validation, so you know which alerts are real and which are test fixtures.

[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=white)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Vite](https://img.shields.io/badge/Vite-8-646CFF?style=flat-square&logo=vite&logoColor=white)](https://vitejs.dev)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.138-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)

[🚀 Live Demo](https://securevault-scanner.vercel.app) · [🐛 Report Bug](../../issues) · [✨ Request Feature](../../issues)

</div>

---

## Screenshots

> _Add a screenshot of the idle hero page and one of the results view here._

---

## What it detects

| Secret type | Severity | Validated by |
|---|---|---|
| **AI / ML** | | |
| OpenAI API Key | 🔴 Critical | `sk-` prefix + `T3BlbkFJ` structural marker |
| Anthropic API Key | 🔴 Critical | `sk-ant-` prefix |
| Hugging Face Token | 🟠 High | `hf_` prefix + length |
| Replicate API Token | 🟠 High | `r8_` prefix + exact length |
| **Cloud** | | |
| AWS Access Key ID | 🔴 Critical | `AKIA`/`ASIA`/`AROA` prefix + length |
| AWS Secret Access Key | 🔴 Critical | Context keyword + length + charset |
| DigitalOcean PAT | 🔴 Critical | `dop_v1_` prefix + 64 hex chars |
| Google API Key | 🟠 High | `AIza` prefix + length |
| **Communication / SaaS** | | |
| SendGrid API Key | 🟠 High | `SG.` prefix + two-segment format |
| Slack Token | 🟠 High | `xox[bpoa]-` prefix |
| Twilio Account SID | 🟠 High | `AC` prefix + 32 hex chars |
| Discord Bot Token | 🟠 High | Context keyword + three-part token format |
| Mailchimp API Key | 🟡 Medium | 32 hex chars + `-us\d` datacenter suffix |
| **DevOps / Registries** | | |
| GitHub Personal Access Token | 🔴 Critical | `ghp_`/`gho_`/`ghu_`/`ghs_` prefix |
| GitHub Fine-Grained PAT | 🔴 Critical | `github_pat_` prefix |
| GitLab Personal Access Token | 🔴 Critical | `glpat-` prefix + exact length |
| npm Access Token | 🔴 Critical | `npm_` prefix + exact length |
| PyPI API Token | 🔴 Critical | `pypi-` prefix + length |
| **Payments / E-commerce** | | |
| Stripe Secret Key (live) | 🔴 Critical | `sk_live_` prefix + length |
| Stripe Publishable Key (live) | 🟡 Medium | `pk_live_` prefix |
| Razorpay Live API Key | 🔴 Critical | `rzp_live_` prefix + exact length |
| Square API Key / OAuth Token | 🟠 High | `sq0atp-`/`sq0csp-`/`EAAAl` prefix |
| Shopify Access Token | 🟠 High | `shppa_`/`shpss_`/`shpca_`/`shpat_` + 32 hex |
| **Infrastructure** | | |
| Private Key (PEM) | 🔴 Critical | `BEGIN ... PRIVATE KEY` header |
| JWT | 🟡 Medium | Base64 header decoded (must contain `"alg"`) |
| Database connection string | 🟠 High | URL with literal password credential |
| Hardcoded API key / password | 🟡 Medium | Keyword + entropy heuristic |

Every finding also carries a **confidence score (1-99%)** derived from Shannon entropy, variable-name context, file-path context (test fixtures, docs, examples each get a ceiling), and structural format validation. Severity is the impact *if real*; confidence is the likelihood it *is* real. Both are tracked separately.

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

### 1. Clone

```bash
git clone https://github.com/your-username/securevault.git
cd securevault
```

### 2. Backend

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

API is live at **http://localhost:8000**. Interactive docs at `/docs`.

### 3. Frontend

```bash
cd client
cp .env.example .env   # or: copy .env.example .env (Windows cmd)
npm install
npm run dev
```

Open **http://localhost:5173**.

### 4. Optional: GitHub token

Without a token you get 60 unauthenticated API requests per hour (enough for small repos). For large or private repos, create a [fine-grained PAT](https://github.com/settings/tokens?type=beta) with **Contents: read** scope and paste it into the token field in the header.

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
- Matched secret values are always redacted before leaving the backend. Responses contain only `first6****last4` previews.
- No live credential verification is performed (the scanner does structural validation only, never calls AWS/GitHub/Stripe APIs to check if a key is active).

---

## License

MIT
