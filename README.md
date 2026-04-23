# ThreatChain

**Automated SOC Level 1 investigation pipeline built with LangChain + LangGraph.**

Submit an IOC (IP, domain, hash, URL, or CVE) and ThreatChain orchestrates 7 specialized AI agents that query 17+ threat intelligence APIs, correlate findings with MITRE ATT&CK via RAG, and generate a professional investigation report with verdict and recommendations — in 15-30 seconds.

---

## Architecture

```
User submits IOC
      |
      v
 COORDINATOR (GPT-4o / LangGraph)
      |
  asyncio.gather
 /    |    |    |    \
RECON MALWARE VULN OSINT MITRE
(Grok)(Grok)(Gemini)(Gemini)(RAG)
      |
 Correlation Engine
      |
 REPORT AGENT (Claude Sonnet)
      |
 Markdown / PDF / STIX 2.1
```

**IOC routing:**
- IP / Domain -> RECON + OSINT + MITRE
- Hash -> MALWARE + MITRE
- URL -> RECON + MALWARE + OSINT
- CVE -> VULN + MITRE

---

## Stack

| Layer | Technology |
|---|---|
| AI Framework | LangChain 0.3.x + LangGraph 0.2.x |
| Backend | FastAPI (async) |
| Database | PostgreSQL via psycopg v3 |
| Vector Store | ChromaDB (local) |
| Embeddings | OpenAI text-embedding-3-small |
| Cache | Redis |
| LLMs | GPT-4o, Claude Sonnet, Grok, Gemini, Groq |
| UI | Streamlit |

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/cc22n/threatchain
cd ThreatChain
cp .env.example .env
# Edit .env with your API keys
```

### 2. Run with Docker Compose

```bash
docker compose up -d
```

API available at `http://localhost:8000`
UI available at `http://localhost:8501`

### 3. Index MITRE ATT&CK (one-time setup)

Download the STIX bundle from:
```
https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json
```
Save to `knowledge_base/mitre/enterprise-attack.json`, then:

```bash
docker compose exec api python -c "from app.rag.loaders.mitre_loader import load_mitre_index; load_mitre_index()"
```

---

## Authentication

Mutation endpoints (`POST /investigate`, `POST /investigate/batch`, `POST /report/regenerate`, `DELETE`) require an `X-API-Key` header when `API_KEY` is set in `.env`.

```bash
curl -X POST http://localhost:8000/api/v1/investigate \
  -H "X-API-Key: your-key-here" \
  -H "Content-Type: application/json" \
  -d '{"ioc_value": "8.8.8.8"}'
```

Leave `API_KEY` empty to disable auth in local/dev mode.

---

## Local Development

```bash
conda create -n ThreatChain python=3.11
conda activate ThreatChain
pip install -r requirements.txt

# Start PostgreSQL and Redis (or use Docker)
alembic upgrade head

uvicorn app.main:app --reload        # API on :8000
streamlit run ui/app.py              # UI on :8501
```

---

## API Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/investigate` | Required | Start investigation |
| POST | `/api/v1/investigate/batch` | Required | Batch (up to 20 IOCs) |
| GET | `/api/v1/investigations` | - | List investigations |
| GET | `/api/v1/investigations/{id}` | - | Investigation detail |
| GET | `/api/v1/investigations/{id}/results` | - | Per-agent results |
| GET | `/api/v1/investigations/{id}/mitre` | - | MITRE mappings |
| GET | `/api/v1/investigations/{id}/report` | - | Generated report |
| GET | `/api/v1/investigations/{id}/report/download?format=md\|pdf\|stix` | - | Download report |
| POST | `/api/v1/investigations/{id}/report/regenerate` | Required | Regenerate report |
| DELETE | `/api/v1/investigations/{id}` | Required | Soft-delete investigation |
| GET | `/api/v1/health/apis` | - | API rate limit status |
| GET | `/api/v1/health/llms` | - | LLM provider status |
| GET | `/api/v1/stats` | - | Global statistics |
| WS | `/ws/investigation/{id}` | - | Real-time progress |

Full Swagger docs: `http://localhost:8000/docs`

---

## Threat Intelligence APIs (17 Tools)

| # | API | Coverage | Agent |
|---|---|---|---|
| 1 | VirusTotal | IP, Domain, Hash, URL | RECON, MALWARE |
| 2 | AbuseIPDB | IP | RECON |
| 3 | Shodan | IP, Domain | RECON |
| 4 | AlienVault OTX | All types | OSINT, MALWARE |
| 5 | URLScan.io | URL, Domain | RECON |
| 6 | NVD (NIST) | CVE | VULN |
| 7 | CISA KEV | CVE | VULN |
| 8 | MalwareBazaar | Hash | MALWARE |
| 9 | Hybrid Analysis | Hash, URL | MALWARE |
| 10 | GreyNoise | IP | OSINT |
| 11 | Pulsedive | IP, Domain, URL | OSINT |
| 12 | ThreatFox | IP, Domain, Hash | RECON |
| 13 | PhishTank | URL, Domain | OSINT |
| 14 | SecurityTrails | Domain | RECON |
| 15 | ExploitDB | CVE | VULN |
| 16 | ThreatCrowd | IP, Domain, Hash | OSINT |
| 17 | HaveIBeenPwned | Email, Domain | OSINT |
| 18 | MITRE ATT&CK | Techniques (RAG) | MITRE |

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Environment Variables

See `.env.example` for the full list. Required keys:

```
DATABASE_URL=postgresql+psycopg://...
REDIS_URL=redis://localhost:6379/0
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
XAI_API_KEY=
GEMINI_API_KEY=
GROQ_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
API_KEY=                    # Optional: enables X-API-Key auth on mutations
```

---

## Project Structure

```
app/
  agents/       # 7 LangChain agents
  tools/        # 17 threat intel API wrappers
  chains/       # IOC classifier, severity scorer, MITRE lookup, report chain
  rag/          # ChromaDB + MITRE ATT&CK STIX loader
  llm/          # Multi-LLM router + fallback
  services/     # Cache, rate limiter, investigation orchestration, export
  api/          # FastAPI routers + auth dependency
  models/       # SQLAlchemy models (indexed FKs)
  utils.py      # Shared helpers (LLM JSON parser)
ui/             # Streamlit frontend
tests/          # pytest test suite
knowledge_base/ # MITRE ATT&CK STIX bundle + playbooks
alembic/        # Database migrations
```

---

## Security Notes

- `X-API-Key` authentication on all mutation endpoints (configurable)
- STIX 2.1 export sanitizes IOC values to prevent pattern injection
- Rate limiting enforced per-API via database counters
- Redis cache with 24h TTL reduces external API exposure
- Soft-delete preserves investigation audit trail
- No API keys in source code; all secrets via environment variables

---

## Portfolio Context

Built to demonstrate:
- **LangChain mastery**: agents, tools, chains, RAG, multi-LLM routing
- **Multi-agent orchestration**: LangGraph StateGraph, parallel execution with asyncio
- **Production patterns**: async FastAPI, psycopg v3, Redis cache, Alembic migrations
- **Cybersecurity domain**: MITRE ATT&CK, STIX 2.1, 17 real threat intel APIs
- **Clean architecture**: base classes, dependency injection, partial failure handling
- **Security hardening**: API key auth, injection prevention, rate limiting, soft-delete

---

*Built with LangChain + FastAPI + PostgreSQL + ChromaDB*
