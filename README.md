# ThreatChain

**Automated SOC Level 1 investigation pipeline built with LangChain + LangGraph.**

Submit an IOC (IP, domain, hash, URL, or CVE) and ThreatChain orchestrates 7 specialized AI agents that query 17+ threat intelligence APIs, correlate findings with MITRE ATT&CK via RAG, and generate a professional investigation report with verdict and recommendations — in 15-30 seconds.

---

## Architecture

```
User submits IOC (chat, HTTP, or Telegram)
      |
      v
 COORDINATOR (DeepSeek Reasoner / LangGraph)
      |
  asyncio.gather
 /    |    |    |    \
RECON MALWARE VULN OSINT MITRE
(DeepSeek Chat, all four)      (RAG)
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
| LLMs | DeepSeek (primary), Claude Sonnet, GPT-4o (fallback), Gemini, Groq |
| UI | Streamlit |
| Bot | python-telegram-bot (private, allowlist-gated) |

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
Telegram bot starts automatically if `TELEGRAM_BOT_TOKEN` is set in `.env` (see [Telegram Bot](#telegram-bot) below) — it's a private, allowlist-only bot with no exposed port.

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

python -m app.main                   # API on :8000
streamlit run ui/app.py              # UI on :8501
```

> **Note:** start the API with `python -m app.main`, not the `uvicorn` CLI.
> On Windows the uvicorn CLI forces the ProactorEventLoop, which psycopg
> async cannot use; the module entry point installs the Selector loop first.

---

## API Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/investigate` | Required | Start investigation |
| POST | `/api/v1/investigate/batch` | Required | Batch (up to 20 IOCs) |
| GET | `/api/v1/investigations` | - | List investigations (optional `?ioc_value=` filter) |
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

### Async mode and real-time progress

By default `POST /investigate` returns the investigation id immediately
(status `pending`, `"wait": false` is the default) so a caller behind a
proxy timeout never blocks for the full 15-120s pipeline. Pass
`"wait": true` if you specifically want a synchronous call that returns
the finished result directly — only safe for direct scripting against a
backend with no request timeout in front of it.

```bash
curl -X POST http://localhost:8000/api/v1/investigate \
  -H "Content-Type: application/json" \
  -d '{"ioc_value": "8.8.8.8"}'
# -> {"id": "<uuid>", "status": "pending", ...}
```

`WS /ws/investigation/{id}` then streams JSON events: `snapshot` (state on
connect), `investigation_started`, one `agent_completed` per agent (with
`agent_status`), `report_generated`, and a final `investigation_finished`
with verdict, severity and score. The Streamlit UI uses this flow to show
live per-agent progress.

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
| 16 | ThreatCrowd | IP, Domain, Hash | Retired (service offline) |
| 17 | HaveIBeenPwned | Email, Domain | OSINT |
| 18 | MITRE ATT&CK | Techniques (RAG) | MITRE |

---

## Telegram Bot

A private Telegram bot (`app/bot/telegram_bot.py`) wraps the API so investigations can be run from a phone. It's a thin HTTP/WebSocket client — no direct database or agent access — built on `python-telegram-bot`, reusing the same `POST /investigate` + `WS /ws/investigation/{id}` flow as the Streamlit UI.

**Commands:**

| Command | Description |
|---|---|
| `/investigar <IOC>` | Start an investigation (or send the IOC with no command) |
| `/estado <id>` | Check progress/result on demand |
| `/reporte <id>` | Full markdown report, sent in-chat |
| `/metricas` | Global stats (`GET /api/v1/stats`) |
| `/ayuda` | Usage examples |

**Live progress:** the initial message is edited in place as each agent finishes (`[OK] recon`, `[OK] osint`, ...), then replaced with the final verdict — no chat spam.

**Why private (allowlist), not public:**
- Every investigation burns LLM tokens and calls against the 17 external APIs' shared daily quotas — an open bot is an open invitation to drain both.
- For a portfolio piece, a controlled demo (GIF/video, or a recruiter's `chat_id` added temporarily) is safer and just as effective as a public link, without the abuse surface.
- `TELEGRAM_ALLOWLIST` is a plain comma-separated list of Telegram `chat_id`s in `.env`; an empty list means the bot accepts nobody. Get your own `chat_id` from `@userinfobot`.

**Per-user protections**, independent of the per-API rate limiter in `app/services/rate_limiter.py`:
- Daily cap per Telegram user (`TELEGRAM_RATE_LIMIT_PER_DAY`, default 20), in-memory in the bot process.
- Duplicate-investigation dedup: re-asking about the same IOC within 10 minutes reuses the in-flight or just-finished investigation instead of re-running the full 7-agent pipeline.

**Run it:**

```bash
# Local
python -m app.bot.telegram_bot

# Docker Compose (starts automatically alongside api/ui if TELEGRAM_BOT_TOKEN is set)
docker compose up -d bot
```

> Demo GIF: not embedded here yet — the bot is private by design, so a screen recording (rather than a public link) is the "try it yourself" for reviewers. Add it under `docs/telegram-demo.gif` and link it here once recorded.

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
DEEPSEEK_API_KEY=
XAI_API_KEY=
GEMINI_API_KEY=
GROQ_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
API_KEY=                    # Optional: enables X-API-Key auth on mutations

# Telegram bot (optional - private, allowlist-only)
TELEGRAM_BOT_TOKEN=         # From @BotFather
TELEGRAM_ALLOWLIST=         # Comma-separated chat_ids; empty = bot accepts nobody
TELEGRAM_RATE_LIMIT_PER_DAY=20
THREATCHAIN_API_BASE=http://localhost:8000/api/v1
THREATCHAIN_WS_BASE=ws://localhost:8000/ws
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

## Architecture Decisions

Short answers to the "why didn't you..." questions a reviewer might ask:

**Why no Celery, if it's in `requirements.txt`?**
It's a leftover from early planning — no worker, no task module, nothing imports it. Non-blocking investigations are already solved with FastAPI `BackgroundTasks` (`POST /investigate` with `"wait": false` returns immediately) plus the `WS /ws/investigation/{id}` progress stream. A task queue only earns its complexity if the bot/API need to scale across multiple processes or machines; at the current single-instance scale it would be pure overhead. Revisit if that changes.

**Why is the Telegram bot private instead of public?**
See [Telegram Bot](#telegram-bot) above — public access on a bot that triggers real LLM calls and hits shared third-party API quotas is an abuse vector with no upside for a portfolio piece.

**Where does this actually run — VPS, PaaS, or just local?**
Not deployed permanently yet, by choice: the repo is deployment-ready (`docker compose up -d` brings up `db`, `redis`, `api`, `ui`, and `bot` with `restart: unless-stopped` on all five), but provisioning a real host (Hetzner VPS, Railway/Render/Fly.io, or a temporary tunnel for a live demo) is a cost/hosting decision left for whenever it's actually needed, rather than paying for infrastructure that would otherwise sit idle.

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
