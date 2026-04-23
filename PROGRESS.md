  # ThreatChain - Progreso de Desarrollo

> **Inicio:** 2026-04-14
> **Estado actual:** Fase 5 completada — proyecto listo para portfolio
> **Repo:** https://github.com/cc22n/threatchain

---

## Resumen de Fases

| Fase | Nombre | Semanas | Estado |
|---|---|---|---|
| 1 | LangChain Core + 3 Tools basicos | 1-3 | Completada |
| 2 | Multi-agente + RAG MITRE | 4-6 | Completada |
| 3 | Report Agent + Exportacion | 7-8 | Completada |
| 4 | Cache + Rate Limiting + Optimizacion | 9-10 | Completada |
| 5 | UI Pulida + Documentacion + Demo | 11-12 | Completada |

---

## Fase 1: LangChain Core + 3 Tools basicos

> **Objetivo:** Sistema que recibe una IP y devuelve reporte basico de reputacion
> usando 3 APIs + LLM.
> **Semanas:** 1-3

### Setup e Infraestructura

- [x] Entorno conda dedicado para ThreatChain (Python 3.11+)
- [x] Instalar dependencias y activar entorno
- [x] Crear `requirements.txt` con versiones fijadas
- [x] Configurar `.env` desde `.env.example` (copiar y rellenar API keys)
- [x] Estructura de directorios del proyecto (`app/`, `ui/`, `tests/`, etc.)
- [x] `.env.example` con todas las variables documentadas
- [x] `.gitignore`

### Base de Datos

- [x] PostgreSQL: crear base de datos `threatchain` y usuario
- [x] `app/database.py` - async engine + session con psycopg v3
- [x] `app/config.py` - Settings con pydantic-settings
- [x] Modelos SQLAlchemy:
  - [x] `app/models/investigation.py` - tabla `investigations`
  - [x] `app/models/agent_result.py` - tabla `agent_results`
  - [x] `app/models/api_tool_result.py` - tabla `api_tool_results`
- [x] Alembic: `alembic.ini` + `alembic/env.py` + migracion inicial
- [x] Ejecutar migracion: `alembic revision --autogenerate -m "init"` + `alembic upgrade head`

### LLM Router

- [x] `ai_config.json` - configuracion de providers y modelos
- [x] `app/llm/providers.py` - factory de providers LangChain
- [x] `app/llm/router.py` - routing por tipo de agente
- [x] `app/llm/fallback.py` - logica de fallback si falla el LLM principal

### Tools de APIs (3 iniciales)

- [x] `app/tools/base_tool.py` - clase base abstracta con rate limiting y cache Redis
- [x] `app/tools/virustotal.py` - reputacion de IPs, hashes, dominios, URLs
- [x] `app/tools/abuseipdb.py` - reputacion de IPs, reportes de abuso
- [x] `app/tools/shodan.py` - puertos abiertos, servicios, banners
- [x] `api_config.json` - configuracion de APIs (base_url, rate limits)

### Agente RECON

- [x] `app/agents/base_agent.py` - clase base abstracta con persistencia en DB
- [x] `app/agents/recon_agent.py` - agente con las 3 tools iniciales
- [x] Chain basico: IOC -> consulta APIs -> parsea resultados -> resumen con LLM

### Chains Basicos

- [x] `app/chains/ioc_classifier.py` - clasificar tipo de IOC (regex, sin LLM)

### FastAPI

- [x] `app/main.py` - entry point con routers
- [x] `app/api/investigations.py` - `POST /api/v1/investigate` + `GET /api/v1/investigations/{id}`
- [x] `app/api/health.py` - `GET /api/v1/health`
- [x] Schemas Pydantic: `app/schemas/investigation.py`, `app/schemas/ioc.py`

### Streamlit UI Basico

- [x] `ui/app.py` - input de IOC + mostrar resultado + conectado al endpoint
- [ ] `ui/pages/investigate.py` - pagina separada (opcional en Fase 1)

### Tests

- [x] `tests/conftest.py` - fixtures: DB in-memory, mocks de cache y rate limiter
- [x] `tests/fixtures/sample_vt_response.json`
- [x] `tests/fixtures/sample_abuseipdb_response.json`
- [x] `tests/fixtures/sample_shodan_response.json`
- [x] `tests/test_tools/test_virustotal.py`
- [x] `tests/test_tools/test_abuseipdb.py`
- [x] `tests/test_tools/test_shodan.py`
- [x] `tests/test_agents/test_recon.py`

---

## Fase 2: Multi-Agente + RAG MITRE

> **Objetivo:** Sistema multi-agente completo que investiga cualquier tipo de IOC.
> **Semanas:** 4-6

### Tools restantes (14 tools)

- [x] `app/tools/alienvault_otx.py`
- [x] `app/tools/urlscan.py`
- [x] `app/tools/nvd.py`
- [x] `app/tools/cisa_kev.py`
- [x] `app/tools/malwarebazaar.py`
- [x] `app/tools/hybrid_analysis.py`
- [x] `app/tools/greynoise.py`
- [x] `app/tools/pulsedive.py`
- [x] `app/tools/threatfox.py`
- [x] `app/tools/phishtank.py`
- [x] `app/tools/securitytrails.py`
- [x] `app/tools/exploitdb.py`
- [x] `app/tools/threatcrowd.py`
- [x] `app/tools/haveibeenpwned.py`

### Modelos y Migraciones adicionales

- [x] `app/models/mitre_mapping.py` - tabla `mitre_mappings`
- [x] `app/models/ioc_relationship.py` - tabla `ioc_relationships`
- [x] `app/models/config.py` - tablas `api_configs` y `llm_configs`
- [ ] Migracion Alembic: `alembic revision --autogenerate -m "phase2"` + `alembic upgrade head`
- [ ] Seed de `api_configs` con las 17 APIs (rate limits, base_urls)
- [ ] Seed de `llm_configs` con todos los providers

### RAG MITRE ATT&CK

- [ ] Descargar `enterprise-attack.json` a `knowledge_base/mitre/`
- [x] `app/rag/embeddings.py`
- [x] `app/rag/knowledge_base.py`
- [x] `app/rag/loaders/mitre_loader.py`
- [ ] Indexar MITRE ATT&CK: ejecutar `load_mitre_index()` una vez
- [x] `app/chains/mitre_lookup_chain.py`

### Agentes adicionales

- [x] `app/agents/malware_agent.py`
- [x] `app/agents/vuln_agent.py`
- [x] `app/agents/mitre_agent.py`
- [x] `app/agents/osint_agent.py`

### Coordinator con LangGraph

- [x] `app/agents/coordinator.py` - LangGraph StateGraph con routing por IOC type
- [x] Ejecucion paralela con `asyncio.gather(..., return_exceptions=True)`
- [x] Manejo de fallos parciales

### Chains adicionales

- [x] `app/chains/severity_scorer.py`
- [x] `app/chains/correlation_chain.py`

### API Endpoints nuevos

- [x] `GET /api/v1/investigations` - listado paginado
- [x] `GET /api/v1/investigations/{id}` - detalle completo
- [x] `GET /api/v1/investigations/{id}/results` - resultados por agente
- [x] `GET /api/v1/investigations/{id}/mitre` - mapeos MITRE
- [x] `GET /api/v1/investigations/{id}/relationships` - IOCs relacionados
- [x] `DELETE /api/v1/investigations/{id}`

### Tests Fase 2

- [x] `tests/test_agents/test_coordinator.py`
- [x] `tests/test_agents/test_malware.py`
- [x] `tests/test_rag/test_mitre_lookup.py`
- [x] `tests/test_chains/test_severity_scorer.py`
- [x] `tests/test_chains/test_correlation.py`

---

## Fase 3: Report Agent + Exportacion

> **Objetivo:** Reportes profesionales de investigacion con exportacion multi-formato.
> **Semanas:** 7-8

### Report Agent

- [x] `app/agents/report_agent.py` - con Claude Sonnet como LLM principal
- [x] `app/chains/report_chain.py` - chain de generacion de reporte con Jinja2
- [x] `templates/report.md.j2` - template Markdown
- [x] Modelo SQLAlchemy: `app/models/report.py` - tabla `reports`
- [ ] Migracion Alembic: `alembic revision --autogenerate -m "phase3"` + `alembic upgrade head`

### Correlation Engine

- [x] Correlation Engine en `app/chains/correlation_chain.py`
- [x] Severity scoring automatico en `app/chains/severity_scorer.py`
- [x] Cruce de resultados entre agentes
- [x] Calculo de `severity_score` numerico (0.0 - 10.0)

### Exportacion

- [x] `app/services/export_service.py` - Markdown + PDF (reportlab) + STIX 2.1
- [x] Export a Markdown (template Jinja2)
- [x] Export a PDF (reportlab)
- [x] Export a STIX 2.1 (stix2)

### WebSocket y UI

- [x] `app/api/ws.py` - WebSocket `WS /ws/investigation/{id}`
- [x] `app/api/reports.py` - endpoints de reporte y descarga
- [x] `ui/pages/history.py` - historial de investigaciones
- [x] `ui/pages/report_viewer.py` - visor de reportes con descarga

### API Endpoints Fase 3

- [x] `GET /api/v1/investigations/{id}/report`
- [x] `POST /api/v1/investigations/{id}/report/regenerate`
- [x] `GET /api/v1/investigations/{id}/report/download?format=pdf`
- [x] `GET /api/v1/investigations/{id}/report/download?format=stix`
- [x] `GET /api/v1/investigations/{id}/report/download?format=md`
- [x] `GET /api/v1/investigations` - listado paginado

### Tests Fase 3

- [x] `tests/test_agents/test_report_agent.py`
- [x] `tests/test_services/test_export_service.py`

---

## Fase 4: Cache + Rate Limiting + Optimizacion

> **Objetivo:** Sistema robusto, eficiente y con metricas de uso.
> **Semanas:** 9-10

### Redis y Cache

- [x] `app/services/cache_service.py` - Redis cache, TTL 24h, clave `{api}:{ioc}`
- [x] Cache integrado en `base_tool.py` (todos los tools lo heredan)
- [x] `get_redis_client()` con fallback graceful si Redis no esta disponible

### Rate Limiting

- [x] `app/services/rate_limiter.py` - rate limiting por API leyendo `api_configs`
- [x] Reset de contadores: `reset_daily_counters()` disponible
- [x] Fallback: si API no esta en DB se permite la llamada

### Dashboard de APIs

- [x] `GET /api/v1/health/apis` - estado de cada API (rate limits, uso)
- [x] `GET /api/v1/health/llms` - estado de LLM providers
- [x] `GET /api/v1/stats` - estadisticas globales de uso
- [x] `ui/pages/api_health.py` - dashboard completo

### Metricas de Costo

- [x] Tokens usados por agente loguados en `agent_results.tokens_used`
- [x] `get_stats()` agrega tokens y tiempo de ejecucion

### Optimizacion

- [x] `app/services/investigation_service.py` - orquestacion centralizada
- [x] Batch investigation: `POST /api/v1/investigate/batch` (max 20 IOCs, asyncio.Semaphore)
- [x] `ui/pages/settings.py` - batch input desde UI

### Tests Fase 4

- [x] `tests/test_services/test_cache_service.py`
- [x] `tests/test_services/test_rate_limiter.py`

---

## Fase 5: UI Pulida + Documentacion + Demo

> **Objetivo:** Proyecto completo listo para GitHub y demostraciones.
> **Semanas:** 11-12

### Frontend

- [x] UI Streamlit completa con 4 paginas (main, history, report_viewer, api_health, settings)
- [ ] Migrar UI a React (alcance futuro, fuera del portfolio actual)
- [ ] Grafo visual de relaciones entre IOCs (D3.js o vis.js) (alcance futuro)
- [ ] Visualizacion de tecnicas MITRE interactiva (alcance futuro)

### Documentacion

- [x] `README.md` profesional con diagrama ASCII, quick start, API reference, tools table
- [x] Swagger/OpenAPI disponible en `/docs` (FastAPI auto-generado)
- [ ] Demo video (pendiente — captura manual)

### DevOps

- [x] `Dockerfile` - python:3.11-slim, instala gcc + libpq-dev
- [x] `docker-compose.yml` - 4 servicios: db, redis, api, ui con healthchecks
- [x] `.dockerignore` - excluye .env, __pycache__, chroma_data, tests
- [x] `.github/workflows/ci.yml` - GitHub Actions: lint (ruff) + tests (postgres + redis services)

### Repositorio

- [x] `.gitignore` completo
- [x] `.env.example` con todas las variables documentadas
- [ ] Tag de release v1.0.0 (pendiente push a GitHub)

---

## Notas de Desarrollo

- ASCII puro en todos los archivos `.py` (sin acentos, tildes, emojis)
- Usar `psycopg` v3 siempre (`psycopg[async]==3.2.x`), nunca `psycopg2`
- Cache Redis SIEMPRE antes de llamar cualquier API externa
- Nunca llamar APIs reales en tests (usar fixtures en `tests/fixtures/`)
- LangChain versiones fijadas para evitar breaking changes
- El Coordinator usa LangGraph StateGraph, NO AgentExecutor clasico
