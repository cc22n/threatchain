# Plan de Implementacion - Bot de Telegram + Produccion

Version actualizada y verificada contra el codigo real de `ThreatChain_Agente_Produccion_Telegram.md`
(ese doc es la idea original pero quedo desactualizado frente al backend actual).
Generado tras auditar el codigo con graphify + lectura directa de archivos, 2026-07-16.

---

## 0. Estado actual verificado (no hay que reinventar esto)

Antes de escribir fases, esto es lo que YA existe y funciona en el backend,
confirmado leyendo el codigo (no asumido del plan viejo):

| Necesidad del plan Telegram | Ya implementado en | Nota |
|---|---|---|
| Investigacion no bloqueante | `app/api/investigations.py` - `POST /investigate` con `BackgroundTasks` | Ya retorna el id de inmediato en modo async (`payload.wait=False`) |
| Progreso en tiempo real | `app/api/ws.py` + `app/services/progress.py` | WebSocket `/ws/investigation/{id}` con snapshot inicial + eventos + poll fallback cada 10s |
| Cache agresivo de IOCs | `app/services/cache_service.py` | Redis, TTL default 86400s (24h), ya usado por las tools |
| Rate limit por API externa | `app/services/rate_limiter.py` + tabla `api_configs` | Chequeo atomico check-and-increment, ya usado por RECON/MALWARE/etc |
| Auth en endpoints de mutacion | `app/api/auth.py` - `require_api_key` | Header `X-API-Key`, comparacion constant-time, se puede desactivar en dev |
| Observabilidad / metricas | `GET /api/v1/stats`, `GET /api/v1/health/apis`, `GET /api/v1/health/llms` | Ya expone investigaciones totales, uso de APIs, salud de LLMs |
| Export de reportes | `app/services/export_service.py` | STIX 2.1 y Markdown ya implementados |

**Conclusion importante:** el plan original asumia que hacia falta Celery para
no bloquear el bot. Eso YA esta resuelto a nivel API con `BackgroundTasks` +
WebSocket. El bot de Telegram puede ser un cliente HTTP/WS simple sin
necesitar cola de tareas propia. Ver seccion 1 (decisiones de arquitectura).

## 0.1 Gaps reales (esto si falta)

- **No existe ningun modulo de bot.** No hay `python-telegram-bot` ni nada
  similar en `requirements.txt`, ni carpeta `app/bot/` o equivalente.
- **`celery==5.4.0` esta en `requirements.txt` pero no se usa en ningun `.py`.**
  Dependencia fantasma — no hay workers, no hay `celery_app.py`, no hay tasks.
- **`docker-compose.yml` solo tiene `db`, `redis`, `api`, `ui`.** No hay
  servicio `bot` ni `celery-worker`.
- **Rate limiting es por API externa, no por usuario.** No hay proteccion
  para que un usuario de Telegram sature el bot con investigaciones.
- **No hay allowlist / control de acceso al bot.** Si se hace publico,
  cualquiera puede mandar IOCs.
- **`RateLimiter.reset_daily_counters()` existe pero nadie lo llama nunca**
  (ver `ARCHITECTURAL_ROADMAP.md` Item 1 - APScheduler no esta cableado en
  `app/main.py`). Esto es un prerequisito real para correr 24/7: sin esto,
  los contadores diarios de las 17 APIs nunca se resetean y el sistema
  reportara "limite alcanzado" permanentemente despues del primer dia.

## 1. Decisiones de arquitectura (a confirmar antes de picar codigo)

1. **Celery: no para el MVP.** Dado que `BackgroundTasks` + WebSocket ya
   resuelven "no bloquear", agregar Celery solo se justifica si se necesita
   escalar el bot en varios procesos/maquinas. Recomendacion: arrancar sin
   Celery (el bot llama a la API, sigue el WS, notifica al usuario), dejarlo
   como mejora de Fase 4+ si el uso real lo justifica. Si el usuario prefiere
   mantener Celery desde el inicio (por ejemplo para practicar esa skill de
   cara a entrevistas), es una decision valida — solo que no es requisito
   tecnico.
2. **Hosting: pendiente de eleccion.** El doc original ofrece 3 opciones
   (Hetzner VPS, Railway/Render/Fly.io, tunel local solo demo). No hay
   informacion en el repo de cual se eligio. Se deja como decision abierta
   en Fase 3.
3. **Acceso al bot: PRIVADO con allowlist.** Decidido — mejor para
   portafolio (evita abuso/costos de API descontrolados y permite mostrarlo
   de forma controlada a reclutadores). Ver detalle de implementacion en
   Fase 1 y Fase 4.
4. **Arranque del bot en Windows (dev local).** `app/main.py` ya tiene el
   fix de `WindowsSelectorEventLoopPolicy` para psycopg async. Si el bot
   corre en el mismo proceso que la API o como script separado en Windows,
   necesita el mismo fix o correr bajo Docker/Linux para evitar el problema.

---

## Fase 0 - Prerequisito de backend (antes de tocar Telegram) - HECHO

Implementado y verificado 2026-07-18.

- [x] Implementado el fix de `ARCHITECTURAL_ROADMAP.md` Item 1: `lifespan` +
      `AsyncIOScheduler` en `app/main.py`, job `_reset_rate_limits` con
      `CronTrigger(hour=0, minute=0, timezone="UTC")` y
      `misfire_grace_time=3600` (si el server estuvo caido a medianoche,
      corre igual al levantar). `apscheduler==3.10.4` agregado a
      `requirements.txt` e instalado en el conda env.
      Verificado con el servidor real corriendo (puerto 8010, para no chocar
      con otro proyecto que ya tenia el 8000 ocupado): booteo sin errores,
      `GET /api/v1/health/apis` mostro contadores reales con uso previo
      (ej. `shodan: 2`, `virustotal: 1`), se invoco `reset_daily_counters()`
      manualmente contra la DB real y confirmo `reset rows: 17` seguido de
      todos los contadores en 0 via el mismo endpoint. Shutdown del scheduler
      limpio (sin excepciones ni proceso colgado). Suite completa
      97/97 tests + ruff limpio despues del cambio.
- [x] Revisado `ARCHITECTURAL_ROADMAP.md` Item 2 (2026-07-18). La
      arquitectura propuesta (insert rapido + background task) ya estaba
      implementada inline en `app/api/investigations.py` cuando `wait=False`
      — `run_investigation` ya acepta `investigation_id` opcional tal como
      pedia el roadmap, no hizo falta separar `create_investigation`/
      `run_investigation_background` como funciones nuevas.
      El riesgo real que quedaba abierto: `wait` por defecto era `True`
      (bloqueante, ~30-120s), asi que cualquier caller que no mandara el
      flag explicito (curl, Postman, un test futuro) quedaba expuesto a un
      504 detras de un proxy con timeout de 60s. UI (`ui/app.py`) y el bot
      (`app/bot/telegram_bot.py`) ya mandaban `wait: False` explicito, asi
      que no se rompio nada. Fix aplicado: default de `wait` cambiado a
      `False` en `app/schemas/investigation.py`. Diferencias cosmeticas del
      roadmap (status 202 en vez de 201, schema `InvestigationAccepted` con
      `ws_url` explicito) quedaron sin implementar — no bloqueantes, el
      `id` ya viene en la respuesta y ambos clientes conocen el patron
      `/ws/investigation/{id}`. 97/97 tests + ruff limpio despues del cambio.

## Fase 1 - Bot de Telegram basico (sin Celery, privado con allowlist) - HECHO

Implementado y verificado 2026-07-16/17. Detalle de lo que quedo armado:

- [x] `python-telegram-bot==21.9` agregado a `requirements.txt` e instalado
      en el conda env `ThreatChain`.
- [x] `TELEGRAM_BOT_TOKEN` y `TELEGRAM_ALLOWLIST` agregados a `app/config.py`
      (`Settings`), `.env` y `.env.example`. `TELEGRAM_ALLOWLIST` se guarda
      como `str` plano (no `List[int]`): pydantic-settings intenta decodear
      como JSON cualquier campo de tipo complejo ANTES de correr un
      `field_validator(mode="before")`, asi que un valor vacio o una lista
      separada por comas rompe con `SettingsError` antes de llegar al
      validador. La propiedad `settings.telegram_allowlist_ids` hace el
      parseo a `list[int]` on-demand. (Mismo problema late en `CORS_ORIGINS`,
      que solo funciona hoy porque el `.env` real usa sintaxis JSON — no se
      toco, queda anotado como posible mejora futura, no bloqueante.)
- [x] Decorator `require_allowlist` en `app/bot/telegram_bot.py`: valida
      `update.effective_chat.id` contra `settings.telegram_allowlist_ids`
      antes de correr cualquier handler. Si no esta permitido, responde
      "Este bot es privado. No tenes acceso." y no ejecuta el handler.
- [x] `app/bot/telegram_bot.py` creado con:
      - `/start`, `/ayuda` (con `/help` como alias)
      - `/investigar <IOC>` - clasifica con `IocClassifier`, llama
        `POST /investigate` (`wait=False`), devuelve el id y la instruccion
        de usar `/estado <id>`
      - `/estado <id>` - hace `GET /investigations/{id}` y formatea el
        resultado segun el estado (pending/running/failed/cancelled/completed)
      - Mensaje directo con un IOC (sin comando) - mismo flujo que `/investigar`
- [x] El bot llama a la API por HTTP con `httpx.AsyncClient` (usa `X-API-Key`
      via `settings.API_KEY` si esta configurada) - no importa nada de
      `app/agents` ni `app/chains` mas alla de `IocClassifier`, mismo
      desacople que `ui/api_utils.py`.
- [x] `split_message()` particiona a 4096 caracteres respetando saltos de
      linea cuando puede.
- [x] Sanitizacion basica: `IocClassifier` devuelve `"unknown"` para valores
      no reconocibles como IOC, y el bot corta ahi con un mensaje de error
      en vez de mandarlo a la API.
- [x] Tests: `tests/test_bot/test_telegram_bot.py` (21 tests, mocks de
      `httpx.AsyncClient` con un fake async context manager - ver el
      comentario en el test sobre por que no sirve un `AsyncMock` plano
      para `__aenter__`/`__aexit__`). `ruff check` limpio.
- [x] **Verificacion real (no solo mocks):** se levanto `python -m app.main`
      contra Postgres/Redis locales reales y se corrio el flujo completo del
      bot (`_start_investigation` -> `_fetch_investigation` ->
      `format_investigation`) contra la API en vivo con el IOC `8.8.8.8`.
      Resultado real: `BENIGN`, severity `low (2.0/10)`. La investigacion de
      prueba se soft-deleteo despues y el servidor se bajo.
- [ ] Falta probar el bot de punta a punta con un token real de BotFather y
      un `chat_id` real (no se hizo — no hay token/chat_id de prueba
      disponibles en este entorno). Cuando se tenga el token, correr
      `python -m app.bot.telegram_bot` y probar `/start`, `/investigar`,
      `/estado` desde Telegram de verdad antes de dar la Fase 1 por cerrada
      del todo.

## Fase 2 - Progreso en tiempo real (conectar al WS existente) - HECHO

Implementado y verificado 2026-07-18.

- [x] El bot se conecta a `ws://.../ws/investigation/{id}` (mismo patron que
      `ui/app.py`). `THREATCHAIN_WS_BASE` agregado como env var (mismo
      patron override que `THREATCHAIN_API_BASE`), default
      `ws://localhost:8000/ws`, agregado a `.env` y `.env.example`.
- [x] `_watch_investigation()` en `app/bot/telegram_bot.py`: manda un
      mensaje inicial y lo va editando in-place (`edit_text`) a medida que
      llegan eventos `agent_completed` — evita floodear el chat con un
      mensaje por agente. Dedup: si el texto no cambio no se llama a
      `edit_text` de nuevo.
- [x] Al llegar a estado terminal (`completed`/`failed`/`cancelled` via el
      evento `investigation_finished` o el snapshot inicial si la
      investigacion ya habia terminado), hace un ultimo `GET
      /investigations/{id}` para traer el resumen completo (el evento WS no
      trae `summary`) y edita el mensaje final con `format_investigation()`.
      Reporte STIX/Markdown completo queda para Fase 5 (no se aten al bot
      todavia, se puede pedir por HTTP directo).
- [x] `/estado <id>` seguia sin depender del WS (ya estaba asi desde
      Fase 1) - confirmado, no requirio cambios.
- [x] Concurrencia: `_handle_ioc` ya no bloquea al llamador — dispara
      `_watch_investigation` como task de fondo via `_spawn()`
      (`asyncio.create_task` + set de referencias fuertes para que no lo
      recolecte el GC). Cada investigacion corre en su propia task con su
      propia conexion WS, sin bloquear el handler de PTB para otros
      comandos/usuarios mientras corre.
- [x] Manejo de errores: timeout de 180s, "investigation not found" del
      servidor, y corte de conexion WS caen todos a un mensaje de fallback
      que apunta a `/estado <id>` en vez de dejar al usuario sin respuesta.
- [x] Tests nuevos en `tests/test_bot/test_telegram_bot.py`
      (`_FakeWebSocketConnection` como fake de `websockets.connect`, mismo
      patron que `_FakeAsyncClient`): `_format_progress` (2 tests),
      `_watch_investigation` happy path / not-found / connection-error /
      dedup de ediciones (4 tests). Suite del bot: 27/27 (antes 21).
- [x] **Verificacion real end-to-end** (no solo mocks): servidor levantado
      contra Postgres/Redis reales (puerto 8010), investigacion real de
      `8.8.8.8` corrida a traves de `_watch_investigation` real conectado
      al WS real. Resultado: mensaje inicial + 3 ediciones en vivo (osint,
      recon, mitre completados) + edicion final con veredicto real
      `BENIGN`, severidad `info (0.4/10)`. Investigacion de prueba borrada
      (soft-delete) y servidor apagado despues. Suite completa: 103/103
      tests, ruff limpio.
- [x] De paso: se encontro y corrigio un `TELEGRAM_BOT_TOKEN=` vacio
      duplicado en `.env` (linea suelta de una edicion anterior) que estaba
      pisando el token real que el usuario ya habia cargado — con
      `python-dotenv`, la ultima ocurrencia de una clave gana, asi que el
      bot habria arrancado sin token pese a que el usuario ya lo habia
      puesto.
- [x] **Prueba real con Telegram/BotFather** (el item que habia quedado
      pendiente de Fase 1): usuario cargo `TELEGRAM_ALLOWLIST` con su
      `chat_id` real, se levanto API + bot de verdad (`t.me/ThreatChainbot`)
      y el usuario probo `/investigar 185.220.101.34` desde su telefono.
      Confirmo que funciona.
- [x] **Bugs reales encontrados durante la prueba con el usuario, corregidos
      y reverificados contra el backend real:**
      1. `Investigation.summary` nunca se poblaba — `ReportAgent` generaba
         el `executive_summary` pero `run_investigation()` nunca lo copiaba
         al modelo. El bot siempre mostraba "Sin resumen disponible" pese a
         que verdict/severity si llegaban bien. Fix: `Coordinator.investigate()`
         ahora devuelve tambien `report` (los findings del ReportAgent) y
         `investigation_service.run_investigation()` setea
         `investigation.summary = report_findings.get("executive_summary")`.
      2. El bot solo mandaba una URL cruda de la API (`GET .../report`) en
         vez del reporte — inutil desde Telegram. Fix: nuevo comando
         `/reporte <id>` en `app/bot/telegram_bot.py` que trae
         `GET /investigations/{id}/report` y manda el markdown completo al
         chat (via `_send`, que ya chunkea a 4096 caracteres).
      3. Las respuestas del LLM (resumen ejecutivo, hallazgos clave,
         recomendaciones) venian en ingles. Fix: `SYSTEM_PROMPT` en
         `app/chains/report_chain.py` ahora pide explicitamente que el
         texto en lenguaje natural sea en espanol (los nombres de campo y
         los valores enum de verdict/severity se mantienen en ingles porque
         el codigo los parsea). Tambien se tradujo el texto de fallback en
         `app/agents/report_agent.py` (cuando el LLM falla) y los headers
         estaticos de `templates/report.md.j2` (afecta tambien el export a
         PDF/Markdown, que reusa la misma plantilla).
      Verificado con una investigacion real de `185.220.101.34` contra el
      servidor real: `summary` con el parrafo generado por el LLM en
      espanol, `/reporte` devolviendo el markdown completo tambien en
      espanol. Suite completa: 108/108 tests, ruff limpio.
- [x] Servidor y bot de prueba apagados a pedido del usuario al terminar.

## Fase 3 - Deployment - HECHO (alcance: repo deployment-ready, sin deploy en vivo)

Implementado y verificado 2026-07-21. Alcance decidido con el usuario: dejar
todo listo para desplegar, sin aprovisionar ni pagar ningun hosting real
todavia — esa decision queda para cuando el usuario elija hacerlo.

- [x] Hosting: decidido con el usuario no aprovisionar nada ahora. Las 3
      opciones del doc original (Hetzner VPS, Railway/Render/Fly.io, tunel
      local solo demo) siguen todas disponibles mas adelante — el
      `docker-compose.yml` corre igual en cualquiera de las 3, no hay
      lock-in.
- [x] Servicio `bot` agregado a `docker-compose.yml`, mismo patron que
      `ui` (build compartido, sin puertos expuestos, red interna hacia
      `api` via `THREATCHAIN_API_BASE`/`THREATCHAIN_WS_BASE`,
      `depends_on: api: condition: service_healthy`). No hizo falta tocar
      el `Dockerfile` — ya hace `COPY . .`, asi que `app/bot/` ya estaba
      incluido en la imagen que tambien usan `api` y `ui`.
- [x] `TELEGRAM_BOT_TOKEN`/`TELEGRAM_ALLOWLIST` ya estaban en
      `app/config.py` y `.env.example` desde Fase 1 — el servicio `bot`
      los recibe automaticamente via `env_file: .env`, igual que los demas
      servicios, sin necesidad de duplicarlos en el bloque `environment:`.
- [x] `restart: unless-stopped` agregado a los 5 servicios (`db`, `redis`,
      `api`, `ui`, `bot`) — ninguno lo tenia antes.
- [x] De paso: se saco el `version: "3.9"` obsoleto del tope del archivo
      (Docker Compose v2 lo ignora con warning).
- [x] `.github/workflows/ci.yml` — revisado, **no requirio cambios**. El
      job `test` ya corre `pytest tests/ -v --tb=short -x` (cubre
      `tests/test_bot/` sin listarlo aparte) y el job `lint` ya corre
      `ruff check app/ tests/` (cubre `app/bot/` igual). `requirements.txt`
      ya tenia `python-telegram-bot`/`apscheduler` desde Fases 1 y 0. Los
      tests del bot no requieren `TELEGRAM_BOT_TOKEN` real (usan
      `monkeypatch` sobre `settings`, nunca pegan a Telegram de verdad), asi
      que no hizo falta agregar variables nuevas al bloque `env:` del CI.
- [x] Validacion real: `docker compose config -q` resuelve el archivo
      completo sin errores (solo confirmo que la sintaxis y las referencias
      entre servicios son correctas). `python -m pip check` sin conflictos
      de dependencias. **No se pudo hacer un build/run real de la imagen**
      porque el motor de Docker Desktop no esta corriendo en esta maquina
      ahora mismo (el CLI resuelve pero el daemon no responde) — pendiente
      de que el usuario lo levante y corra `docker compose up --build` para
      la verificacion final antes de un deploy real.

## Fase 4 - Robustez para uso continuo - HECHO

Implementado y verificado 2026-07-22.

- [x] Rate limiting POR USUARIO de Telegram: contador en memoria del propio
      proceso del bot (`_user_request_log` en `app/bot/telegram_bot.py`),
      no en Redis/Postgres — el bot corre como un solo proceso sin escalado
      horizontal, asi que no hace falta estado compartido; se resetea si el
      bot reinicia, tradeoff aceptable a esta escala. Limite configurable
      via `TELEGRAM_RATE_LIMIT_PER_DAY` (default 20/dia), aplicado en
      `_handle_ioc` antes de arrancar una investigacion nueva (no consume
      cupo si se reusa una investigacion via dedup).
- [x] Allowlist: ya estaba implementada en Fase 1 y ya tenia tests
      (`test_is_allowed_*`, `test_require_allowlist_*`) — verificado que
      siguen cubriendo el caso `chat_id` fuera de la lista, sin cambios.
- [x] Deduplicacion de investigaciones: nuevo filtro `ioc_value` opcional en
      `GET /investigations` (`app/api/investigations.py`) + funcion
      `_find_recent_investigation()` en el bot que consulta ese filtro antes
      de llamar `/investigate`. Si hay una investigacion de los ultimos 10
      minutos (`DEDUP_WINDOW_SECONDS`) para el mismo IOC con status
      pending/running/completed, la reusa (sigue el WS si esta corriendo,
      o muestra el resultado si ya termino) en vez de arrancar el pipeline
      de 7 agentes de nuevo.
- [x] `/metricas` en el bot, consume `GET /api/v1/stats` (ya existia) y lo
      formatea para Telegram.
- [x] **Bug real encontrado durante la verificacion end-to-end, corregido**:
      `Investigation.created_at` usaba `server_default=func.now()` de
      Postgres, pero la sesion de Postgres de esta maquina tiene
      `timezone = America/Mexico_City` (UTC-6) y la columna es
      `TIMESTAMP` SIN zona horaria — Postgres devolvia la hora local sin
      offset, no UTC. Esto contradecia la convencion ya establecida para
      `completed_at`, que si se computa en Python como UTC explicito. El
      bug rompio la deduplicacion (una investigacion recien creada parecia
      tener ~5 horas de antiguedad) y probablemente afecta cualquier lugar
      que calcule "hace cuanto se creo" una investigacion. Fix en
      `app/models/investigation.py`: `created_at` ahora usa un default de
      Python (`default=_utc_now`, mismo patron que `completed_at`) en vez
      de depender de la zona horaria de la sesion de Postgres. No requirio
      migracion de Alembic (el default de Python tiene prioridad sobre el
      `DEFAULT now()` que quedo en el esquema de la DB, nunca se dispara
      via el ORM). Nota para el futuro: otros modelos
      (`app/models/report.py` con `generated_at`, etc.) podrian tener el
      mismo patron `server_default=func.now()` y estar expuestos al mismo
      problema — no se tocaron porque estan fuera del alcance de esta
      fase, quedan anotados aca.
- [x] **Verificacion real end-to-end** contra el servidor real (con el fix
      de timezone aplicado): dedup detecto correctamente una investigacion
      recien arrancada (`status: running`) para el mismo IOC; el filtro
      `ioc_value` en `GET /investigations` devolvio solo filas de ese IOC;
      `/metricas` trajo datos reales de `/stats`; el rate limiter en
      memoria bloqueo correctamente tras alcanzar el limite configurado.
      Registros de prueba limpiados (soft-delete) y servidor apagado
      despues. Suite completa: 119/119 tests, ruff limpio.

## Fase 5 - Pulido para portafolio - HECHO (sin GIF, a pedido del usuario)

Implementado y verificado 2026-07-23.

- [x] README actualizado con seccion `## Telegram Bot` (comandos, progreso
      en vivo, por que es privado, protecciones por usuario, como correrlo
      local/Docker). Placeholder dejado para el GIF (`docs/telegram-demo.gif`)
      con nota explicando por que un GIF/video reemplaza al link publico de
      "pruebalo vos mismo" en un bot privado.
- [x] Decision del GIF: el usuario eligio saltarlo por ahora. El placeholder
      queda listo en el README para cuando decida grabarlo (desde la app
      real de Telegram en su telefono, no Telegram Web, para mejor calidad).
- [x] Nueva seccion `## Architecture Decisions` en el README documentando
      las 3 decisiones de la seccion 1 de este plan: por que no Celery, por
      que el bot es privado, y por que el hosting real queda pendiente
      (deployment-ready pero sin aprovisionar).
- [x] De paso, aprovechando que se estaba tocando el README: se encontraron
      y arreglaron dos desactualizaciones reales que no eran del bot pero
      quedaban mal en un doc de portafolio:
      1. El diagrama de arquitectura y la tabla de Stack todavia decian
         "Grok"/"GPT-4o" como LLM principal — desactualizado desde el
         swap a DeepSeek (hecho fuera de fases, 2026-07-16). Corregido.
      2. Un bloque de instrucciones en español, duplicado y sin code
         fence, pegado sin ningun heading entre "Security Notes" y
         "Portfolio Context" (accidente de copy-paste de una edicion
         anterior) — puro contenido repetido de lo que ya decian "Quick
         Start" y "Local Development" en ingles, mal formateado. Eliminado.
      3. La seccion "Async mode and real-time progress" todavia decia que
         `wait` bloqueaba por defecto — desactualizado desde el fix del
         Item 2 en la revision de Fase 0 (default paso a `wait: false`).
         Corregido.
- [x] Tabla de variables de entorno actualizada con `DEEPSEEK_API_KEY`,
      `TELEGRAM_BOT_TOKEN`, `TELEGRAM_ALLOWLIST`,
      `TELEGRAM_RATE_LIMIT_PER_DAY`, `THREATCHAIN_API_BASE`,
      `THREATCHAIN_WS_BASE`.
- [x] Verificado: 119/119 tests (README no toca codigo, corrida de control
      igual para confirmar que no quedo nada roto).

---

## Pendiente de revisar — resuelto en fases posteriores

Todos los items de esta seccion (dejados abiertos cuando se escribio este
plan) ya se resolvieron en el camino: Item 2 del roadmap revisado y
cerrado en la revision de Fase 0, `restart` policies agregadas en Fase 3,
CI revisado y confirmado que no necesita cambios en Fase 3. No queda nada
pendiente de esta lista original.

## Hecho fuera de las fases (adelantado a pedido del usuario, 2026-07-16)

- **Soporte DeepSeek agregado al LLM router.** `DEEPSEEK_API_KEY` ya estaba
  en `.env` y `.env.example` pero no estaba cableado. Se agrego el
  provider `deepseek` en `ai_config.json` (modelos `deepseek-chat` y
  `deepseek-reasoner`, API OpenAI-compatible via `base_url:
  https://api.deepseek.com`) y la rama correspondiente en
  `app/llm/providers.py` (reusa `ChatOpenAI`, mismo patron que xAI).
  `GET /api/v1/health/llms` ya lo va a listar automaticamente como
  provider configurado. **No se toco `agent_routing`** — el provider esta
  disponible pero ningun agente lo usa todavia como primary/fallback;
  eso es una decision aparte (por ejemplo, podria reemplazar a Groq como
  fallback barato en RECON/MALWARE/VULN/MITRE/OSINT si se quiere probar).
