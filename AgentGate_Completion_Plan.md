# AgentGate - Plan de Cierre (Fase 2 completa + huecos de Fases 1, 3 y 4)

> **Para:** Gemini (implementa)  **Supervisa:** Claude (revisa cada hito antes de dar el siguiente)
> **Base:** `AgentGate_Permission_Harness_BRIEF.md` (fuente de verdad) y `AgentGate_Execution_Plan.md`
> **Fecha:** 2026-09-25
> **Linea base verificada:** `184 passed` con
> `& "C:\Users\coral\anaconda3\envs\ThreatChain\python.exe" -m pytest -q`

---

## 0. Por que existe este plan

La primera ronda dejo el motor de reglas (PDP), el decorador (PEP), los manifiestos y un dashboard
basico. Claude ya corrigio: manifiesto duplicado de RECON, XSS/auth del dashboard, auditoria a
PostgreSQL, rate limiting y el caso MASK sobre IOC privado. **Todo eso ya esta hecho; no lo rehagas.**

Lo que sigue sin existir, aunque el walkthrough anterior decia "100%":

1. **La aprobacion humana no funciona de punta a punta.** Una accion `REQUIRE_APPROVAL` lanza
   `ApprovalRequiredError` y la tool falla. No hay pausa, ni aviso a Telegram, ni reanudacion.
   `TelegramNotifier` y `ContextRevalidator` no los llama nadie fuera de los tests.
2. Audit log no es realmente append-only, y no registra el desenlace de una aprobacion.
3. La cola de aprobaciones vive solo en memoria (Redis esta soportado pero nunca se conecta).
4. Una llamada directa a una tool sin `agent_name` se salta AgentGate (fail-open).
5. Faltan el context manager `AgentGateEnforcer`, filtros del dashboard, editor de manifiestos y
   metricas de tiempo de respuesta humana / herramientas mas usadas.
6. La "Demo 4" (accion pausada y aprobada por Telegram) no se puede ejecutar.

**Prioridad absoluta: Hitos M1-M3 (aprobacion humana real).** El resto se hace despues.

---

## 1. Reglas de trabajo (obligatorias)

- Archivos `.py` en **ASCII puro** (sin acentos, tildes ni emojis). Verifica al final de cada hito:
  ```powershell
  & "C:\Users\coral\anaconda3\envs\ThreatChain\python.exe" -c "from pathlib import Path; [print('NONASCII', p) for r in ['agentgate','app','tests','ui','alembic','scripts'] for p in Path(r).rglob('*.py') if any(c>127 for c in p.read_bytes())]"
  ```
- `psycopg` v3, nunca `psycopg2`. Async SQLAlchemy 2.x.
- **Tests nunca llaman APIs reales, ni Telegram real, ni Redis real.** Usa mocks / fakes en memoria.
- No modifiques tests existentes para "hacerlos pasar". Si un comportamiento cambia a proposito,
  actualiza el test y **anotalo en el reporte del hito** (explicando por que).
- Todo lo de este plan es nuevo codigo o cambios acotados. **No toques** archivos ajenos a AgentGate
  salvo los listados en cada hito (`app/tools/base_tool.py`, `app/main.py`, `app/config.py`,
  `app/bot/telegram_bot.py`, `docker-compose.yml`, `.env.example`).
- El motor sigue siendo **determinista, sin LLM**.
- **No hagas `git commit` ni `git push`.** Deja todo en el working tree; Claude revisa el diff.
- **No inventes herramientas destructivas reales** (nada de `block_ip` real, ni escritura en
  firewalls). Las acciones "de riesgo" de las demos son funciones falsas dentro de `scripts/` y tests.
- Reporta con honestidad: si algo no quedo hecho o quedo parcial, dilo. Un hito solo esta terminado
  cuando pasa su Definicion de Hecho con evidencia pegada (salida de pytest).

### Protocolo de supervision (por hito)

Al terminar cada hito, agrega una seccion al archivo `AgentGate_Completion_Progress.md` (crealo en el
primer hito) con exactamente:

```
## Hito Mx - <nombre>
- Archivos creados/modificados: ...
- Tests nuevos: ... (nombres)
- Salida de pytest (ultima linea): N passed
- Desviaciones del plan y por que: ...
- NO hecho / pendiente: ...
```

**Detente despues de cada hito y espera la revision de Claude antes de seguir con el siguiente.**

---

## 2. Arquitectura objetivo del flujo de aprobacion (leer antes de codificar)

Hechos del sistema actual que condicionan el diseno:

- El **bot de Telegram es un proceso aparte** (`docker-compose.yml`, servicio `bot`,
  `python -m app.bot.telegram_bot`, python-telegram-bot 21.9 con `run_polling`). Se comunica con la
  API **solo por HTTP** con `X-API-Key` (`_headers()`, `API_BASE` en `app/bot/telegram_bot.py`).
- La cola `ApprovalQueue` vive en la **memoria del proceso de la API** (donde corre el PEP).
- Una investigacion completa esta limitada por `INVESTIGATION_TIMEOUT_SECONDS` (120 s,
  `app/services/investigation_service.py`, con `asyncio.wait_for`).
- Los agentes ejecutan sus tools con `asyncio.gather` (`BaseAgent._run_tools_parallel`); si una tool
  lanza excepcion el agente la registra en `errors` y continua con las demas.

Flujo a implementar:

```
Tool._arun (proceso API)
  -> PEP.authorize(agent, tool, args)            # unica implementacion compartida
       PDP.decide -> REQUIRE_APPROVAL (crea ApprovalRequest en la cola)
       -> notificar por Telegram (HTTP directo a api.telegram.org, con botones inline)
       -> await queue.wait_for_decision(id, timeout=AGENTGATE_APPROVAL_WAIT_SECONDS)
            humano toca [Aprobar]  -> proceso bot recibe CallbackQuery
              -> bot hace POST {API}/agentgate/api/approve/{id}  (X-API-Key, approver=chat_id)
              -> queue.approve() dispara el asyncio.Event -> el PEP se despierta
       -> APPROVED : ContextRevalidator.revalidate(...) ; si OK ejecuta la tool con los args
                     ORIGINALES (sin volver a evaluar el PDP para no re-escalar) ; si falla -> error
       -> REJECTED : lanza ApprovalRejectedError
       -> EXPIRED  : lanza ApprovalExpiredError
       (cada desenlace se AUDITA con una fila nueva; ver M2)
```

Decisiones ya tomadas (no las cambies sin avisar):

1. **La logica de pausa/reanudacion vive en UN solo lugar:** `agentgate/client/pep.py`
   (`PolicyEnforcementPoint.authorize`). `ThreatIntelTool._arun` y `@protect` la reutilizan.
   Hoy `base_tool.py` y `pep.py` duplican la logica de decision; eliminar esa duplicacion es parte de M1.
2. **El aviso a Telegram lo envia el proceso de la API** llamando directo a la Bot API
   (`https://api.telegram.org/bot<TOKEN>/sendMessage` con `reply_markup.inline_keyboard`) usando
   `httpx` (ya es dependencia). No dependas de que el proceso `bot` este vivo para *enviar*; el proceso
   `bot` solo es necesario para *recibir* el toque del boton.
3. **El bot resuelve la aprobacion llamando a la API por HTTP** (nunca toca la cola directamente).
4. `callback_data` usa el **UUID completo** (`ag_appr_<uuid>`, 44 bytes < limite de 64). El notifier
   actual trunca a 8 caracteres: eso es ambiguo y debe corregirse.
5. Solo `settings.telegram_allowlist_ids` pueden aprobar. El handler del bot debe validar el chat.
   El `approver` que se guarda es `telegram:<chat_id>`.
6. Config nueva en `app/config.py` (todas con default seguro y documentadas en `.env.example`):
   - `AGENTGATE_APPROVAL_WAIT_SECONDS: int = 90` (debe ser < `INVESTIGATION_TIMEOUT_SECONDS`;
     valida y loguea warning si no).
   - `AGENTGATE_TELEGRAM_NOTIFY: bool = True` (si no hay token/allowlist, se omite el aviso con
     warning; la aprobacion sigue posible desde el dashboard).
   - `AGENTGATE_STRICT: bool = False` (True fuerza fail-closed sin `agent_name`; en
     `APP_ENV=production` se considera True aunque no este seteado; ver M5).

---

## 3. Hitos

### M1 - PEP con pausa/reanudacion (nucleo)   [Prioridad P0]

**Objetivo:** que `REQUIRE_APPROVAL` pause de verdad la llamada y la reanude o cancele.

Cambios:

- `agentgate/client/pep.py`:
  - Nuevas excepciones: `ApprovalRejectedError`, `ApprovalExpiredError`, `ContextChangedError`
    (todas heredan de `AgentGateError` y llevan `decision` / `request`).
  - Nuevo metodo `async def authorize(self, agent, tool, arguments, context=None) -> DecisionResult`
    que: llama `pdp.decide`; DENY -> `PermissionDeniedError`; MASK -> devuelve la decision con
    `masked_arguments` para que el llamador decida; REQUIRE_APPROVAL -> ejecuta el flujo de la
    seccion 2 (notificar, `await wait_for_decision`, revalidar, devolver decision aprobada) o lanza la
    excepcion adecuada. Modo `wait=False` (parametro) mantiene el comportamiento actual (lanzar
    `ApprovalRequiredError` de inmediato) para quien no quiera bloquear.
  - Nuevo context manager async `AgentGateEnforcer(agent, tool, arguments, context=None, pep=None)`
    (`async with AgentGateEnforcer(...) as decision:`) que envuelve `authorize` (lo que pedia el plan
    original de la Fase 1). El cuerpo del `with` recibe los argumentos ya enmascarados/aprobados.
  - `check_and_execute` y `protect` (async y sync) pasan a usar `authorize`. El wrapper **sync** no
    puede esperar aprobacion: si el PDP dice REQUIRE_APPROVAL, sigue lanzando `ApprovalRequiredError`
    (documentalo en el docstring).
- `agentgate/hitl/notifier.py`: nueva clase/funcion `async def send_approval_request(request)` que
  hace el POST a la Bot API con teclado inline (texto ASCII, sin acentos) a cada chat de la allowlist.
  Errores de red -> log warning, nunca rompen el flujo. Corrige `callback_data` a UUID completo.
  Quita del texto la linea "Reply with /approve ..." (no existen esos comandos) o implementalos en M3.
- `app/tools/base_tool.py`: en `_arun`, reemplaza el bloque PDP inline por
  `decision = await pep.authorize(agent_name, self.api_name, eval_args)` y conserva la logica de MASK
  sobre el IOC (`skipped: True`) ya existente. **No dupliques** decisiones en la tool.
- `app/config.py` + `.env.example`: las 3 variables de la seccion 2.
- Progreso en vivo: cuando una tool queda esperando aprobacion, publica un evento con
  `app.services.progress.publish(investigation_id, {...})` **solo si** hay `investigation_id` en
  `context`. Pasa `context={"investigation_id": ...}` desde `BaseAgent._run_tools_parallel`
  (ya recibe agent_name; extiendelo para llevar el id sin romper la firma actual: parametro opcional).

Reglas de robustez (cada una con test):
- Si `asyncio.CancelledError` ocurre mientras espera (timeout global de 120 s), marca la solicitud
  como `EXPIRED`, audita, y re-lanza `CancelledError` (no lo tragues).
- Doble aprobacion / aprobar una solicitud ya resuelta no debe reejecutar nada (idempotencia).
- Rechazar una solicitud ya aprobada devuelve error claro, no cambia el estado.
- Una tool aprobada se ejecuta **una sola vez** y con los argumentos originales de la solicitud.

Tests nuevos (`tests/test_agentgate/test_hitl_flow.py`), todos con `AsyncMock`/fakes:
- `approve` mientras la tool espera -> la tool se ejecuta y devuelve resultado.
- `reject` -> `ApprovalRejectedError`, la API de la tool **no** se llama.
- Timeout -> `ApprovalExpiredError`, la API no se llama.
- Revalidacion falla (token cambio) -> `ContextChangedError`, la API no se llama.
- `AgentGateEnforcer` como context manager (allow, deny, approval).
- Cancelacion mientras espera -> solicitud EXPIRED y `CancelledError` propagada.
- Envio a Telegram: `httpx` mockeado; verifica payload (chat ids de la allowlist, `callback_data`
  con UUID completo, teclado inline). Fallo de red no rompe el flujo.

**Definicion de Hecho M1:** todos los tests nuevos y los 184 previos pasan; `base_tool.py` ya no
contiene logica de decision propia; ASCII limpio.

---

### M2 - Auditoria append-only completa   [P0]

**Objetivo:** que el audit log sea inmutable y cuente la historia completa, incluida la aprobacion.

- Extiende `agentgate/audit/models.py` (`AgentGateAuditLog`) con columnas nullable:
  `event_type` (`DECISION` por defecto | `APPROVAL_RESOLVED` | `EXECUTION` | `MANIFEST_CHANGED`),
  `approver`, `decided_at`, `execution_result` (texto corto: `success` / `error:<Tipo>`),
  `investigation_id` (nullable, string).
- **Nunca UPDATE ni DELETE:** el desenlace de una aprobacion se registra como una **fila nueva**
  con el mismo `approval_id`. Agrega `AuditLogService.record_event(...)` para eso (memoria + BD con
  el mismo mecanismo no bloqueante de `record()`).
- Nueva migracion Alembic `d4e5f6a7b8c9_agentgate_audit_events.py` (down_revision
  `c3d4e5f6a7b8`): agrega las columnas y, **solo si el dialecto es PostgreSQL**, crea un trigger
  `BEFORE UPDATE OR DELETE` que hace `RAISE EXCEPTION 'agentgate_audit_logs is append-only'`.
  Downgrade quita trigger y columnas. Valida con
  `alembic upgrade c3d4e5f6a7b8:d4e5f6a7b8c9 --sql` (usa el ejecutable `alembic`, no
  `python -m alembic`: la carpeta `alembic/` del proyecto lo tapa).
- El PEP registra: la decision (ya existente), el desenlace (`APPROVAL_RESOLVED` con approver) y el
  resultado de ejecucion (`EXECUTION`, success/error) de las tools protegidas.
- Redaccion: `arguments` guardados en BD deben pasar por la misma redaccion que MASK (no persistas
  IPs internas en claro en el log).

Tests: filas nuevas por cada desenlace; el servicio no expone metodos update/delete; el SQL de la
migracion contiene el trigger en modo PostgreSQL y NO en SQLite; argumentos sensibles quedan
redactados en BD.

**DoD M2:** un ciclo completo (pedir -> aprobar -> ejecutar) deja 3 filas ordenadas
(`DECISION`, `APPROVAL_RESOLVED`, `EXECUTION`) enlazadas por `approval_id`.

---

### M3 - Bot de Telegram: recibir la aprobacion   [P0]

**Objetivo:** que el toque del boton resuelva la solicitud.

- `app/bot/telegram_bot.py`: nuevo `CallbackQueryHandler(on_approval_callback, pattern=r"^ag_(appr|rej)_[0-9a-f-]{36}$")`.
  - Valida `require_allowlist` (chat en `settings.telegram_allowlist_ids`); si no, responde
    "no autorizado" y **no** llama a la API.
  - Llama por HTTP a la API con `_headers()`:
    `POST {BACKEND}/agentgate/api/approve/{id}` o `/reject/{id}` pasando `approver=telegram:<chat_id>`.
    (Ojo: `API_BASE` termina en `/api/v1`; el dashboard esta en `/agentgate` sin ese prefijo.
    Deriva la base igual que hace `ui/pages/agentgate.py`.)
  - Edita el mensaje original: quita los botones y muestra "Aprobado por ... a las HH:MM UTC" (evita
    doble toque). Maneja "ya resuelto / expirado" con mensaje claro.
- `agentgate/dashboard/routes.py`: `approve`/`reject` aceptan `approver` opcional (query param,
  validado: `^[A-Za-z0-9:_-]{1,64}$`; por defecto `dashboard_operator`) y **rechazan con 409** si la
  solicitud ya no esta `PENDING`. Sigue exigiendo `X-API-Key`. Sigue escapando salida.
- Comandos opcionales (si el aviso los menciona): `/pendientes` lista solicitudes activas (llama a
  `GET /agentgate/api/pending`). Si no los implementas, no los menciones en el texto del aviso.

Tests (`tests/test_bot/test_agentgate_callbacks.py`, mockeando `httpx` y el objeto `Update`):
allowlist bloquea a extranos; aprobar/rechazar llama al endpoint correcto con el approver correcto;
doble toque -> mensaje "ya resuelto"; patron de `callback_data` invalido se ignora.
Tests de API: 409 en segunda resolucion; `approver` invalido -> 422.

**DoD M3:** prueba manual documentada en el reporte (ver seccion 5, Demo 4) con salida real del bot.
Si no puedes correr Telegram real, indicalo explicitamente y adjunta los tests como evidencia.

---

### M4 - Cola persistente en Redis   [P1]

**Objetivo:** que las solicitudes sobrevivan a un reinicio y sean visibles entre procesos.

- `agentgate/hitl/queue.py`: `get_default_approval_queue()` debe construir la cola con el cliente
  Redis del proyecto (`app.services.cache_service.get_redis_client()`; devuelve `None` si Redis no
  esta) **sin** que `agentgate` importe `app` de forma dura: acepta un `redis_client` inyectado y
  configuralo desde `app/main.py` en el `lifespan` (igual que se hizo con
  `audit_service.configure`).
- Escritura completa: persistir en Redis en **cada cambio de estado** (`approve`, `reject`, expiracion),
  no solo en `create_request` (hoy `approve()` solo muta memoria). Usa `setex` con el TTL restante.
- `wait_for_decision`: ademas del `asyncio.Event` local, hace polling corto (p. ej. cada 1 s) al
  estado en Redis para detectar resoluciones hechas por otro proceso.
- Redis caido = degradar a memoria con warning (nunca fallar la investigacion).

Tests con un fake Redis en memoria (clase dentro del test, sin dependencia nueva): persiste y lee;
`approve` actualiza Redis; una segunda instancia de `ApprovalQueue` (simula otro proceso) ve la
aprobacion; TTL expira; Redis que lanza excepcion no rompe la cola.

**DoD M4:** los tests de M1 siguen pasando con la cola respaldada por el fake Redis.

---

### M5 - Cerrar el fail-open sin agent_name   [P1]

- `ThreatIntelTool._arun`: si no llega `agent_name`:
  - en modo estricto (`AGENTGATE_STRICT` o `APP_ENV=production`) -> DENY fail-closed, auditado
    (`reason: "missing agent identity"`), lanza `PermissionDeniedError`;
  - en modo no estricto -> se comporta como hoy pero **emite un warning y registra evento de
    auditoria** `agent=unknown`, para que el bypass sea visible.
- Verifica que **todos** los caminos de produccion pasan `agent_name`: `_run_tools_parallel` ya lo
  hace; busca otros consumidores de tools (`grep -rn "_arun(" app`) y corrigelos o documentalos.
- No rompas los 137 tests de ThreatChain: los tests de tools que llaman `_arun` sin agente deben
  seguir pasando en modo no estricto (default en tests).

Tests: estricto sin agente -> DENY y una fila de auditoria; no estricto -> warning + fila `unknown`;
con agente -> sin cambios.

**DoD M5:** ninguna llamada a una tool en produccion puede omitir el log.

---

### M6 - Dashboard: filtros, editor de manifiestos y metricas   [P2]

- **Filtros** en `/agentgate/api/decisions` y `/decisions-html`: `agent`, `decision`
  (ALLOW/DENY/REQUIRE_APPROVAL/MASK), `tool`, `limit`. "Severidad" = `risk_level_default` del
  manifiesto del agente (agregalo al resultado). Valida los parametros (enum / regex), no interpoles
  nada sin escapar.
- **Editor de manifiestos:** `GET /agentgate/api/manifests/{agent}` y
  `PUT /agentgate/api/manifests/{agent}` (cuerpo = JSON del manifiesto).
  Reglas de seguridad **obligatorias**: `require_api_key`; `agent` debe cumplir `^[a-z0-9_]{1,50}$`
  (evita path traversal) y coincidir con el campo `agent` del cuerpo; validar con `AgentManifest`
  (Pydantic) y devolver 422 con los errores; escritura **atomica** (archivo temporal + `os.replace`)
  en `agentgate/manifests/`; incrementar `version`; recargar el PDP en memoria; auditar como
  `MANIFEST_CHANGED` (quien, agente, version). Nada de eliminar manifiestos por la UI.
  En la pagina HTML: textarea con el JSON + boton Guardar mostrando errores de validacion.
- **Metricas nuevas** en `/agentgate/api/metrics` (y en las tarjetas): llamadas por agente, top 5
  herramientas mas usadas, **tiempo promedio de respuesta humana** (aprobacion resuelta menos
  solicitud) y conteo de aprobados/rechazados/expirados.
- `ui/pages/agentgate.py` (Streamlit) sigue funcionando con los endpoints con auth (revisa que envia
  `X-API-Key`); no agregues funciones nuevas alli.

Tests: filtros (incluye valores invalidos), PUT valido/invalido/agent distinto/`../x`/sin key,
recarga efectiva del PDP tras el PUT (una tool antes DENY pasa a ALLOW), metricas con datos sembrados.

**DoD M6:** un manifiesto editado desde la API cambia decisiones reales sin reiniciar y deja rastro
de auditoria.

---

### M7 - Demo, docs y limpieza   [P2]

- `scripts/agentgate_demo.py` (ASCII): corre las 4 demos contra el PDP real con **tools falsas**
  (ninguna API real): ALLOW, DENY, MASK (IP interna -> `skipped`) y REQUIRE_APPROVAL
  (`fake_block_ip` decorada con `@protect`, aprobada por la cola desde una tarea asyncio que simula al
  humano). Imprime la cadena de auditoria resultante. Modo `--telegram` opcional para el aviso real.
- Demo real con herramientas existentes (sin inventar nada): baja el `rate_limit_per_min` de `shodan`
  en un manifiesto de prueba a 1 y muestra que la 2da consulta escala a aprobacion (Patron 2 del
  brief: "las primeras N se auto-aprueban, la N+1 pide aprobacion"). Deja el procedimiento en el
  README de la demo.
- Reescribe `AgentGate_Execution_Walkthrough.md`: elimina afirmaciones falsas, deja solo lo que
  esta implementado, con tabla "brief vs. implementado" y lista honesta de pendientes.
- Soporte YAML opcional (P3, solo si sobra tiempo): `load_manifest_file` acepta `.yaml/.yml` con
  `yaml.safe_load` (PyYAML ya esta instalado; usa `safe_load`, nunca `load`).
- `MITRE` no se agrega a manifiestos: `MitreAgent` usa RAG, no `ThreatIntelTool`. Documentalo.
  `threatcrowd` no lo usa ningun agente: no requiere manifiesto.

**DoD M7:** `python scripts/agentgate_demo.py` corre limpio y muestra las 4 decisiones y la cadena de
auditoria; el walkthrough coincide con el codigo.

---

## 4. Riesgos y trampas conocidas (leer)

1. **Timeout global.** El `wait_for` de 120 s de la investigacion cancela todo. Por eso
   `AGENTGATE_APPROVAL_WAIT_SECONDS` (90) < 120 y la cancelacion se maneja explicitamente (M1).
   Una aprobacion tardia despues de expirar debe devolver 409, nunca ejecutar nada.
2. **No re-evaluar el PDP tras aprobar.** Si vuelves a llamar `pdp.decide`, el rate limit o la regla
   `requires_approval` vuelven a escalar y entras en bucle. Ejecuta con la decision aprobada.
3. **Concurrencia.** Varias tools de un mismo agente pueden pedir aprobacion a la vez (gather). Cada
   solicitud es independiente; el dashboard y Telegram las muestran por separado.
4. **Estado en memoria por proceso.** Con varios workers de uvicorn la cola en memoria no se comparte;
   M4 lo mitiga con Redis. Documenta que en despliegue debe usarse 1 worker o Redis activo.
5. **Windows:** el servidor se lanza con `python -m app.main` (Selector event loop, ver cabecera de
   `app/main.py`). No cambies eso. `python -m alembic` no funciona desde la raiz; usa `alembic`.
6. **Secretos:** no imprimas ni loguees `TELEGRAM_BOT_TOKEN` ni `API_KEY`. Si la URL de la Bot API
   aparece en un log de error de `httpx`, redactala (mismo patron que `_redact_secrets` en
   `ThreatIntelTool`).
7. **XSS/escape:** cualquier valor nuevo que llegue al HTML del dashboard pasa por `_e()`.

---

## 5. Criterios de aceptacion finales (los revisa Claude)

1. `pytest -q` completo: los 184 previos + los nuevos, **0 fallos**.
2. ASCII limpio en todos los `.py`.
3. `alembic heads` = un solo head; `upgrade --sql` de las migraciones nuevas valido.
4. **Demo 4 de punta a punta** (o su equivalente simulado con evidencia si no hay Telegram real):
   - una tool que requiere aprobacion **se pausa**;
   - llega el aviso con botones (o su payload mockeado);
   - `Aprobar` -> la tool corre una vez y devuelve su resultado;
   - `Rechazar` / expirar -> la tool no corre y el agente recibe el error (y las demas tools del
     agente siguen);
   - la auditoria muestra `DECISION` -> `APPROVAL_RESOLVED` -> `EXECUTION` con el mismo `approval_id`.
5. Sin llamadas a APIs reales en tests; sin secretos en logs; sin `psycopg2`.
6. `AgentGate_Completion_Progress.md` completo y honesto, con la seccion "NO hecho" de cada hito.

Orden recomendado: **M1 -> M2 -> M3** (aprobacion humana usable) -> **M5** (cierre de seguridad) ->
**M4** -> **M6** -> **M7**. Detente tras cada hito para revision.
