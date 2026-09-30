# AgentGate en ThreatChain - Estado real

> Última revisión: 2026-09-30. Este documento describe **lo que existe en el código y cómo se verificó**,
> y lista sin adornos lo que falta o solo está probado con mocks.
> Fuente de requisitos: `AgentGate_Permission_Harness_BRIEF.md`.
> Plan de cierre ejecutado: `AgentGate_Completion_Plan.md` (hitos M1-M7, reporte en `AgentGate_Completion_Progress.md`).

## 1. Qué es y cómo funciona

AgentGate es una capa de permisos determinista (sin LLM) entre los agentes de ThreatChain y sus 17 herramientas
de threat intel. Cada llamada a una herramienta pasa por un PEP (`agentgate/client/pep.py`) que consulta un PDP
(`agentgate/core/pdp.py`) y obtiene una de cuatro decisiones: `ALLOW`, `DENY`, `MASK` o `REQUIRE_APPROVAL`.

```
BaseAgent._run_tools_parallel  (inyecta agent_name + investigation_id)
        |
ThreatIntelTool._arun  ->  PEP.authorize  ->  PDP.decide  (manifiesto del agente + limite por minuto)
                                                  |
        +-----------------+-----------------+-----+-----------+
      ALLOW             DENY              MASK        REQUIRE_APPROVAL
   ejecuta         PermissionDenied   IOC sensible:   1. crea solicitud (cola, TTL = espera real)
                                      no se llama     2. avisa por Telegram (HTTP directo, botones)
                                      a la API        3. PAUSA la herramienta (await)
                                                      4. humano aprueba/rechaza (Telegram o dashboard)
                                                      5. aprobado -> revalida contexto -> ejecuta UNA vez
                                                         rechazado / expirado / contexto cambiado -> error
```

Auditoría: cada decisión se registra en memoria y en `agentgate_audit_logs` (PostgreSQL). Un ciclo con aprobación
deja filas enlazadas por `approval_id`: `DECISION` -> `APPROVAL_RESOLVED` -> `EXECUTION`.

## 2. Brief vs. implementado

| Requisito del brief | Estado | Detalle |
|---|---|---|
| 4 decisiones deterministas | Hecho | `core/evaluator.py`. Sin manifiesto para un agente: `DENY` (fail-closed). |
| Manifiestos externos por agente | Hecho | JSON y YAML (`yaml.safe_load`). Dos archivos para el mismo agente lanzan `ValueError` al cargar. |
| Librería cliente (decorador) | Hecho | `@protect` y `AgentGateEnforcer`. El wrapper **síncrono** no puede esperar: ante `REQUIRE_APPROVAL` lanza `ApprovalRequiredError`. |
| Autorización a nivel de invocación | Hecho | Límite por minuto por (agente, herramienta): pasarse escala a `REQUIRE_APPROVAL` (Patrón 2 del brief). |
| MASK | Hecho | IP privada (RFC 1918/loopback) como IOC: la herramienta devuelve `skipped: true`, no llama a la API ni cachea. En argumentos secundarios se redacta a `[REDACTED_INTERNAL_IP]`. |
| Pausa y reanudación (HITL) | Hecho, probado con mocks | Tests y demo con aprobación simulada. **No probado con Telegram real.** |
| Revalidar contexto al reanudar | Hecho | `ContextRevalidator` compara token/api_key/session/target_hash del snapshot con el contexto actual. |
| Canal Telegram | Hecho, probado con mocks | La API envía el aviso; el proceso `bot` recibe el botón y llama a la API. Solo chats de la allowlist. |
| Cola con TTL en Redis | Hecho, probado con un Redis falso | Si Redis cae, degrada a memoria con warning. |
| Audit log inmutable | Hecho, trigger sin ejecutar en PG real | Solo se insertan filas. La migración `d4e5f6a7b8c9` crea un trigger de PostgreSQL que bloquea UPDATE/DELETE; se validó el SQL generado, **no se ejecutó contra un PostgreSQL real**. Argumentos con IPs privadas se redactan antes de guardar. |
| Dashboard | Hecho, con salvedad | Filtros (agente, decisión, herramienta, límite), severidad = `risk_level_default` del agente, editor de manifiestos con recarga en caliente, métricas (por agente, top 5 herramientas, tiempo medio de respuesta humana). Los endpoints de datos y acciones exigen `X-API-Key` (solo la página HTML estática es pública) y toda salida se escapa. **Lee del buffer en memoria (últimas 1000 decisiones): se pierde al reiniciar.** |
| PDP como servicio central separado | **No hecho** | El PDP es una librería dentro del proceso de ThreatChain. Solo el router del dashboard se monta en su API. |
| Tablas `permission_manifests` y `approval_requests` en PostgreSQL | **No hecho** | Manifiestos en archivos; solicitudes en memoria/Redis. Solo existe la tabla de auditoría. |
| Fase 5 (MCP Elicitation, LexChiapas, PerfilEvolutivo, clasificador LLM opcional, artículo) | **No hecho** | Era opcional. |

## 3. Manifiestos reales (`agentgate/manifests/`)

| Agente | Herramientas permitidas (límite/min) | Denegadas | Requieren aprobación | Enmascara IP privada |
|---|---|---|---|---|
| `recon_agent` | virustotal 15, abuseipdb 15, shodan 10, urlscan 10, securitytrails 10, threatfox 20 | isolate_host, wipe_disk, send_external_report, exploit_target | block_ip, quarantine_endpoint | Sí |
| `malware_agent` | virustotal 15, alienvault_otx 15, malwarebazaar 20, hybrid_analysis 10 | execute_binary, delete_sample, disable_edr | submit_to_sandbox_live | No |
| `osint_agent` | greynoise 20, alienvault_otx 20, pulsedive 15, phishtank 20, haveibeenpwned 10 | dump_database, scrape_internal_directory | notify_compromised_user | Sí |
| `vuln_agent` | nvd 30, cisa_kev 30, exploitdb 15 | exploit_target, metasploit_run, patch_system | trigger_vulnerability_scan | No |

Notas de alcance:
- **Ninguna herramienta real de ThreatChain aparece en `requires_approval`**: los nombres de esa columna (`block_ip`,
  etc.) no existen como herramientas. Hoy el único camino real hacia una aprobación humana es **superar el límite por
  minuto** de una herramienta permitida.
- El brief pedía 10/min para VirusTotal en RECON; el manifiesto usa 15.
- `MitreAgent` usa RAG interno (no `ThreatIntelTool`), por eso no lleva manifiesto.
- `threatcrowd` existe como herramienta pero ningún agente la usa; si se usara, sería denegada (no está en ningún manifiesto).
- Ejemplo de manifiesto para pruebas: `agentgate/examples/sample_recon.json` (fuera de `manifests/` a propósito: antes,
  al compartir nombre de agente con `recon_agent.json`, lo sobrescribía).

## 4. Configuración

| Variable | Default | Efecto |
|---|---|---|
| `AGENTGATE_APPROVAL_WAIT_SECONDS` | 90 | Cuánto espera una herramienta pausada; también fija el vencimiento mostrado al humano. Se avisa en el log si es >= `INVESTIGATION_TIMEOUT_SECONDS` (120). |
| `AGENTGATE_TELEGRAM_NOTIFY` | true | Envía el aviso a los chats de `TELEGRAM_ALLOWLIST`. Sin token/allowlist se omite con warning; la aprobación sigue posible desde el dashboard. |
| `AGENTGATE_STRICT` | false | Sin `agent_name`: `true` (o `APP_ENV=production`) deniega y audita; `false` solo avisa y audita como `agent=unknown`. |

## 5. Limitaciones conocidas

- **Reiniciar la API descarta las llamadas pausadas.** La solicitud puede seguir en Redis, pero la corrutina que esperaba
  no se reanuda; esa herramienta falla y el agente continúa con las demás.
- **El límite por minuto vive en la memoria de cada proceso.** Con varios workers cada uno cuenta por separado.
- **Una ráfaga que supera el límite genera una solicitud y un mensaje de Telegram por cada llamada** (no se agrupan).
- **`approver` lo declara quien llama a la API** (query param validado por formato, no autenticado). Basta la API key
  compartida; el bot pone `telegram:<chat_id>` pero la API no lo verifica.
- **Solo las llamadas que pasaron por aprobación generan fila `EXECUTION`.** Las llamadas `ALLOW` normales solo dejan `DECISION`.
- El dashboard y las métricas leen el buffer en memoria, no la tabla de PostgreSQL.
- La cola guarda `arguments` y `context_snapshot` sin redactar (en memoria y Redis); solo el audit log redacta.
- Sin `agent_name` y fuera de modo estricto, la herramienta se ejecuta (queda avisada y auditada como `unknown`).
- `scripts/check_apis.py` ahora se identifica como `healthcheck_agent` (manifiesto en memoria, solo en ese proceso) para
  poder correr también en modo estricto.

## 6. Cómo se verificó (2026-09-30)

Ejecutado:
- `python -m pytest -q` -> **235 passed** (137 originales de ThreatChain + AgentGate y endurecimiento).
- Todos los `.py` de `agentgate/`, `app/`, `tests/`, `ui/`, `alembic/`, `scripts/` son ASCII.
- `alembic heads` -> un solo head, `d4e5f6a7b8c9`; `alembic upgrade c3d4e5f6a7b8:d4e5f6a7b8c9 --sql` genera columnas, índices y trigger.
- `python scripts/agentgate_demo.py` -> código 0. Cubre ALLOW, DENY, MASK, REQUIRE_APPROVAL con pausa y reanudación
  (aprobación simulada por una tarea), escalada por límite y la cadena de auditoría. Sin llamadas de red.

**No verificado** (solo mocks, SQLite en memoria, un Redis falso o SQL sin ejecutar):
- Telegram real (envío del aviso, botones, edición del mensaje).
- Redis real, incluido el sondeo entre procesos.
- El trigger contra un PostgreSQL real.
- Una investigación completa de punta a punta con una aprobación real.

Antes de darlo por listo hace falta esa prueba de humo: `alembic upgrade head`, arrancar con `python -m app.main` y
el bot, bajar el límite de `shodan` a 1 en un manifiesto de prueba, lanzar una investigación de una IP pública,
aprobar desde Telegram y comprobar las filas de `agentgate_audit_logs`.

## 7. Demo

```powershell
& "C:\Users\coral\anaconda3\envs\ThreatChain\python.exe" scripts/agentgate_demo.py
```

Pasos: (1) ALLOW, (2) DENY, (3) MASK con IP privada, (4) REQUIRE_APPROVAL con `@protect` sobre una herramienta falsa
que se pausa y se reanuda tras la aprobación, (5) escalada por límite por minuto, (6) cadena de auditoría.
