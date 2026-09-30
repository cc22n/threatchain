# Plan de Implementación: AgentGate (Capa de Permisos y Orquestación para Agentes)

> **DOCUMENTO HISTORICO (primera ronda).** Este plan fue reemplazado por
> [`AgentGate_Completion_Plan.md`](AgentGate_Completion_Plan.md). Las casillas marcadas abajo
> reflejan lo que se declaro al cerrar la primera ronda, y varias eran inexactas (por ejemplo, el
> mecanismo de pausa y reanudacion, el canal de aprobacion por Telegram y la auditoria persistente
> no existian de punta a punta). Esas piezas se implementaron despues, en los hitos M1-M7 del plan
> de cierre. **El estado real y las limitaciones conocidas estan en
> [`AgentGate_Execution_Walkthrough.md`](AgentGate_Execution_Walkthrough.md).** No uses este
> archivo como fuente de estado.

> **Basado en:** [`AgentGate_Permission_Harness_BRIEF.md`](file:///c:/Users/coral/Desktop/ThreatChain/AgentGate_Permission_Harness_BRIEF.md)  
> **Análisis de Grafo (Graphify):** 792 nodos, 1463 aristas, 77 comunidades en ThreatChain.  
> **Patrón Arquitectónico:** PEP (Policy Enforcement Point) + PDP (Policy Decision Point) determinista.

---

## 1. Hallazgos del Análisis con Graphify (Topología de ThreatChain)

Al analizar el grafo AST y semántico generado por `graphify update .` (`graphify-out/GRAPH_REPORT.md`), se identificaron los puntos neurálgicos de la arquitectura actual:

1. **God Node Central (`ThreatIntelTool`):**
   - [`ThreatIntelTool`](file:///c:/Users/coral/Desktop/ThreatChain/app/tools/base_tool.py) cuenta con 41 dependencias directas en el grafo.
   - Las 17 herramientas de Threat Intelligence heredan de `ThreatIntelTool` y ejecutan sus llamadas a través del método `_arun()`.
2. **Cluster de Agentes (`BaseAgent` & Agentes Derivados):**
   - [`ReconAgent`](file:///c:/Users/coral/Desktop/ThreatChain/app/agents/recon_agent.py), [`MalwareAgent`](file:///c:/Users/coral/Desktop/ThreatChain/app/agents/malware_agent.py), [`VulnAgent`](file:///c:/Users/coral/Desktop/ThreatChain/app/agents/vuln_agent.py) y [`OsintAgent`](file:///c:/Users/coral/Desktop/ThreatChain/app/agents/osint_agent.py) consumen las herramientas concurrentemente mediante [`BaseAgent._run_tools_parallel`](file:///c:/Users/coral/Desktop/ThreatChain/app/agents/base_agent.py).
3. **Punto de Inyección Óptimo para el PEP (Policy Enforcement Point):**
   - Interceptar a nivel de `ThreatIntelTool._arun()` y/o `BaseAgent._run_tools_parallel` permite gobernar **el 100% de las 17 herramientas** con cero riesgo de bypass y sin modificar la lógica interna de cada una de las 17 APIs.

---

## 2. Decisiones de Diseño y Reglas Críticas

- **Motor 100% Determinista (No LLM):** Las decisiones (`ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `MASK`) se basan en manifiestos declarativos y reglas de políticas, garantizando auditoría reproducible.
- **Entorno Windows / PowerShell:** Código en ASCII puro, `psycopg` v3 async, y pip con `--break-system-packages` donde aplique.
- **Estructura Desacoplada:** El núcleo de AgentGate se construirá de forma modular (`agentgate/`), pudiendo funcionar como servicio independiente (PDP) y como librería cliente (PEP) integrable en cualquier proyecto de agentes.

---

## 3. Plan de Fases de Ejecución (estado declarado en la primera ronda; ver aviso al inicio)

### 📦 Fase 1: Motor Core PEP/PDP (Standalone) - [COMPLETADO]
**Objetivo:** Construir el servicio evaluador de políticas y el cliente/decorador de intercepción sin alterar aún ThreatChain.

- [x] **Modelos de Datos:**
  - Manifiesto de permisos por agente (`agent`, `project`, `tools_allowed`, `tools_denied`, `requires_approval`, `mask_rules`, `rate_limits`) en [`agentgate/models/manifest.py`](file:///c:/Users/coral/Desktop/ThreatChain/agentgate/models/manifest.py).
  - Modelos de decisión y veredictos en [`agentgate/models/decision.py`](file:///c:/Users/coral/Desktop/ThreatChain/agentgate/models/decision.py).
- [x] **PDP Engine (`agentgate.core.pdp`):**
  - Evaluador determinista de políticas en [`agentgate/core/evaluator.py`](file:///c:/Users/coral/Desktop/ThreatChain/agentgate/core/evaluator.py).
  - Servicio central PDP con soporte *fail-closed* en [`agentgate/core/pdp.py`](file:///c:/Users/coral/Desktop/ThreatChain/agentgate/core/pdp.py).
  - Soporte de los 4 veredictos: `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `MASK`.
- [x] **PEP Library (`agentgate.client.pep`):**
  - Decorador `@protect` y método `check_and_execute()` en [`agentgate/client/pep.py`](file:///c:/Users/coral/Desktop/ThreatChain/agentgate/client/pep.py).
- [x] **Pruebas Unitarias:** Cobertura de los 4 tipos de decisión en [`tests/test_agentgate/test_evaluator.py`](file:///c:/Users/coral/Desktop/ThreatChain/tests/test_agentgate/test_evaluator.py) y [`tests/test_agentgate/test_pep.py`](file:///c:/Users/coral/Desktop/ThreatChain/tests/test_agentgate/test_pep.py).

---

### 🛡️ Fase 2: Audit Log Inmutable y Human-in-the-Loop (HITL) - [COMPLETADO]
**Objetivo:** Registrar cada decisión y permitir aprobación interactiva de acciones sensibles.

- [x] **Audit Log Append-Only (`agentgate.audit`):**
  - Modelo SQLAlchemy inmutable en [`agentgate/audit/models.py`](file:///c:/Users/coral/Desktop/ThreatChain/agentgate/audit/models.py).
  - Servicio dual in-memory buffer + persistencia DB en [`agentgate/audit/service.py`](file:///c:/Users/coral/Desktop/ThreatChain/agentgate/audit/service.py).
- [x] **Mecanismo Pause-Resume Interrupt:**
  - Cola de solicitudes de aprobación con TTL (`ApprovalQueue`) en [`agentgate/hitl/queue.py`](file:///c:/Users/coral/Desktop/ThreatChain/agentgate/hitl/queue.py).
  - **Gotcha Resuelto:** Revalidación estricta de credenciales y contexto al reanudar tras la aprobación humana en [`agentgate/hitl/revalidator.py`](file:///c:/Users/coral/Desktop/ThreatChain/agentgate/hitl/revalidator.py).
- [x] **Canal de Aprobación Telegram:**
  - Formateador y teclado interactivo en [`agentgate/hitl/notifier.py`](file:///c:/Users/coral/Desktop/ThreatChain/agentgate/hitl/notifier.py).
- [x] **Pruebas Unitarias:** Cobertura completa en [`tests/test_agentgate/test_audit_log.py`](file:///c:/Users/coral/Desktop/ThreatChain/tests/test_agentgate/test_audit_log.py), [`test_approval_queue.py`](file:///c:/Users/coral/Desktop/ThreatChain/tests/test_agentgate/test_approval_queue.py), [`test_hitl_revalidation.py`](file:///c:/Users/coral/Desktop/ThreatChain/tests/test_agentgate/test_hitl_revalidation.py) y [`test_telegram_notifier.py`](file:///c:/Users/coral/Desktop/ThreatChain/tests/test_agentgate/test_telegram_notifier.py).

---

### 🔌 Fase 3: Piloto de Integración con ThreatChain - [COMPLETADO]
**Objetivo:** Enrutar las 17 herramientas de ThreatChain a través de AgentGate.

- [x] **Manifiestos de Permisos para ThreatChain ([`agentgate/manifests/`](file:///c:/Users/coral/Desktop/ThreatChain/agentgate/manifests/)):**
  - `recon_agent.json`: Solo lectura en APIs de reconocimiento, bloqueo de herramientas destructivas y enmascaramiento de IPs RFC 1918.
  - `malware_agent.json`: Permite feeds de hashes de malware; bloquea ejecución de binarios.
  - `vuln_agent.json`: Acceso a NVD y CISA KEV; restringe exploits activos.
  - `osint_agent.json`: Enmascaramiento obligatorio (`MASK`) de rangos de IPs internas corporativas (RFC 1918).
- [x] **Retrofit de ThreatChain:**
  - Intercepción PEP inyectada en [`app/tools/base_tool.py`](file:///c:/Users/coral/Desktop/ThreatChain/app/tools/base_tool.py) dentro de `ThreatIntelTool._arun()`.
  - Inyección de identidad del agente en [`app/agents/base_agent.py`](file:///c:/Users/coral/Desktop/ThreatChain/app/agents/base_agent.py).
- [x] **Casos de Demostración Práctica ([`tests/test_agentgate/test_threatchain_integration.py`](file:///c:/Users/coral/Desktop/ThreatChain/tests/test_agentgate/test_threatchain_integration.py)):**
  - Demo 1: Herramienta autorizada ejecutándose normalmente (`ALLOW`).
  - Demo 2: Acción fuera de alcance bloqueada y auditada (`DENY`).
  - Demo 3: Intento de consulta sobre IP interna con datos redactados (`MASK`).
  - Demo 4: Acción de riesgo pausada y aprobada (`REQUIRE_APPROVAL`).

---

### 📊 Fase 4: Dashboard Operativo y Métricas - [COMPLETADO]
**Objetivo:** Interfaz visual para auditoría en vivo y portafolio.

- [x] **Dashboard FastAPI + HTMX ([`agentgate/dashboard/`](file:///c:/Users/coral/Desktop/ThreatChain/agentgate/dashboard/)):**
  - Rutas y API endpoints en [`agentgate/dashboard/routes.py`](file:///c:/Users/coral/Desktop/ThreatChain/agentgate/dashboard/routes.py).
  - Templates SPA con Tailwind CSS y HTMX en [`agentgate/dashboard/templates.py`](file:///c:/Users/coral/Desktop/ThreatChain/agentgate/dashboard/templates.py).
  - Montado en FastAPI bajo `/agentgate` en [`app/main.py`](file:///c:/Users/coral/Desktop/ThreatChain/app/main.py).
- [x] **Portal Streamlit UI:**
  - Página nativa de gobernanza en [`ui/pages/agentgate.py`](file:///c:/Users/coral/Desktop/ThreatChain/ui/pages/agentgate.py) con métricas en vivo, cola HITL interactiva, feed de auditoría filtrable y visor de manifiestos.
- [x] **Script de Demostración E2E:**
  - La demo actual es [`scripts/agentgate_demo.py`](scripts/agentgate_demo.py) (la version de la primera ronda se elimino porque daba por bueno un flujo de aprobacion que no se reanudaba).

---

## 4. Plan de Verificación

Los resultados de verificacion vigentes (conteo de tests, migraciones, demo y lo que NO esta
verificado contra servicios reales) estan en `AgentGate_Execution_Walkthrough.md`. Los numeros que
este apartado mostraba en la primera ronda quedaron desactualizados.
