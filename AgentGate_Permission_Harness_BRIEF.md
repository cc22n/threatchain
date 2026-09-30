# AgentGate - Capa de Permisos y Orquestacion para Agentes

> **Estado:** APROBADO
> **Fecha de aprobacion:** 2026-09-16
> **Tipo:** Proyecto de portafolio - infraestructura reusable (agent security)
> **Objetivo:** Componente independiente que responde "como se otorgan permisos
> a un agente, que permisos tiene, y como se decide" - de forma demostrable,
> no enterrada en la logica de un solo proyecto de dominio
> **Piloto de integracion:** ThreatChain (primero), extensible despues a
> LexChiapas y PerfilEvolutivo

---

## 1. Por que este proyecto y no otro agente mas

Ya existen tres piezas en el ecosistema que caen en el area de "agentes
autonomos" (ThreatChain, SOC Range, PerfilEvolutivo). La skill de orquestacion
y permisos ya esta presente en el trabajo, pero vive IMPLICITA dentro de la
logica de cada proyecto - nadie la ve a menos que lea todo el codigo.

AgentGate saca esa capa y la construye como componente aparte, reusable, que
se sienta entre cualquier agente (LangGraph u otro) y sus herramientas. No es
"otro proyecto de agentes" - es la infraestructura que hace que los agentes
existentes sean demostrablemente mas seguros y auditables.

**Por que esto importa para portafolio:** la seguridad de agentes (agent
security, tool permissioning, prompt injection, human-in-the-loop) es un area
en crecimiento activo en 2026, y casi ningun candidato junior construye esta
capa - la mayoria solo llama herramientas sin control de permisos. Es tambien
material perfecto para el articulo tecnico que falta en el portafolio.

---

## 2. El concepto central: el "gap de autorizacion"

Este es el eje conceptual de todo el proyecto (investigado y confirmado,
patron reconocido en la industria en 2026):

**OAuth scope responde:** "puede este agente llamar esta categoria de
herramienta?" - Es una decision que se toma UNA VEZ, al momento de dar acceso.

**Lo que NO responde:** "deberia ejecutarse ESTA llamada especifica, con
estos argumentos, en este momento?" - Eso es autorizacion a nivel de
INVOCACION, evaluada en tiempo real.

**Ejemplo concreto (ThreatChain):**
- Scope: "el agente RECON puede usar la tool de VirusTotal" (correcto, general)
- Invocacion: "el agente quiere consultar VirusTotal 400 veces en un minuto
  sobre IPs internas de la organizacion" (esto necesita otra capa de decision,
  aunque el scope ya lo permita)

AgentGate implementa ambas capas: permisos generales (que puede hacer un
agente) Y autorizacion de invocacion (deberia hacerse esto, ahora, asi).

---

## 3. Arquitectura: patron PEP / PDP

Patron estandar de la industria (usado por ejemplo en el Authorization Fabric
de Microsoft para agentes): separar QUIEN hace cumplir la politica de QUIEN
decide la politica.

```
[Agente (ThreatChain, LexChiapas, etc.)]
         |
         v  intenta llamar una herramienta
[PEP - Policy Enforcement Point]  <- vive como libreria/decorador
         |  envia la solicitud (agente, herramienta, argumentos, contexto)
         v
[PDP - Policy Decision Point]  <- servicio central (AgentGate)
         |
         v  evalua contra el manifiesto de permisos
   +-----+-----+-----+---------+
   |     |     |     |         |
 ALLOW DENY REQUIRE_  MASK
             APPROVAL
   |     |     |     |
   v     v     v     v
[Ejecuta] [Bloquea] [Pausa, pide  [Ejecuta pero
                      aprobacion   oculta/redacta
                      humana]      datos sensibles
                                   del resultado]
         |
         v
[AUDIT LOG - se registra la decision, siempre, sin importar el resultado]
```

**Los 4 tipos de decision (no solo si/no):**
- **ALLOW** - se ejecuta normal
- **DENY** - se bloquea, se registra por que
- **REQUIRE_APPROVAL** - se pausa y espera confirmacion humana (seccion 4)
- **MASK** - se ejecuta pero el resultado se filtra antes de llegar al agente
  (ej: el agente puede consultar una base de datos, pero ciertos campos
  sensibles se ocultan del resultado que recibe)

---

## 4. Aprobacion humana (Human-in-the-Loop)

Investigado el estado del arte 2026: hay varios patrones documentados, se
implementan los dos mas aplicables al proyecto:

**Patron 1: Pause-Resume Interrupt (el principal)**
- El agente propone una accion de riesgo (ej: bloquear una IP, enviar un
  reporte externo, escribir en produccion)
- El flujo se PAUSA (no se ejecuta nada)
- Se manda la solicitud a un humano (Telegram, ya se tiene experiencia con
  bots de Telegram en varios proyectos - reusar ese canal)
- El humano aprueba o rechaza
- Solo entonces se reanuda: se ejecuta o se cancela

**Patron 2: Dynamic Authorization Check**
- La politica se evalua en el momento exacto de la invocacion, no antes
- Permite reglas como "las primeras 10 consultas por hora se auto-aprueban,
  la numero 11 requiere aprobacion" (rate-based escalation)

**GOTCHA importante a manejar (encontrado en la investigacion):**
Cuando un agente se pausa esperando aprobacion, las credenciales o el contexto
que eran validos al momento de pausar NO estan garantizados a seguir validos
al momento de reanudar (ej: una API key roto, un token expirado, datos que
cambiaron mientras se esperaba). Validar de nuevo el contexto al reanudar,
no asumir que sigue igual.

**Nota para el futuro (no en el MVP):** el patron "MCP Elicitation" - aprobacion
interactiva nativa del protocolo MCP - es la version mas moderna de esto y
conecta directo con el trabajo ya hecho en SOC Range y la integracion de
WhatsApp de VetPOS (ambos ya usan MCP). Se deja como mejora Fase 5.

---

## 5. Manifiesto de permisos (por agente)

Configuracion externa (JSON/YAML), no hardcodeada - mismo principio que ya se
usa en los archivos ai_config.json de otros proyectos.

```json
{
  "agent": "recon_agent",
  "project": "threatchain",
  "tools_allowed": [
    {"name": "virustotal_lookup", "scope": "read_only", "rate_limit_per_min": 10},
    {"name": "abuseipdb_check", "scope": "read_only", "rate_limit_per_min": 10},
    {"name": "shodan_search", "scope": "read_only", "rate_limit_per_min": 5}
  ],
  "tools_denied": ["isolate_host", "block_ip", "send_external_report"],
  "requires_approval": ["isolate_host", "block_ip"],
  "risk_level_default": "low",
  "mask_fields": ["internal_ip_ranges"]
}
```

Cada agente (de cualquier proyecto conectado) tiene su propio manifiesto.
Cambiar permisos es editar el archivo, no tocar codigo del agente.

---

## 6. Audit Log (registro inmutable)

Reusa el patron que ya existe en SOC Agent (audit log append-only). Cada
decision del PDP se registra, sin excepcion, incluyendo las denegadas.

### Esquema (PostgreSQL):

**Tabla `permission_manifests`**
agent_id, project, tools_allowed (JSONB), tools_denied (JSONB),
requires_approval (JSONB), version, updated_at

**Tabla `decisions`**
id, agent_id, project, tool_name, arguments (JSONB, redactado si aplica),
decision (ALLOW/DENY/REQUIRE_APPROVAL/MASK), reason, requested_at,
decided_at, decided_by (sistema o humano), execution_result (nullable)

**Tabla `approval_requests`**
id, decision_id (FK), status (pending/approved/rejected/expired),
requested_context (JSONB), approver, approved_at, notes

Con esto se puede responder en entrevista: "aqui esta el log completo de
cada decision que tomo el agente, quien la aprobo, y por que" - eso es lo que
un evaluador tecnico de seguridad quiere ver.

---

## 7. Stack Tecnologico

| Capa | Tecnologia | Justificacion |
|---|---|---|
| Servicio central (PDP) | FastAPI (Python 3.11+) | Async, consistente con el resto del ecosistema |
| Base de datos | PostgreSQL (psycopg v3) | Manifiestos, decisiones, audit log |
| Cola de aprobaciones | Redis | Solicitudes pendientes, con TTL |
| Cliente/PEP | Libreria Python (decorador) | Se instala en cualquier proyecto (ThreatChain, etc.) |
| Canal de aprobacion | Bot de Telegram | Reusa experiencia ya construida en otros proyectos |
| Motor de politicas | Reglas deterministicas (no LLM) | Decision reproducible y auditable, no "se le pregunto al LLM" |
| Dashboard | FastAPI + HTMX + Tailwind | Ver decisiones, aprobar pendientes, editar manifiestos |

**Por que reglas deterministicas y no un LLM para decidir:**
Un sistema de permisos que dice "le pregunte a un LLM si estaba bien" no es
defendible ni auditable de la misma forma. El core del proyecto es
intencionalmente de sistemas/seguridad, no de prompting - eso es lo que lo
distingue del resto del portafolio (que es mayormente RAG y LLMs). Un
clasificador de riesgo con LLM se deja como experimento OPCIONAL en Fase 5,
nunca como la unica capa de decision.

### Notas de entorno Windows/PowerShell:
- Archivos Python: ASCII puro (sin acentos, tildes, emojis)
- Usar psycopg v3 (no psycopg2)
- `--break-system-packages` en pip installs donde sea necesario

---

## 8. Fases de Desarrollo

### Fase 1: Motor de decision (PEP/PDP core, standalone)
- FastAPI + PostgreSQL: modelos de manifiestos y decisiones
- Logica de evaluacion: dado (agente, herramienta, argumentos) -> decision
- Los 4 tipos de decision (ALLOW/DENY/REQUIRE_APPROVAL/MASK)
- Manifiestos en JSON, cargables sin tocar codigo
- Libreria cliente (decorador Python) que cualquier proyecto puede importar
- Tests: casos de cada tipo de decision
- **Entregable:** servicio que decide permisos, sin integrarse aun a nada

### Fase 2: Audit log + aprobacion humana
- Tabla de decisiones (todo se registra, incluido lo denegado)
- Flujo de aprobacion: Pause-Resume Interrupt
- Bot de Telegram para aprobar/rechazar solicitudes pendientes
- Manejo del gotcha de credenciales al reanudar (seccion 4)
- Redis para cola de pendientes con expiracion
- **Entregable:** aprobaciones humanas funcionando end-to-end

### Fase 3: Piloto de integracion - ThreatChain
- Retrofit: los agentes de ThreatChain (recon, malware, vuln, mitre, osint)
  enrutan sus llamadas a herramientas a traves de AgentGate
- Manifiestos reales por agente (recon = solo lectura, etc.)
- Las 17 APIs de threat intel quedan bajo control de permisos explicito
- Demostrar: una llamada bloqueada, una que requiere aprobacion, una con
  MASK de datos sensibles
- **Entregable:** ThreatChain corriendo con AgentGate como capa de permisos

### Fase 4: Dashboard
- Vista de decisiones recientes (permitidas, denegadas, pendientes)
- Editar manifiestos desde la interfaz
- Aprobar/rechazar sin depender solo de Telegram
- Metricas: cuantas llamadas por agente, tasa de denegacion, tiempo de
  aprobacion promedio
- **Entregable:** panel visible y demostrable para portafolio

### Fase 5 (opcional/futuro): extension
- Aplicar el mismo manifiesto a LexChiapas (formalizar sus guardrails
  actuales bajo AgentGate) y a PerfilEvolutivo (el limite de "el agente de
  perfil nunca responde al usuario" se vuelve una regla explicita en el
  manifiesto, no solo una instruccion de prompt)
- Patron MCP Elicitation (aprobacion nativa via protocolo MCP)
- Experimento: comparar patron supervisor (el actual en ThreatChain via
  LangGraph) contra un patron de enjambre/swarm descentralizado - medir
  diferencias, documentar hallazgos
- Clasificador de riesgo opcional con LLM barato, como capa ADICIONAL,
  nunca como reemplazo del motor de reglas
- Escribir el articulo tecnico sobre el diseno y lo aprendido

---

## 9. Evaluacion de Viabilidad

| Criterio | Score | Notas |
|---|---|---|
| Tiempo de desarrollo | 7/10 | 6-8 semanas para Fases 1-4, cada una usable |
| Complejidad tecnica | 6/10 | Patron conocido (PEP/PDP), la integracion es lo mas fino |
| Impacto en portafolio | 10/10 | Agent security/permisos es escala distinta al resto del portafolio |
| Costo | 10/10 | Todo local/gratis, sin dependencia de LLM para el core |

**Veredicto: APROBADO**

---

## 10. Por que esto es mas fuerte que un agente nuevo

- Responde directo la pregunta que hacen las vacantes: como se otorgan
  permisos, que permisos tienen, como deciden
- No es una demo aislada: hace mas seguro y auditable algo que YA existe
  (ThreatChain), lo cual es mas creible que un proyecto de juguete
- Es la unica pieza del portafolio centrada en sistemas/seguridad de agentes,
  no en RAG ni en llamar LLMs - diversifica la evidencia de skill
- Da material real para el articulo tecnico pendiente
- El patron PEP/PDP y el "gap de autorizacion" son terminologia que se puede
  nombrar con precision en una entrevista, lo cual distingue de quien solo
  dice "le puse un if antes de llamar la herramienta"

---

## 11. Recordatorios para el chat de ejecucion

- Windows/PowerShell: ASCII puro, psycopg v3, --break-system-packages
- El core (Fases 1-2) se construye standalone, SIN integrarlo a nada todavia
- Las decisiones son reglas deterministicas, no "preguntale al LLM" - eso es
  lo que distingue este proyecto del resto del portafolio
- Los 4 tipos de decision: ALLOW / DENY / REQUIRE_APPROVAL / MASK
- Gotcha: revalidar contexto/credenciales al reanudar tras una aprobacion,
  no asumir que sigue vigente
- ThreatChain es el piloto real de integracion (Fase 3), no un ejemplo de juguete
- Manifiestos de permisos en JSON externo, nunca hardcodeados
- Reusar el bot de Telegram ya construido en otros proyectos para las
  aprobaciones (mismo patron, otro caso de uso)
- Todo se audita: lo permitido y lo denegado, sin excepcion
- LexChiapas y PerfilEvolutivo quedan como extension futura (Fase 5), no
  para el MVP

---

*Documento generado desde el chat de planificacion de ideas.*
*Nombre sugerido del proyecto: AgentGate*
