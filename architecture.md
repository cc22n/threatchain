# ThreatChain: Revisión de Arquitectura y Diseño de Software

## 1. Diagnóstico Arquitectónico General y Mapa de Capas

Actualmente, ThreatChain es un monolito asíncrono en FastAPI donde las capas lógicas carecen de límites estrictos. La lógica de orquestación, la infraestructura de datos y la inteligencia artificial están fuertemente acopladas.

### Mapa de Capas Actual
```text
[ API (FastAPI) ] -- POST /investigate
       |
[ Coordinator (LangGraph Fake) ] <-- Orquestación manual con asyncio.gather()
       |
[ Agents (Recon, Malware...) ] <-- Domain Layer (Lógica de Negocio/IA)
       |--> LLM (Async)
       |--> DB (AsyncSession compartida) [FILTRACIÓN DE INFRAESTRUCTURA]
       |--> Redis (Sync) [CUELLO DE BOTELLA]
       |
[ Tools (VirusTotal, Shodan...) ] <-- Infraestructura Externa
       |--> API Rest
       |--> Redis (Sync)
       |--> ChromaDB (Sync)
```

**Principales Problemas Estructurales:**
- **Filtración de Infraestructura en Dominio:** Los Agentes y Tools reciben directamente objetos `AsyncSession` y clientes de Redis. Los agentes gestionan sus propias escrituras a base de datos en lugar de retornar resultados para ser persistidos.
- **Modelos Anémicos e Inconsistentes:** Se utilizan modelos Pydantic en los endpoints de FastAPI (`app/schemas`), pero la comunicación interna entre herramientas, agentes y orquestador es mediante diccionarios en crudo (`dict`).

---

## 2. Deuda Técnica Estructural Crítica y Alta

### 🔴 CRÍTICA: Concurrencia Rota y Corrupción de Sesión (AsyncSession)
El `Coordinator` instancia una única `AsyncSession` (`self.db`) de SQLAlchemy y luego utiliza `asyncio.gather(*tasks)` para ejecutar múltiples agentes en paralelo (coroutines distintas). `AsyncSession` **no es thread-safe ni coroutine-safe**. El uso concurrente de una sola sesión provocará errores de estado y fallos silenciosos en la persistencia.

### 🔴 CRÍTICA: Bloqueo del Event Loop (IO Síncrono en Async)
Herramientas como `app/tools/base_tool.py` y `app/rag/knowledge_base.py` utilizan clientes síncronos de Redis (`redis_client.get`) y ChromaDB (`vs.similarity_search`). Al ser llamados dentro del event loop principal de FastAPI (vía los agentes), bloquean la hebra, destruyendo por completo los beneficios de la asincronía y degradando el rendimiento ante múltiples peticiones.

### 🟠 ALTA: LangGraph Subutilizado (StateGraph Falso)
El sistema utiliza LangGraph, pero solo define dos nodos artificiales (`run_agents` y `correlate`). La orquestación multi-agente real ocurre a través de un `asyncio.gather` estático basado en diccionarios (`IOC_AGENT_MAP`).
- **Problema:** LangGraph no modela el estado de los agentes. Si un agente falla, no hay *checkpointing* real ni posibilidad de reanudar el nodo fallido o realizar bucles de razonamiento (ciclos).
- **Código Muerto:** El `Coordinator` está configurado para usar `deepseek-reasoner`, pero nunca invoca al LLM para enrutamiento o toma de decisiones (solo utiliza un mapa estático).

### 🟠 ALTA: Ejecución Secuencial de Tools en Agentes
En `BaseAgent`, las herramientas se ejecutan en un bucle `for` secuencial (e.g. llamadas a VirusTotal, luego Shodan, luego URLScan). Dado que son I/O externas e independientes, deberían ejecutarse de forma concurrente con `asyncio.gather`.

### 🟡 MEDIA: Tablas Huérfanas y Persistencia Fragmentada
Las tablas `ApiToolResult` y `IocRelationship` existen en el esquema, pero los agentes empaquetan los datos raw en un JSON de `agent_results` y omiten usar estas tablas.

---

## 3. Recomendaciones de Diseño y Refactorización a Nivel Macro

1. **Desacoplamiento de Persistencia (Agentes Puros)**
   Los agentes no deben recibir la base de datos (`self.db`). Deben ser funciones o clases puras que tomen el estado (`InvestigationState`) y retornen un estado actualizado. La persistencia debe ser gestionada por un *Application Service* o usando un `AsyncPostgresSaver` nativo de LangGraph.

2. **Tipado Fuerte y Contratos (Pydantic en el Dominio)**
   Reemplazar el uso de diccionarios por modelos Pydantic internos.
   - `ToolResponse`: Modelo Pydantic para unificar respuestas de herramientas (wrappers).
   - `AgentFindings`: Modelo Pydantic devuelto por cada agente.
   Esto evitará errores de llaves faltantes en los prompts de los LLMs.

3. **Solución a Operaciones Síncronas**
   - Utilizar `redis.asyncio` para interactuar con la caché de forma asíncrona.
   - En ChromaDB, envolver las llamadas síncronas usando `asyncio.to_thread` o `run_in_executor` para evitar bloquear el event loop.

4. **Concurrencia en Herramientas (Tools)**
   Dentro de los agentes, cambiar el bucle `for tool in tools:` por una ejecución paralela real de llamadas a las APIs para reducir el tiempo total por investigación drásticamente.

---

## 4. Propuesta de Arquitectura Objetivo (Target Architecture)

La meta es evolucionar el orquestador hacia un verdadero **Grafo de Estados de LangGraph**, separar la capa de aplicación de la capa de inteligencia, y preparar el sistema para escalabilidad y colas de trabajo (Celery/Temporal).

### Topología del Grafo LangGraph Objetivo
```text
                  [ START ]
                      |
                < Router LLM > (Coordinator invoca deepseek-reasoner)
               /      |       \      \
       [Recon]  [Malware]  [Vuln]  [Osint]
             \        |       |      /
              \       |       |     /
               -----> | <-----      
                      |
                [ Correlation ]
                      |
                   [ Mitre ]
                      |
                  [ Report ]
                      |
                   [ END ]
```

### Arquitectura de Capas Recomendada

1. **API / Presentación (`app/api`):**
   - Endpoints de FastAPI. Retornan un HTTP 202 Inmediato.
   - Transforman payloads crudos a Pydantic.

2. **Capa de Servicios / Background (`app/services`):**
   - Gestiona el ciclo de vida de la investigación.
   - Pide al Checkpointer persistir el estado de la investigación a la base de datos (PostgreSQL/SQLAlchemy).
   - Inicia la ejecución de LangGraph asíncronamente o encola la tarea (Celery).

3. **Capa del Grafo (`app/graph` o `app/agents`):**
   - Módulos de LangGraph. El estado (`InvestigationState`) fluye como un Pydantic/TypedDict puro.
   - Nodos (Agentes): Solo procesan datos y llaman LLMs. Sin conexión a BD (pura lógica AI).
   - Conditional Edges (Router): Define qué nodos se ejecutan según el tipo de IOC, usando un LLM para razonar o lógica estática pura si se prefiere no usar LLM.

4. **Capa de Infraestructura (`app/tools` / `app/rag`):**
   - Integraciones con APIs externas (async).
   - Acceso a Redis (async) para rate-limit y caché.
   - Búsqueda vectorial local encapsulada (IO aislada en thread pools).

### Camino de Transición Inmediato (Quick Wins)
- Remover `self.db` de los Agentes, hacer que retornen `dict` / `Pydantic` y el coordinador (o servicio de FastAPI) guarde el estado.
- Cambiar Redis a `redis.asyncio` y encapsular ChromaDB con `asyncio.to_thread()`.
- Refactorizar LangGraph para que cada agente sea un nodo independiente (así se habilita la visualización gráfica de LangGraph Studio y la persistencia de estado).
