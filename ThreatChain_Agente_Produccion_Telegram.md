# ThreatChain - Agente en Produccion (Telegram + Deployment)

## Contexto y proposito:
ThreatChain ya esta disenado como un sistema multi-agente (7 agentes:
coordinator, recon, malware, vuln, MITRE, OSINT, report) que investiga IOCs
usando 17+ herramientas de threat intel, con LangChain/LangGraph.

Esta mejora lo convierte en un "AGENTE EN PRODUCCION" completo: accesible via
Telegram, desplegado, funcionando 24/7. Esto es lo que piden las vacantes de
Ingeniero de IA Junior ("agentes en produccion", "automatizaciones").

**IMPORTANTE:** ThreatChain ya existe/se esta construyendo. Revisar el estado
actual y agregar esta capa sin romper la logica de agentes ya hecha.

---

## Por que esto es un "agente en produccion" (lo que buscan las vacantes)

Las vacantes de IA Junior piden agentes en produccion. Eso significa un sistema
que: recibe entrada, RAZONA/decide que hacer, USA herramientas, ejecuta pasos
autonomamente, y entrega resultado, TODO desplegado y funcionando de verdad
(no un notebook).

ThreatChain ya tiene los pilares tecnicos (autonomia + tool use + orquestacion).
Lo que falta para que sea "produccion demostrable":
1. Una interfaz de entrada facil de probar (Telegram)
2. Deployment real (corriendo 24/7, accesible)
3. Manejo robusto para uso continuo

El patron final:
```
Usuario manda por Telegram: "investiga la IP 185.220.101.34"
        |
        v
ThreatChain se activa (autonomo)
        |
        v
Los 7 agentes trabajan (usan las 17 herramientas, razonan, correlacionan)
        |
        v
El usuario recibe el reporte completo de investigacion en Telegram
```

Esto es demostrable en vivo por un reclutador (le pasas el link del bot y lo
prueba). Muestra los 3 pilares: autonomia + herramientas + deployment.

---

## Parte 1: Interfaz de Telegram

### Comandos del bot:
- `/start` - bienvenida, explica que hace
- `/investigar <IOC>` - inicia investigacion (IP, dominio, hash, URL, CVE)
- Mensaje directo con un IOC - detecta el tipo y lo investiga
- `/estado <id>` - ver progreso de una investigacion en curso
- `/ayuda` - lista de comandos y ejemplos

### Flujo de la interaccion:
1. Usuario manda un IOC
2. El bot confirma: "Investigando 185.220.101.34, esto puede tardar ~30 seg..."
3. Mientras trabaja, opcionalmente manda actualizaciones de progreso
   ("Recon completado, analizando reputacion...")
4. Al terminar, envia el reporte:
   - Veredicto (MALICIOUS / SUSPICIOUS / BENIGN)
   - Severity score
   - Hallazgos clave (resumidos para Telegram)
   - Tecnicas MITRE detectadas
   - Opcion de recibir el reporte completo (PDF/texto largo)

### Consideraciones de Telegram:
- Los mensajes largos hay que partirlos (limite de Telegram ~4096 caracteres)
- Formato: usar el Markdown de Telegram (o texto plano), cuidar los asteriscos
  (mismo tema que LexChiapas: limpiar formato en backend)
- Investigaciones largas: correr en background (no bloquear el bot)
- Usar la abstraccion de mensajeria si se quiere multi-plataforma despues

### Manejo asincrono (importante):
- Una investigacion tarda ~15-30 seg (17 APIs + varios LLMs)
- NO bloquear el bot mientras investiga
- Usar Celery o tasks async: el bot recibe el IOC, encola la investigacion,
  responde cuando termina
- El usuario puede mandar varios IOCs sin esperar

---

## Parte 2: Deployment (lo que lo hace "produccion")

### Opciones de hosting (el agente recomienda segun presupuesto):

**Opcion A - VPS economico (recomendado para portafolio real):**
- Hetzner (CX22, ~4 EUR/mes) o similar - ya tienes experiencia con Hetzner
- Docker Compose con todos los servicios
- Corre 24/7, el bot siempre disponible
- Lo mas "profesional" para demostrar

**Opcion B - Free tier / bajo costo:**
- Railway, Render, Fly.io (tiers gratuitos o baratos)
- Mas facil de configurar, menos control
- Bueno para empezar

**Opcion C - Local con tunel (solo para demos):**
- Correr local + ngrok/cloudflare tunnel para exponer el webhook
- Solo para demostraciones puntuales, no 24/7 real

### Componentes a desplegar (Docker Compose):
- La app de ThreatChain (FastAPI)
- El bot de Telegram
- PostgreSQL (investigaciones, resultados)
- Redis (cache, cola de Celery)
- Celery workers (investigaciones en background)
- ChromaDB (RAG de MITRE) si aplica

### Requisitos de produccion:
- Variables de entorno / secretos bien manejados (API keys de las 17 fuentes,
  token del bot, keys de LLM) - nunca en el codigo
- Restart automatico si algo se cae (Docker restart policies)
- Logs centralizados (para debugging)
- Health checks
- Rate limiting (que un usuario no sature el bot)
- Manejo de errores robusto (si una API de threat intel falla, seguir)

---

## Parte 3: Ajustes para uso continuo (24/7)

### Cache y rate limits (critico con 17 APIs gratuitas):
- Muchas APIs de threat intel tienen limites diarios en free tier
- Cache agresivo: si ya se investigo un IOC hace poco, devolver el cacheado
- Contador de requests por API (no exceder free tiers)
- Fallback si una API se agota

### Seguridad:
- El bot es publico: cualquiera puede mandarle IOCs
- Rate limiting por usuario (ej: max X investigaciones por hora)
- Opcional: lista de usuarios permitidos (allowlist) si se quiere privado
- No exponer las API keys ni la logica interna en las respuestas
- Validar/sanitizar los IOCs de entrada (no inyeccion)

### Observabilidad (para el portafolio):
- Log de cuantas investigaciones se hacen
- IOCs mas consultados
- Tiempo promedio de investigacion
- Que APIs se usan mas / cuales fallan
- Esto da numeros para la entrevista ("el agente ha procesado X
  investigaciones, tarda en promedio Y segundos")

---

## Fases de Desarrollo

### Fase 1: Bot de Telegram basico
- Conectar bot de Telegram (python-telegram-bot)
- Comando /investigar que dispara ThreatChain
- Recibir el resultado y enviarlo (partiendo mensajes largos)
- Probar local con tunel

### Fase 2: Async + background
- Celery para investigaciones en background
- El bot no se bloquea
- Actualizaciones de progreso
- Multiples investigaciones simultaneas

### Fase 3: Deployment
- Docker Compose completo
- Desplegar en VPS (Hetzner) o free tier
- Variables de entorno / secretos
- Restart automatico, health checks
- Bot corriendo 24/7

### Fase 4: Robustez para produccion
- Rate limiting por usuario
- Cache agresivo de IOCs
- Manejo de limites de las 17 APIs
- Logs y observabilidad
- Metricas para el portafolio

### Fase 5: Pulido para portafolio
- README con demo (GIF del bot investigando)
- Link al bot para que reclutadores lo prueben
- Documentacion de la arquitectura de agentes
- Metricas de uso reales

---

## Evaluacion de Viabilidad

| Criterio | Score | Notas |
|---|---|---|
| Tiempo de desarrollo | 7/10 | 4-6 semanas (la base de agentes ya existe) |
| Complejidad tecnica | 5/10 | Telegram + async + deployment sobre lo ya hecho |
| Impacto en portafolio | 10/10 | "Agente en produccion" es lo que piden las vacantes |
| Costo | 8/10 | VPS ~4 EUR/mes o free tier; APIs gratis; LLMs baratos |

**Veredicto: APROBADO**

---

## Por que esto te consigue entrevistas

- "Agente en produccion" es de lo mas pedido para IA Junior
- Es DEMOSTRABLE en vivo: el reclutador manda un IOC al bot y ve la magia
- Muestra los 3 pilares: autonomia (los agentes deciden), tool use (17 APIs),
  deployment (corriendo 24/7)
- Combina IA + ciberseguridad + DevOps (deployment) = perfil completo
- Tienes numeros: investigaciones procesadas, tiempos, APIs usadas
- No es un notebook ni una demo local: es un sistema real funcionando

---

## Recordatorios para el chat de ejecucion:
- Windows/PowerShell para desarrollo: ASCII puro, psycopg v3, --break-system-packages
- ThreatChain ya existe: revisar estado actual, agregar sin romper
- El deployment es lo que lo hace "produccion", no saltarselo
- Async obligatorio: investigaciones tardan, no bloquear el bot
- Cache agresivo por los limites de las 17 APIs gratuitas
- Secretos en variables de entorno, NUNCA en codigo
- Cuidar formato de mensajes de Telegram (asteriscos, limite de longitud)
- Rate limiting por usuario (el bot es publico)
- Observabilidad = numeros para la entrevista
- README con demo y link al bot para que reclutadores lo prueben
- Reusar la capa de abstraccion de mensajeria si se quiere WhatsApp despues
