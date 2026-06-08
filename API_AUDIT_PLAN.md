# ThreatChain - API Audit & Fix Plan

## Resumen Ejecutivo

Auditoria completa de los 17 tools: que tipos de IOC acepta cada API,
como los llama cada agente, y que bugs producen errores en produccion.

---

## 1. Mapa IOC → API (fuente de verdad)

| API | IP | Domain | Hash | URL | CVE | Email | Notas |
|---|---|---|---|---|---|---|---|
| VirusTotal | OK | OK | OK | OK (base64) | - | - | Requiere `ioc_type` |
| AbuseIPDB | **SOLO IP** | NO | NO | NO | NO | NO | Endpoint `/check?ipAddress=` |
| Shodan | **SOLO IP** | NO | NO | NO | NO | NO | Endpoint `/shodan/host/{ip}` |
| URLScan | NO | NO | NO | **SOLO URL** | NO | NO | Necesita URL completa con scheme |
| SecurityTrails | NO | **SOLO Domain** | NO | NO | NO | NO | Endpoint `/domain/{domain}` |
| ThreatFox | OK | OK | OK | OK | NO | NO | `search_ioc` acepta cualquier IOC |
| AlienVault OTX | OK | OK | OK | OK | NO | NO | Requiere `ioc_type` |
| MalwareBazaar | NO | NO | **SOLO Hash** | NO | NO | NO | `get_info?hash=` |
| Hybrid Analysis | NO | NO | **SOLO Hash** | NO | NO | NO | `/search/hash` |
| GreyNoise | **SOLO IP** | NO | NO | NO | NO | NO | `/community/{ip}` |
| Pulsedive | OK | OK | NO | OK | NO | NO | `indicator=` acepta IP/domain/URL |
| ThreatCrowd | OK | OK | OK | NO | NO | OK | Requiere `ioc_type` |
| PhishTank | NO | NO | NO | **SOLO URL** | NO | NO | `/checkurl/` |
| HaveIBeenPwned | NO | NO | NO | NO | NO | **SOLO Email** | `/breachedaccount/{email}` |
| NVD (NIST) | NO | NO | NO | NO | **SOLO CVE** | NO | `?cveId=CVE-XXXX-XXXXX` |
| CISA KEV | NO | NO | NO | NO | **SOLO CVE** | NO | Busca en catalog descargado |
| ExploitDB | NO | NO | NO | NO | **SOLO CVE** | NO | Web scraping via XHR |

---

## 2. Bugs Criticos (producen errores HTTP en runtime)

### Bug #1 - ReconAgent llama AbuseIPDB con dominios, hashes y URLs

**Archivo:** `app/agents/recon_agent.py` lineas 44-54

**Problema:**
```python
# Actual - llama AbuseIPDB para CUALQUIER ioc_type
for tool_name, tool, kwargs in [
    ("virustotal", self.vt, {"ioc_type": ioc_type}),
    ("abuseipdb", self.abuseipdb, {}),   # <-- se ejecuta siempre
    ("shodan", self.shodan, {}),          # <-- se ejecuta siempre
]:
```

**Error que produce:** HTTP 422 de AbuseIPDB cuando `ioc_value` no es una IP.
```
{"errors": [{"detail": "The ip address must be a valid IP address."}]}
```

**Fix:**
```python
tools_to_run = [("virustotal", self.vt, {"ioc_type": ioc_type})]
if ioc_type == "ip":
    tools_to_run += [
        ("abuseipdb", self.abuseipdb, {}),
        ("shodan", self.shodan, {}),
    ]
if ioc_type in ("url", "domain"):
    tools_to_run.append(("urlscan", self.urlscan, {}))
if ioc_type == "domain":
    tools_to_run.append(("securitytrails", self.securitytrails, {}))
tools_to_run.append(("threatfox", self.threatfox, {}))
```

---

### Bug #2 - ReconAgent no tiene URLScan, SecurityTrails ni ThreatFox

**Archivo:** `app/agents/recon_agent.py`

**Problema:** Segun el plan, RECON debe usar 6 tools. Solo usa 3.
URLScan, SecurityTrails y ThreatFox estan implementados pero no instanciados
en el agente.

**Fix:** Instanciar los 3 tools que faltan en `__init__` y agregarlos al
`tools_to_run` segun el tipo de IOC (ver fix del Bug #1 arriba).

---

### Bug #3 - MalwareAgent llama MalwareBazaar y HybridAnalysis con URLs

**Archivo:** `app/agents/malware_agent.py` lineas 43-48

**Problema:** El Coordinator envia URLs al MalwareAgent. Dentro del agente
se llaman MalwareBazaar y Hybrid Analysis siempre, sin filtrar por ioc_type.
Ambas APIs solo aceptan hashes.

```python
# Actual - malwarebazaar y hybrid se llaman con cualquier ioc_type
for tool_name, tool, kwargs in [
    ("virustotal", self.vt, {"ioc_type": ioc_type}),
    ("malwarebazaar", self.malwarebazaar, {}),   # <-- falla con URL
    ("hybrid_analysis", self.hybrid, {}),         # <-- falla con URL
    ("alienvault_otx", self.otx, {"ioc_type": ioc_type}),
]:
```

**Error que produce:**
- MalwareBazaar: `{"query_status": "illegal_hash"}`
- Hybrid Analysis: HTTP 400

**Fix:**
```python
tools_to_run = [
    ("virustotal", self.vt, {"ioc_type": ioc_type}),
    ("alienvault_otx", self.otx, {"ioc_type": ioc_type}),
]
if ioc_type == "hash":
    tools_to_run += [
        ("malwarebazaar", self.malwarebazaar, {}),
        ("hybrid_analysis", self.hybrid, {}),
    ]
```

---

## 3. Issues Medios (no rompen pero degradan calidad)

### Issue #4 - OsintAgent no tiene tools para hashes

**Archivo:** `app/agents/osint_agent.py` lineas 49-68

**Problema:** `tool_map` no tiene entry para `"hash"`.
Cuando se llama con un hash, cae al default que solo usa OTX.

**Fix:** Agregar entry `"hash"` al mapa:
```python
"hash": [
    ("alienvault_otx", self.otx, {"ioc_type": ioc_type}),
    ("threatcrowd", self.threatcrowd, {"ioc_type": ioc_type}),
],
```

---

### Issue #5 - AlienVaultOTX default ioc_type="ip" en check_apis.py

**Archivo:** `scripts/check_apis.py` linea 96

**Problema:**
```python
("AlienVault OTX", AlienVaultOTXTool, IP, {}),  # no pasa ioc_type
```
Funciona porque el default es `"ip"` y se esta testeando con una IP,
pero es implicito y fragil.

**Fix:**
```python
("AlienVault OTX", AlienVaultOTXTool, IP, {"ioc_type": "ip"}),
```

---

### Issue #6 - ThreatCrowd sin ioc_type en check_apis.py

**Archivo:** `scripts/check_apis.py` linea 106

Mismo problema que Issue #5.

**Fix:**
```python
("ThreatCrowd", ThreatCrowdTool, IP, {"ioc_type": "ip"}),
```

---

### Issue #7 - ExploitDB usa web scraping no una API oficial

**Archivo:** `app/tools/exploitdb.py` lineas 12-18

**Problema:** `exploit-db.com/search` con `X-Requested-With: XMLHttpRequest`
es scraping de la interfaz web, no la API oficial. Puede romperse si
Exploit-DB cambia su frontend. No hay API key oficial disponible publicamente.

**Estado:** Aceptable para portfolio, documentar el riesgo.

---

### Issue #8 - ThreatCrowd puede estar offline

**Archivo:** `app/tools/threatcrowd.py`

**Problema:** `threatcrowd.org` ha tenido periodos de inestabilidad.
La API es mantenida por la comunidad y puede estar down.

**Estado:** El agente ya maneja errores parciales, pero puede
causar falsos "partial" en los resultados.

---

## 4. Plan de Fixes (orden de prioridad)

| # | Bug | Archivo | Prioridad | Esfuerzo |
|---|---|---|---|---|
| 1 | ReconAgent: filtrar AbuseIPDB/Shodan por ioc_type + agregar URLScan/SecurityTrails/ThreatFox | `recon_agent.py` | CRITICO | 30 min |
| 2 | MalwareAgent: filtrar MalwareBazaar/HybridAnalysis para hash only | `malware_agent.py` | CRITICO | 15 min |
| 3 | OsintAgent: agregar tool_map entry para hash | `osint_agent.py` | MEDIO | 10 min |
| 4 | check_apis.py: pasar ioc_type explicito a OTX y ThreatCrowd | `check_apis.py` | BAJO | 5 min |

---

## 5. Estado de Implementacion de Tools en Agentes

| Tool | Implementado | Agente Correcto | Filtro IOC Correcto |
|---|---|---|---|
| VirusTotal | SI | RECON + MALWARE | SI (pasa ioc_type) |
| AbuseIPDB | SI | RECON | **NO - falta filtro IP** |
| Shodan | SI | RECON | **NO - falta filtro IP** |
| URLScan | SI | **NO ESTA EN RECON** | N/A |
| SecurityTrails | SI | **NO ESTA EN RECON** | N/A |
| ThreatFox | SI | **NO ESTA EN RECON** | N/A |
| AlienVault OTX | SI | MALWARE + OSINT | SI |
| MalwareBazaar | SI | MALWARE | **NO - falta filtro hash** |
| Hybrid Analysis | SI | MALWARE | **NO - falta filtro hash** |
| GreyNoise | SI | OSINT | SI (solo IP en tool_map) |
| Pulsedive | SI | OSINT | SI |
| ThreatCrowd | SI | OSINT | SI (pasa ioc_type) |
| PhishTank | SI | OSINT | SI (solo URL en tool_map) |
| HaveIBeenPwned | SI | OSINT | SI (solo email en tool_map) |
| NVD | SI | VULN | SI |
| CISA KEV | SI | VULN | SI |
| ExploitDB | SI | VULN | SI |

**Bugs criticos:** 2 (AbuseIPDB/Shodan sin filtro, MalwareBazaar/HybridAnalysis sin filtro)
**Tools faltantes en agente:** 3 (URLScan, SecurityTrails, ThreatFox en RECON)

---

## 6. Detalle de Fixes a Implementar

### Fix 1: `app/agents/recon_agent.py` - Completo

```python
# En __init__ agregar:
self.urlscan = URLScanTool(redis_client=redis_client, db=db)
self.securitytrails = SecurityTrailsTool(redis_client=redis_client, db=db)
self.threatfox = ThreatFoxTool(redis_client=redis_client, db=db)

# En run() reemplazar el loop fijo por:
tools_to_run = [("virustotal", self.vt, {"ioc_type": ioc_type})]

if ioc_type == "ip":
    tools_to_run += [
        ("abuseipdb", self.abuseipdb, {}),
        ("shodan", self.shodan, {}),
    ]
elif ioc_type in ("url", "domain"):
    tools_to_run.append(("urlscan", self.urlscan, {}))

if ioc_type == "domain":
    tools_to_run.append(("securitytrails", self.securitytrails, {}))

tools_to_run.append(("threatfox", self.threatfox, {}))
```

### Fix 2: `app/agents/malware_agent.py` - Completo

```python
# Reemplazar el loop fijo por:
tools_to_run = [
    ("virustotal", self.vt, {"ioc_type": ioc_type}),
    ("alienvault_otx", self.otx, {"ioc_type": ioc_type}),
]
if ioc_type == "hash":
    tools_to_run += [
        ("malwarebazaar", self.malwarebazaar, {}),
        ("hybrid_analysis", self.hybrid, {}),
    ]
```

### Fix 3: `app/agents/osint_agent.py` - Agregar entry hash

```python
# En tool_map agregar:
"hash": [
    ("alienvault_otx", self.otx, {"ioc_type": ioc_type}),
    ("threatcrowd", self.threatcrowd, {"ioc_type": ioc_type}),
],
```

### Fix 4: `scripts/check_apis.py` - Explicitar ioc_type

```python
("AlienVault OTX", AlienVaultOTXTool, IP, {"ioc_type": "ip"}),
...
("ThreatCrowd", ThreatCrowdTool, IP, {"ioc_type": "ip"}),
```

---

*Generado: 2026-05-19*
