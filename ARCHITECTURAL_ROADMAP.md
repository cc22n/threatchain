# ThreatChain - Architectural Roadmap

Tres mejoras arquitecturales identificadas durante el code-audit de 2026-06-12.
No son bugs — el sistema funciona sin ellas — pero son necesarias antes de
cualquier despliegue real o demostracion con carga.

---

## Item 1 — Reset automatico de rate limit diario

### Problema

`RateLimiter.reset_daily_counters()` esta implementado correctamente en
`app/services/rate_limiter.py:68` pero nunca se llama de forma automatica.

Efecto: despues del primer dia de uso, `requests_today` sigue creciendo y
nunca vuelve a 0. El sistema reporta "rate limit reached" para todas las
APIs al dia siguiente aunque no se haya hecho ninguna llamada ese dia.

### Solucion: APScheduler como lifespan event en main.py

APScheduler ya esta disponible via `slowapi` (que lo incluye como dependencia).
Alternativa mas limpia: instalar `apscheduler` directamente.

**Instalacion** — agregar a `requirements.txt`:
```
apscheduler==3.10.4
```

**Implementacion en `app/main.py`:**

```python
from contextlib import asynccontextmanager
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from app.database import AsyncSessionLocal
from app.services.rate_limiter import RateLimiter

scheduler = AsyncIOScheduler()

async def _reset_rate_limits():
    async with AsyncSessionLocal() as db:
        limiter = RateLimiter(db)
        n = await limiter.reset_daily_counters()
    # logger disponible a nivel modulo

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: lanzar scheduler
    scheduler.add_job(
        _reset_rate_limits,
        trigger=CronTrigger(hour=0, minute=0, timezone="UTC"),
        id="reset_rate_limits",
        replace_existing=True,
        misfire_grace_time=3600,   # si el server estuvo down a medianoche, ejecutar igual
    )
    scheduler.start()
    yield
    # Shutdown: detener scheduler limpiamente
    scheduler.shutdown(wait=False)

app = FastAPI(title="ThreatChain", version="0.3.0", lifespan=lifespan)
```

### Comportamiento esperado

- Cada dia a las 00:00 UTC, `requests_today` se resetea a 0 en todos los registros de `api_configs`
- Si el servidor estuvo caido a medianoche, APScheduler ejecuta el job en cuanto levanta (dentro de `misfire_grace_time`)
- El endpoint `GET /api/v1/health/apis` siempre muestra contadores del dia actual

### Alternativa sin dependencia nueva

Si se prefiere no agregar APScheduler, se puede hacer un reset lazy: al inicio
de cada `check_and_increment`, comparar `last_reset_date` con la fecha actual y
resetear si difieren. Requiere agregar una columna `last_reset_date DATE` a
`api_configs` y una migracion.

```python
# En RateLimiter.check_and_increment(), antes del UPDATE:
from datetime import date
if config.last_reset_date != date.today():
    await self.db.execute(
        update(ApiConfig)
        .where(ApiConfig.api_name == api_name)
        .values(requests_today=0, last_reset_date=date.today())
    )
```

Esta opcion es mas robusta frente a reinicios pero requiere la migracion.

### Archivos a modificar

| Archivo | Cambio |
|---|---|
| `app/main.py` | Agregar `lifespan`, instanciar `AsyncIOScheduler`, registrar job |
| `requirements.txt` | Agregar `apscheduler==3.10.4` |
| `app/models/config.py` | (solo si se elige la alternativa lazy) Columna `last_reset_date` |
| `alembic/versions/` | (solo si se elige la alternativa lazy) Migracion para nueva columna |

---

## Item 2 — POST /investigate debe retornar 202 inmediato

### Problema

El endpoint actual en `app/api/investigations.py:22`:

```python
@router.post("/investigate", response_model=InvestigationResponse, status_code=201)
async def start_investigation(payload: InvestigationCreate, db: AsyncSession = Depends(get_db)):
    investigation = await run_investigation(payload.ioc_value, ioc_type, db, redis)
    return investigation
```

`run_investigation` no retorna hasta que los 7 agentes terminan (~30-120 segundos).
El cliente HTTP queda bloqueado todo ese tiempo. Con un timeout de proxy/nginx
de 60s, las investigaciones largas generan errores 504 en el cliente aunque
el servidor este trabajando correctamente.

El endpoint `/investigate/batch` ya usa el patron correcto (202 + background task).

### Solucion: crear la fila y retornar 202, ejecutar en background

La clave es separar la creacion de la fila `Investigation` (sincrona, rapida)
de la ejecucion del pipeline (asincrona, lenta).

**Nueva funcion en `app/services/investigation_service.py`:**

```python
async def create_investigation(
    ioc_value: str,
    ioc_type: str,
    db: AsyncSession,
) -> Investigation:
    """Crea la fila en DB y retorna inmediatamente. No ejecuta agentes."""
    investigation = Investigation(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        status="pending",
    )
    db.add(investigation)
    await db.commit()
    await db.refresh(investigation)
    return investigation


async def run_investigation_background(
    investigation_id: uuid.UUID,
    ioc_value: str,
    ioc_type: str,
    redis_client=None,
) -> None:
    """Ejecuta el pipeline completo en background. Abre su propia sesion de DB."""
    from app.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        await run_investigation(ioc_value, ioc_type, db, redis_client, investigation_id)
```

**`run_investigation` necesita aceptar `investigation_id` opcional:**

```python
async def run_investigation(
    ioc_value: str,
    ioc_type: str | None,
    db: AsyncSession,
    redis_client=None,
    investigation_id: uuid.UUID | None = None,   # <-- nuevo parametro
) -> Investigation:
    resolved_type = ioc_type or classifier.classify(ioc_value)["type"]

    if investigation_id is None:
        # Flujo original (batch lo sigue usando asi)
        investigation = Investigation(ioc_value=ioc_value, ioc_type=resolved_type, status="running")
        db.add(investigation)
        await db.commit()
        await db.refresh(investigation)
    else:
        # Fila ya existe — recuperarla y marcarla como running
        result = await db.execute(select(Investigation).where(Investigation.id == investigation_id))
        investigation = result.scalar_one()
        investigation.status = "running"
        await db.commit()

    # ... resto igual ...
```

**Endpoint actualizado en `app/api/investigations.py`:**

```python
@router.post("/investigate", status_code=202,
             dependencies=[Depends(require_api_key)])
async def start_investigation(
    payload: InvestigationCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    ioc_type = payload.ioc_type or _classifier.classify(payload.ioc_value)["type"]
    if ioc_type == "unknown":
        raise HTTPException(status_code=422, detail="Could not classify IOC type")

    # Crear fila en DB de forma sincrona (rapido, <10ms)
    investigation = await create_investigation(payload.ioc_value, ioc_type, db)

    # Lanzar pipeline en background (el cliente no espera)
    redis = get_redis_client()
    background_tasks.add_task(
        run_investigation_background,
        investigation.id,
        payload.ioc_value,
        ioc_type,
        redis,
    )

    return {
        "investigation_id": str(investigation.id),
        "status": "pending",
        "message": "Investigation started. Use GET /investigations/{id} to poll or connect to WS /ws/investigation/{id} for real-time updates.",
        "ws_url": f"/ws/investigation/{investigation.id}",
    }
```

### Flujo completo con este cambio

```
Cliente                    API                          Background
  |                         |                               |
  |-- POST /investigate ---->|                               |
  |                         |-- INSERT investigation ------->|
  |                         |   (status=pending, <10ms)     |
  |<---- 202 + inv_id -------|                               |
  |                         |-- add_task(run_pipeline) ----->|
  |                         |                               |-- UPDATE status=running
  |-- WS /ws/{id} --------->|                               |-- run agents (30-120s)
  |<-- {status: running} ---|                               |-- UPDATE status=completed
  |<-- {status: running} ---|                               |
  |<-- {status: completed} -|<------------------------------|
```

### Impacto en el WebSocket

El WebSocket (`app/api/ws.py`) ya hace polling de `Investigation.status` cada 2
segundos. Con este cambio emite `status=pending` hasta que el background task
lo actualice a `running`, y luego `completed`. No requiere cambios en ws.py.

### Response schema actualizado

Hay que agregar un schema de respuesta 202 en `app/schemas/investigation.py`:

```python
class InvestigationAccepted(BaseModel):
    investigation_id: uuid.UUID
    status: str
    message: str
    ws_url: str
```

### Archivos a modificar

| Archivo | Cambio |
|---|---|
| `app/services/investigation_service.py` | Agregar `create_investigation()`, `run_investigation_background()`, parametro `investigation_id` en `run_investigation()` |
| `app/api/investigations.py` | `POST /investigate` pasa a 202, usa `BackgroundTasks` |
| `app/schemas/investigation.py` | Agregar `InvestigationAccepted` |

---

## Item 3 — Test para el path de error de H2 (status="failed" tras rollback)

### Problema

El fix H2 en `investigation_service.py` corrigio un bug critico: cuando el
Coordinator lanza una excepcion, el objeto `Investigation` queda detachado
despues del `rollback()` y el UPDATE de `status="failed"` no llegaba a la DB.

El fix re-fetcha el objeto por PK, pero no hay ninguna prueba que verifique
que el comportamiento es correcto. Si alguien rompe ese codigo en el futuro,
ningun test fallara.

### Test a crear: `tests/test_services/test_investigation_service.py`

El test debe:
1. Crear una fila `Investigation` real en SQLite in-memory (usando el fixture `db_session`)
2. Mockear `Coordinator.investigate` para que lance una excepcion
3. Llamar a `run_investigation`
4. Re-fetch el objeto desde la DB (no confiar en el objeto Python retornado)
5. Verificar que `status == "failed"`

```python
# tests/test_services/test_investigation_service.py
import pytest
from unittest.mock import AsyncMock, patch
from sqlalchemy import select
from app.models.investigation import Investigation
from app.services.investigation_service import run_investigation


@pytest.mark.asyncio
async def test_investigation_status_failed_on_coordinator_error(db_session):
    """
    Cuando el Coordinator lanza una excepcion, la fila en DB debe quedar
    con status='failed'. Verifica el fix H2: re-fetch despues de rollback.
    """
    with patch(
        "app.services.investigation_service.Coordinator"
    ) as MockCoordinator:
        mock_instance = MockCoordinator.return_value
        mock_instance.investigate = AsyncMock(side_effect=RuntimeError("Coordinator exploded"))

        investigation = await run_investigation(
            ioc_value="1.2.3.4",
            ioc_type="ip",
            db=db_session,
        )

    # El objeto retornado debe reflejar el estado final
    assert investigation.status == "failed"

    # Verificar tambien contra la DB directamente (el objeto Python podria
    # estar desincronizado si el fix no funciona bien)
    result = await db_session.execute(
        select(Investigation).where(Investigation.id == investigation.id)
    )
    db_row = result.scalar_one()
    assert db_row.status == "failed"
    assert db_row.execution_time_seconds is not None
    assert db_row.execution_time_seconds >= 0


@pytest.mark.asyncio
async def test_investigation_status_completed_on_success(db_session):
    """
    Camino feliz: Coordinator exitoso produce status='completed'.
    Test de regresion para no romper el camino normal al arreglar H2.
    """
    mock_correlation = {
        "verdict": "malicious",
        "severity": "high",
        "severity_score": 8.5,
        "agents_completed": ["recon", "osint"],
    }

    with patch(
        "app.services.investigation_service.Coordinator"
    ) as MockCoordinator:
        mock_instance = MockCoordinator.return_value
        mock_instance.investigate = AsyncMock(return_value={
            "agent_findings": {"recon": {"reputation": "malicious"}},
            "correlation": mock_correlation,
        })

        investigation = await run_investigation(
            ioc_value="185.220.101.50",
            ioc_type="ip",
            db=db_session,
        )

    assert investigation.status == "completed"
    assert investigation.verdict == "malicious"
    assert investigation.severity == "high"

    result = await db_session.execute(
        select(Investigation).where(Investigation.id == investigation.id)
    )
    db_row = result.scalar_one()
    assert db_row.status == "completed"
    assert db_row.verdict == "malicious"


@pytest.mark.asyncio
async def test_investigation_execution_time_recorded_on_failure(db_session):
    """
    Incluso en fallo, execution_time_seconds debe quedar registrado.
    Necesario para diagnosticar timeouts.
    """
    with patch(
        "app.services.investigation_service.Coordinator"
    ) as MockCoordinator:
        mock_instance = MockCoordinator.return_value
        mock_instance.investigate = AsyncMock(side_effect=TimeoutError("Agents timed out"))

        investigation = await run_investigation(
            ioc_value="evil.com",
            ioc_type="domain",
            db=db_session,
        )

    assert investigation.status == "failed"
    assert investigation.execution_time_seconds is not None
    assert investigation.execution_time_seconds >= 0.0
```

### Archivo a crear

| Archivo | Contenido |
|---|---|
| `tests/test_services/test_investigation_service.py` | Los 3 tests de arriba |

### Como ejecutar

```bash
pytest tests/test_services/test_investigation_service.py -v
```

Salida esperada:
```
PASSED  test_investigation_status_failed_on_coordinator_error
PASSED  test_investigation_status_completed_on_success
PASSED  test_investigation_execution_time_recorded_on_failure
```

---

## Resumen de esfuerzo

| Item | Archivos modificados | Archivos nuevos | Estimacion |
|---|---|---|---|
| 1 - Reset rate limits | `main.py`, `requirements.txt` | - | 30 min |
| 2 - POST 202 async | `investigation_service.py`, `investigations.py`, `schemas/investigation.py` | - | 1-2 h |
| 3 - Tests H2 | - | `test_investigation_service.py` | 20 min |

**Orden recomendado:** 3 → 1 → 2

El item 3 (tests) se hace primero porque es el mas rapido y da confianza
para hacer los cambios de los items 1 y 2 sin romper nada. El item 2 es el
mas invasivo y debe hacerse con los tests verdes.

---

*Generado: 2026-06-13*
