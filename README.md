# VulneraTrack

Sistema web de gestión y mitigación de vulnerabilidades en infraestructura tecnológica.
Proyecto de **Ingeniería de Software — UAEM, FCAeI**.

Stack: **Python 3.10+ · Flask · SQLAlchemy · SQLite (por defecto) o MySQL 8 · HTML/CSS/JS sin dependencias externas · ReportLab (PDF)**.

---

## 1. Funcionalidades

| Módulo | Requerimientos | Qué hace |
|---|---|---|
| Inicio de sesión y RBAC | RF-01, RNF-01 | Login con contraseñas hasheadas (werkzeug/scrypt), mensaje genérico de error, bloqueo tras 5 intentos fallidos, sesión de 30 min, protección CSRF, permisos por rol |
| Inventario de activos | RF-02 | Alta, edición, eliminación y búsqueda; valida IP (formato y duplicado) |
| Ingesta de hallazgos | RF-03, RF-04 | Carga masiva CSV/JSON (arrastrar y soltar) y registro manual; severidad CVSS v3 automática; rechaza puntajes fuera de 0.0–10.0 |
| Tickets de remediación | RF-05, RF-06 | Tablero Kanban, transiciones validadas, asignación de técnico, fecha límite / SLA |
| Dashboard | RF-07 | KPIs en tiempo real (abiertas, críticas, MTTR, activos), distribución CVSS, top 5 activos, abiertas vs. cerradas; se refresca cada 30 s |
| Auditoría y reportes | RF-08, RF-09, RNF-04 | Bitácora automática de cada acción, filtros por fecha, exportación CSV, PDF y vista imprimible |
| Usuarios | RF-01 | Alta/baja de usuarios por el Administrador |

### Roles y permisos

| Permiso | Administrador | Analista | Técnico | CISO | Auditor |
|---|:-:|:-:|:-:|:-:|:-:|
| Ver dashboard, activos y tickets | ✔ | ✔ | ✔ | ✔ | ✔ |
| Crear / editar activos | ✔ | ✔ | | | |
| Eliminar activos | ✔ | | | | |
| Registrar hallazgos | ✔ | ✔ | | | |
| Crear tickets, asignar técnico | ✔ | ✔ | | | |
| Cambiar estado de tickets | ✔ | ✔ | solo sus tickets: En Remediación → Mitigada | solo → Riesgo Aceptado | |
| Reportes y bitácora | ✔ | ✔ | | ✔ | ✔ |
| Gestionar usuarios | ✔ | | | | |

### Flujo de estados de un ticket

```
Abierta → En Analisis → En Remediacion → Mitigada → Verificada
                     ↘ Riesgo Aceptado          ↘ (reabrir) En Remediacion
```
Reglas: para pasar a *En Remediación* debe haber técnico asignado; *Riesgo Aceptado* requiere justificación y rol Administrador o CISO; *Verificada* solo Analista o Administrador.

---

## 2. Ejecución local (SQLite, la opción más rápida)

> Requisitos: Python 3.10 o superior. Compruebe con `python --version` (en Linux/Mac puede ser `python3`).

**Windows (PowerShell o CMD)**
```bat
cd vulneratrack
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python seed.py --reset
python app.py
```

**Linux / macOS**
```bash
cd vulneratrack
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python seed.py --reset
python app.py
```

Abra **http://127.0.0.1:5000** en el navegador.

`python seed.py --reset` borra y vuelve a crear la base `vulneratrack.db` con datos de prueba. Úselo antes de cada ronda de pruebas para partir del mismo estado.

### Usuarios de prueba

| Rol | Correo | Contraseña |
|---|---|---|
| Administrador | admin@vulneratrack.local | Admin123! |
| Analista | analista@vulneratrack.local | Analista123! |
| Técnico (Carlos Cardoso) | tecnico@vulneratrack.local | Tecnico123! |
| Técnico (María López) | tecnico2@vulneratrack.local | Tecnico123! |
| CISO | ciso@vulneratrack.local | Ciso123! |
| Auditor | auditor@vulneratrack.local | Auditor123! |

Datos semilla: 8 activos, 12 vulnerabilidades, 14 tickets en todos los estados con su historial de auditoría y 5 eventos de bitácora.

---

## 3. Ejecución con MySQL 8 (opcional)

1. Cree la base, tablas, índices y el usuario `vt_user`:
   ```bash
   mysql -u root -p < database/schema_mysql.sql
   ```
2. Cargue los datos semilla, con **una** de estas dos opciones:
   - Script SQL: `mysql -u root -p vulneratrack < database/seed_mysql.sql`
   - O desde Python (fechas relativas a hoy, recomendado):
     ```bash
     # Windows:  set DATABASE_URL=mysql+pymysql://root:SU_PASSWORD@localhost:3306/vulneratrack
     export DATABASE_URL="mysql+pymysql://root:SU_PASSWORD@localhost:3306/vulneratrack"
     python seed.py --reset
     ```
3. Arranque la app apuntando a MySQL:
   ```bash
   export DATABASE_URL="mysql+pymysql://vt_user:vt_pass@localhost:3306/vulneratrack"   # Windows: set DATABASE_URL=...
   python app.py
   ```

Para regenerar `seed_mysql.sql` después de cambiar `seed.py`: `python database/generar_seed_mysql.py`.

---

## 4. Pruebas automatizadas

```bash
python -m pytest -v
```
46 casos (CP-01 a CP-41 funcionales, NF-01 a NF-05 no funcionales) en `tests/test_casos_prueba.py`. Usan una base SQLite en memoria, así que no tocan `vulneratrack.db`.

La guía de pruebas manuales paso a paso está en **`docs/ESCENARIOS_DE_PRUEBA.md`**. Los archivos de ejemplo para la ingesta están en `samples/`:

| Archivo | Uso |
|---|---|
| `hallazgos_validos.csv` | 4 hallazgos correctos |
| `hallazgos_con_errores.csv` | 1 válido + 6 inválidos (CVSS > 10, negativo, texto, activo inexistente, CVE mal formado, título vacío) |
| `hallazgos_limites.csv` | fronteras CVSS 0.0 / 0.1 / 3.9 / 4.0 / 6.9 / 7.0 / 8.9 / 9.0 / 10.0 / 10.1 |
| `hallazgos_decimales.csv` | CVSS 3.95 (más de un decimal) |
| `hallazgos.json` | formato JSON, búsqueda por hostname e IP |
| `archivo_no_soportado.txt` | formato no permitido |

---

## 5. Estructura

```
vulneratrack/
├── app.py                 # fábrica Flask, filtros, manejadores de error
├── config.py              # configuración (SQLite/MySQL, SLA, bloqueo)
├── models.py              # tablas ORM
├── services.py            # reglas de negocio: CVSS, transiciones, ingesta, bitácora
├── security.py            # login, RBAC, CSRF, bloqueo de intentos
├── seed.py                # creación de BD + datos semilla
├── routes/                # auth, dashboard, activos, hallazgos, tickets, reportes, usuarios
├── templates/             # vistas HTML (Jinja2)
├── static/css, static/js  # tema oscuro morado/azul, gráficas SVG
├── database/              # schema_mysql.sql, seed_mysql.sql, generador
├── samples/               # archivos CSV/JSON de prueba
├── tests/                 # pytest
└── docs/                  # escenarios de prueba y evidencias
```

## 6. Subir a GitHub

El proyecto ya trae su historial Git (commits `feat:`, `test:` y `fix:`). Para publicarlo:
```bash
git remote add origin https://github.com/USUARIO/vulneratrack.git
git push -u origin main
```

## 7. Nota sobre la base de datos

Además de las cinco tablas de la arquitectura, se agregó `bitacora_eventos` (y la columna `fecha_cierre` en `tickets_remediacion`). `auditoria_tickets` solo guarda los cambios de estado; la bitácora general registra inicios de sesión, altas, ediciones, exportaciones y accesos denegados, que es lo que muestra el Módulo de Auditoría. `fecha_cierre` se usa para calcular el MTTR.
