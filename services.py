"""Reglas de negocio de VulneraTrack: CVSS, transiciones, validaciones, auditoría e ingesta."""
import csv
import io
import ipaddress
import json
import re
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation

from flask import current_app, request, session

from models import (
    ESTADOS_CERRADOS,
    Activo,
    AuditoriaTicket,
    Bitacora,
    TicketRemediacion,
    Usuario,
    Vulnerabilidad,
    db,
)

# ---------------------------------------------------------------------------
# RF-04: Cálculo de severidad CVSS v3
# ---------------------------------------------------------------------------
CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$")


class ValidacionError(ValueError):
    """Error de validación con mensaje listo para mostrar al usuario."""


def parse_cvss(valor) -> Decimal:
    """Convierte y valida un puntaje CVSS. Rechaza valores fuera de 0.0 - 10.0."""
    if valor is None or str(valor).strip() == "":
        raise ValidacionError("El puntaje CVSS es obligatorio.")
    try:
        puntaje = Decimal(str(valor).strip())
    except InvalidOperation:
        raise ValidacionError(f"El puntaje CVSS '{valor}' no es numérico.")
    if not puntaje.is_finite():  # NaN / Infinity
        raise ValidacionError(f"El puntaje CVSS '{valor}' no es numérico.")
    if puntaje.as_tuple().exponent < -1:
        raise ValidacionError(f"El puntaje CVSS {valor} debe tener como máximo un decimal (CVSS v3, ej. 7.5).")
    if puntaje < 0 or puntaje > 10:
        raise ValidacionError(f"El puntaje CVSS {valor} está fuera del rango permitido (0.0 a 10.0).")
    return puntaje


def calcular_severidad(puntaje) -> str:
    """Escala cualitativa CVSS v3.x."""
    p = Decimal(str(puntaje))
    if p == 0:
        return "Ninguna"
    if p <= Decimal("3.9"):
        return "Baja"
    if p <= Decimal("6.9"):
        return "Media"
    if p <= Decimal("8.9"):
        return "Alta"
    return "Critica"


# ---------------------------------------------------------------------------
# RF-02: validaciones de activos
# ---------------------------------------------------------------------------
def validar_ip(ip: str) -> str:
    if not ip:
        raise ValidacionError("La dirección IP es obligatoria.")
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise ValidacionError(f"La dirección IP '{ip}' no tiene un formato válido.")


def validar_activo(form, activo_id=None) -> dict:
    from models import CRITICIDADES

    nombre = (form.get("nombre_host") or "").strip()
    so = (form.get("sistema_operativo") or "").strip()
    criticidad = (form.get("criticidad") or "").strip()
    ip = validar_ip(form.get("direccion_ip"))
    if not nombre:
        raise ValidacionError("El nombre de host es obligatorio.")
    if len(nombre) > 100:
        raise ValidacionError("El nombre de host no puede exceder 100 caracteres.")
    if not so:
        raise ValidacionError("El sistema operativo es obligatorio.")
    if criticidad not in CRITICIDADES:
        raise ValidacionError("Seleccione una criticidad válida (Baja, Media, Alta o Crítica).")
    duplicado = Activo.query.filter(Activo.direccion_ip == ip).first()
    if duplicado and duplicado.id_activo != activo_id:
        raise ValidacionError(
            f"La dirección IP {ip} ya está registrada para el activo {duplicado.codigo} ({duplicado.nombre_host})."
        )
    return {"nombre_host": nombre, "direccion_ip": ip, "sistema_operativo": so, "criticidad": criticidad}


# ---------------------------------------------------------------------------
# RF-05: ciclo de vida de tickets
# ---------------------------------------------------------------------------
TRANSICIONES = {
    "Abierta": ["En Analisis"],
    "En Analisis": ["En Remediacion", "Riesgo Aceptado"],
    "En Remediacion": ["Mitigada"],
    "Mitigada": ["Verificada", "En Remediacion"],  # si la verificación falla se reabre
    "Verificada": [],
    "Riesgo Aceptado": [],
}


def validar_transicion(ticket: TicketRemediacion, nuevo_estado: str, usuario: Usuario, notas: str = "") -> None:
    actual = ticket.estado
    if nuevo_estado not in TRANSICIONES:
        raise ValidacionError(f"El estado '{nuevo_estado}' no existe.")
    if nuevo_estado not in TRANSICIONES[actual]:
        permitidas = ", ".join(TRANSICIONES[actual]) or "ninguna (estado final)"
        raise ValidacionError(
            f"Transición no permitida: '{actual}' → '{nuevo_estado}'. Transiciones válidas: {permitidas}."
        )
    rol = usuario.rol
    if rol in ("Auditor",):
        raise ValidacionError("Su rol no tiene permisos para cambiar el estado de tickets.")
    if rol == "Tecnico":
        if ticket.id_tecnico_asignado != usuario.id_usuario:
            raise ValidacionError("Solo puede cambiar el estado de los tickets asignados a usted.")
        if not (actual == "En Remediacion" and nuevo_estado == "Mitigada"):
            raise ValidacionError("Como Técnico solo puede marcar como 'Mitigada' un ticket 'En Remediación'.")
    if nuevo_estado == "Riesgo Aceptado":
        if rol not in ("Administrador", "CISO"):
            raise ValidacionError("Solo el Administrador o el CISO pueden aceptar un riesgo.")
        if not notas.strip():
            raise ValidacionError("Debe justificar en las notas la aceptación del riesgo.")
    if rol == "CISO" and nuevo_estado != "Riesgo Aceptado":
        raise ValidacionError("El CISO solo puede aceptar riesgos; las demás transiciones son operativas.")
    if nuevo_estado == "En Remediacion" and not ticket.id_tecnico_asignado:
        raise ValidacionError("Debe asignar un técnico antes de pasar el ticket a 'En Remediación'.")
    if nuevo_estado == "Verificada" and rol not in ("Administrador", "Analista"):
        raise ValidacionError("Solo un Analista o Administrador puede verificar la mitigación.")


def cambiar_estado(ticket: TicketRemediacion, nuevo_estado: str, usuario: Usuario, notas: str = "") -> None:
    validar_transicion(ticket, nuevo_estado, usuario, notas)
    anterior = ticket.estado
    ticket.estado = nuevo_estado
    if nuevo_estado in ESTADOS_CERRADOS:
        ticket.fecha_cierre = datetime.utcnow()
    else:
        ticket.fecha_cierre = None
    db.session.add(
        AuditoriaTicket(
            id_ticket=ticket.id_ticket,
            id_usuario=usuario.id_usuario,
            estado_anterior=anterior,
            estado_nuevo=nuevo_estado,
            notas=notas.strip() or None,
        )
    )
    registrar_evento("Cambió estado de ticket", f"Ticket #{ticket.id_ticket}: {anterior} → {nuevo_estado}", commit=False)
    db.session.commit()


def fecha_limite_sugerida(severidad: str) -> date:
    dias = current_app.config["SLA_DIAS"].get(severidad, 30)
    return date.today() + timedelta(days=dias)


def crear_ticket(activo: Activo, vuln: Vulnerabilidad, usuario: Usuario, tecnico_id=None, fecha_limite=None, notas="Ticket creado"):
    ticket = TicketRemediacion(
        id_activo=activo.id_activo,
        id_vulnerabilidad=vuln.id_vulnerabilidad,
        id_tecnico_asignado=tecnico_id,
        estado="Abierta",
        fecha_limite=fecha_limite or fecha_limite_sugerida(vuln.nivel_severidad),
    )
    db.session.add(ticket)
    db.session.flush()
    db.session.add(
        AuditoriaTicket(
            id_ticket=ticket.id_ticket,
            id_usuario=usuario.id_usuario,
            estado_anterior=None,
            estado_nuevo="Abierta",
            notas=notas,
        )
    )
    return ticket


# ---------------------------------------------------------------------------
# RF-08 / RNF-04: bitácora de eventos
# ---------------------------------------------------------------------------
def ip_cliente() -> str:
    try:
        return request.headers.get("X-Forwarded-For", request.remote_addr or "-").split(",")[0].strip()
    except RuntimeError:
        return "-"


def registrar_evento(accion: str, detalle: str = "", usuario: Usuario = None, usuario_txt: str = None, commit=True):
    if usuario is None and session.get("user_id"):
        usuario = db.session.get(Usuario, session["user_id"])
    texto = usuario_txt or (usuario.usuario_corto if usuario else "anónimo")
    db.session.add(
        Bitacora(
            id_usuario=usuario.id_usuario if usuario else None,
            usuario_txt=texto,
            accion=accion,
            detalle=(detalle or "")[:255],
            ip_origen=ip_cliente(),
        )
    )
    if commit:
        db.session.commit()


# ---------------------------------------------------------------------------
# RF-03: ingesta de hallazgos (CSV / JSON / manual)
# ---------------------------------------------------------------------------
CAMPOS_REQUERIDOS = ["codigo_cve", "titulo", "puntaje_cvss"]


def _leer_filas(nombre_archivo: str, contenido: bytes):
    texto = contenido.decode("utf-8-sig")
    if nombre_archivo.lower().endswith(".json"):
        datos = json.loads(texto)
        if isinstance(datos, dict):
            datos = datos.get("hallazgos", [])
        if not isinstance(datos, list):
            raise ValidacionError("El JSON debe ser una lista de hallazgos o un objeto con la llave 'hallazgos'.")
        return datos
    if nombre_archivo.lower().endswith(".csv"):
        return list(csv.DictReader(io.StringIO(texto)))
    raise ValidacionError("Formato no soportado. Solo se aceptan archivos .csv o .json.")


def buscar_activo(fila: dict):
    ip = (fila.get("direccion_ip") or "").strip()
    host = (fila.get("nombre_host") or "").strip()
    if ip:
        return Activo.query.filter_by(direccion_ip=ip).first()
    if host:
        return Activo.query.filter_by(nombre_host=host).first()
    return None


def registrar_hallazgo(fila: dict, usuario: Usuario):
    """Valida un hallazgo y crea (o reutiliza) la vulnerabilidad y su ticket. Devuelve el ticket."""
    for campo in CAMPOS_REQUERIDOS:
        if not str(fila.get(campo) or "").strip():
            raise ValidacionError(f"El campo '{campo}' es obligatorio.")
    cve = str(fila["codigo_cve"]).strip().upper()
    if not CVE_REGEX.match(cve):
        raise ValidacionError(f"El código '{cve}' no tiene formato CVE válido (ej. CVE-2026-1234).")
    puntaje = parse_cvss(fila["puntaje_cvss"])
    activo = buscar_activo(fila)
    if activo is None:
        raise ValidacionError("El activo indicado (IP u hostname) no existe en el inventario.")

    vuln = Vulnerabilidad.query.filter_by(codigo_cve=cve).first()
    if vuln is None:
        vuln = Vulnerabilidad(
            codigo_cve=cve,
            titulo=str(fila["titulo"]).strip()[:200],
            descripcion=str(fila.get("descripcion") or "").strip(),
            puntaje_cvss=puntaje,
            nivel_severidad=calcular_severidad(puntaje),
        )
        db.session.add(vuln)
        db.session.flush()

    abierto = TicketRemediacion.query.filter(
        TicketRemediacion.id_activo == activo.id_activo,
        TicketRemediacion.id_vulnerabilidad == vuln.id_vulnerabilidad,
        TicketRemediacion.estado.notin_(ESTADOS_CERRADOS),
    ).first()
    if abierto:
        raise ValidacionError(f"Ya existe el ticket #{abierto.id_ticket} activo para {cve} en {activo.nombre_host}.")
    return crear_ticket(activo, vuln, usuario, notas="Hallazgo ingerido")


def procesar_archivo(nombre_archivo: str, contenido: bytes, usuario: Usuario) -> dict:
    filas = _leer_filas(nombre_archivo, contenido)
    resultado = {"total": len(filas), "creados": 0, "errores": []}
    for num, fila in enumerate(filas, start=2 if nombre_archivo.lower().endswith(".csv") else 1):
        try:
            with db.session.begin_nested():
                ticket = registrar_hallazgo(fila, usuario)
            resultado["creados"] += 1
        except ValidacionError as e:
            resultado["errores"].append({"fila": num, "cve": fila.get("codigo_cve", ""), "error": str(e)})
    registrar_evento(
        "Importó hallazgos",
        f"{nombre_archivo}: {resultado['creados']} creados, {len(resultado['errores'])} rechazados",
        usuario=usuario,
        commit=False,
    )
    db.session.commit()
    return resultado
