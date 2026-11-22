"""Crea las tablas y carga datos semilla de prueba.

Uso:
    python seed.py            # crea BD (si no existe) y carga datos si está vacía
    python seed.py --reset    # BORRA todo y vuelve a cargar los datos semilla
"""
import sys
from datetime import datetime, timedelta

from app import create_app
from models import Activo, AuditoriaTicket, Bitacora, TicketRemediacion, Usuario, Vulnerabilidad, db
from services import calcular_severidad

USUARIOS = [
    # nombre, email, password, rol
    ("Ana Martínez", "admin@vulneratrack.local", "Admin123!", "Administrador"),
    ("Luis Hernández", "analista@vulneratrack.local", "Analista123!", "Analista"),
    ("Carlos Cardoso", "tecnico@vulneratrack.local", "Tecnico123!", "Tecnico"),
    ("María López", "tecnico2@vulneratrack.local", "Tecnico123!", "Tecnico"),
    ("Oficial CISO", "ciso@vulneratrack.local", "Ciso123!", "CISO"),
    ("Jorge Ramírez", "auditor@vulneratrack.local", "Auditor123!", "Auditor"),
]

ACTIVOS = [
    ("srv-db-01", "192.168.1.10", "Linux Ubuntu 22.04", "Critica"),
    ("srv-web-01", "192.168.1.20", "Windows Server 2019", "Alta"),
    ("pc-admin-01", "192.168.1.30", "Windows 11", "Media"),
    ("lap-ventas-01", "192.168.1.40", "Windows 10", "Baja"),
    ("srv-app-01", "192.168.1.50", "Linux CentOS 8", "Alta"),
    ("fw-perimetral", "192.168.1.1", "FortiOS 7.2", "Critica"),
    ("srv-correo-01", "192.168.1.60", "Linux Ubuntu 20.04", "Media"),
    ("srv-backup-01", "192.168.1.70", "Debian 12", "Alta"),
]

VULNS = [
    ("CVE-2021-44228", "Apache Log4j2 - ejecución remota de código (Log4Shell)", "JNDI lookup en mensajes de log permite RCE.", "10.0"),
    ("CVE-2019-0708", "Remote Desktop Services - RCE (BlueKeep)", "Ejecución remota sin autenticación vía RDP.", "9.8"),
    ("CVE-2021-34527", "Windows Print Spooler - RCE (PrintNightmare)", "Escalamiento y ejecución remota en el servicio de impresión.", "8.8"),
    ("CVE-2022-0847", "Linux kernel - escalamiento de privilegios (Dirty Pipe)", "Sobrescritura de archivos de solo lectura.", "7.8"),
    ("CVE-2014-0160", "OpenSSL - fuga de memoria (Heartbleed)", "Lectura de memoria del proceso vía extensión heartbeat.", "7.5"),
    ("CVE-2026-1234", "Servidor de aplicaciones - inyección SQL en módulo de reportes", "Parámetro sin sanitizar en endpoint /export.", "8.1"),
    ("CVE-2026-5678", "Motor de base de datos - credenciales por defecto", "Cuenta de servicio con contraseña de fábrica.", "7.2"),
    ("CVE-2026-0001", "Servidor web - cabecera HSTS ausente", "No se fuerza HTTPS en el navegador.", "5.3"),
    ("CVE-2026-9999", "Firewall - TLS 1.0 habilitado en consola", "Protocolos obsoletos permitidos.", "5.9"),
    ("CVE-2026-0002", "Equipo de usuario - divulgación de versión de SMB", "Banner revela versión del servicio.", "3.1"),
    ("CVE-2026-8888", "Correo - registro SPF permisivo", "Política ~all permite suplantación parcial.", "3.7"),
    ("CVE-2026-4321", "Respaldo - cifrado débil en archivos de backup", "Uso de algoritmo obsoleto en respaldos.", "6.5"),
]

# (host, cve, estado, técnico(email|None), días desde creación, horas hasta cierre|None)
TICKETS = [
    ("srv-web-01", "CVE-2026-0001", "Abierta", None, 2, None),
    ("pc-admin-01", "CVE-2026-0002", "Abierta", None, 1, None),
    ("srv-db-01", "CVE-2021-44228", "Abierta", None, 1, None),
    ("srv-app-01", "CVE-2026-1234", "En Analisis", None, 4, None),
    ("srv-db-01", "CVE-2026-5678", "En Analisis", None, 3, None),
    ("srv-db-01", "CVE-2014-0160", "En Remediacion", "tecnico@vulneratrack.local", 6, None),
    ("srv-web-01", "CVE-2019-0708", "En Remediacion", "tecnico2@vulneratrack.local", 5, None),
    ("srv-app-01", "CVE-2022-0847", "En Remediacion", "tecnico@vulneratrack.local", 9, None),
    ("fw-perimetral", "CVE-2026-9999", "Mitigada", "tecnico@vulneratrack.local", 8, None),
    ("srv-correo-01", "CVE-2026-8888", "Verificada", "tecnico2@vulneratrack.local", 20, 5.5),
    ("pc-admin-01", "CVE-2021-34527", "Verificada", "tecnico@vulneratrack.local", 15, 3.2),
    ("srv-backup-01", "CVE-2026-4321", "Verificada", "tecnico2@vulneratrack.local", 12, 4.0),
    ("lap-ventas-01", "CVE-2026-0002", "Riesgo Aceptado", None, 25, 2.0),
    ("srv-backup-01", "CVE-2022-0847", "Abierta", None, 0, None),
]

FLUJO = ["Abierta", "En Analisis", "En Remediacion", "Mitigada", "Verificada"]


def cargar():
    ahora = datetime.utcnow()
    usuarios = {}
    for nombre, email, pwd, rol in USUARIOS:
        u = Usuario(nombre_completo=nombre, email=email, rol=rol, fecha_creacion=ahora - timedelta(days=60))
        u.set_password(pwd)
        db.session.add(u)
        usuarios[email] = u
    activos = {}
    for i, (host, ip, so, crit) in enumerate(ACTIVOS):
        a = Activo(nombre_host=host, direccion_ip=ip, sistema_operativo=so, criticidad=crit,
                   fecha_registro=ahora - timedelta(days=50 - i))
        db.session.add(a)
        activos[host] = a
    vulns = {}
    for cve, tit, desc, cvss in VULNS:
        v = Vulnerabilidad(codigo_cve=cve, titulo=tit, descripcion=desc, puntaje_cvss=cvss,
                           nivel_severidad=calcular_severidad(cvss))
        db.session.add(v)
        vulns[cve] = v
    db.session.flush()

    admin = usuarios["admin@vulneratrack.local"]
    analista = usuarios["analista@vulneratrack.local"]
    sla = {"Critica": 3, "Alta": 7, "Media": 30, "Baja": 90}
    for host, cve, estado, tec, dias, horas_cierre in TICKETS:
        creado = ahora - timedelta(days=dias, hours=2)
        v = vulns[cve]
        t = TicketRemediacion(
            id_activo=activos[host].id_activo, id_vulnerabilidad=v.id_vulnerabilidad,
            id_tecnico_asignado=usuarios[tec].id_usuario if tec else None, estado=estado,
            fecha_creacion=creado, fecha_limite=(creado + timedelta(days=sla[v.nivel_severidad])).date(),
        )
        if horas_cierre:
            t.fecha_cierre = creado + timedelta(hours=horas_cierre)
        db.session.add(t)
        db.session.flush()
        # Historial de auditoría coherente con el estado actual
        recorrido = ["Abierta"]
        if estado == "Riesgo Aceptado":
            recorrido += ["En Analisis", "Riesgo Aceptado"]
        else:
            recorrido = FLUJO[: FLUJO.index(estado) + 1]
        paso = (timedelta(hours=horas_cierre) / max(len(recorrido) - 1, 1)) if horas_cierre else timedelta(hours=6)
        anterior = None
        for n, e in enumerate(recorrido):
            quien = admin if e == "Riesgo Aceptado" else (usuarios[tec] if (e == "Mitigada" and tec) else analista)
            db.session.add(AuditoriaTicket(
                id_ticket=t.id_ticket, id_usuario=quien.id_usuario, estado_anterior=anterior, estado_nuevo=e,
                notas="Hallazgo ingerido" if n == 0 else ("Riesgo aceptado: equipo en baja programada" if e == "Riesgo Aceptado" else None),
                fecha_registro=min(creado + paso * n, ahora),
            ))
            anterior = e

    # Eventos de bitácora de ejemplo (para el Módulo de Auditoría)
    eventos = [
        (admin, "Inició sesión", "Acceso al sistema", "192.168.1.5", 10),
        (analista, "Registró hallazgo", "CVE-2026-1234 en srv-app-01", "192.168.1.23", 4),
        (admin, "Cambió estado de ticket", "Ticket #9: En Remediacion → Mitigada", "192.168.1.5", 3),
        (analista, "Actualizó activo", "A001 srv-db-01", "192.168.1.30", 2),
        (usuarios["auditor@vulneratrack.local"], "Consultó reporte", "Reporte de riesgo", "192.168.1.50", 1),
    ]
    for u, acc, det, ip, dias in eventos:
        db.session.add(Bitacora(id_usuario=u.id_usuario, usuario_txt=u.usuario_corto, accion=acc, detalle=det,
                                ip_origen=ip, fecha_registro=ahora - timedelta(days=dias, hours=3)))
    db.session.commit()


def main():
    app = create_app()
    with app.app_context():
        if "--reset" in sys.argv:
            db.drop_all()
            print("Tablas eliminadas.")
        db.create_all()
        if Usuario.query.count() == 0:
            cargar()
            print("Datos semilla cargados.")
        else:
            print("La base ya contiene datos (use --reset para recargar).")
        print(f"BD: {app.config['SQLALCHEMY_DATABASE_URI']}")
        print("Usuarios de prueba:")
        for nombre, email, pwd, rol in USUARIOS:
            print(f"  {rol:<14} {email:<32} {pwd}")


if __name__ == "__main__":
    main()
