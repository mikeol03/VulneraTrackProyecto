"""Modelos ORM (SQLAlchemy) que reflejan las tablas definidas en la arquitectura."""
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()

ROLES = ["Administrador", "Analista", "Tecnico", "CISO", "Auditor"]
CRITICIDADES = ["Baja", "Media", "Alta", "Critica"]
SEVERIDADES = ["Baja", "Media", "Alta", "Critica"]
ESTADOS = ["Abierta", "En Analisis", "En Remediacion", "Mitigada", "Verificada", "Riesgo Aceptado"]
ESTADOS_CERRADOS = ["Verificada", "Riesgo Aceptado"]


class Usuario(db.Model):
    __tablename__ = "usuarios"
    id_usuario = db.Column(db.Integer, primary_key=True)
    nombre_completo = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(20), nullable=False)
    fecha_creacion = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        db.CheckConstraint(
            "rol IN ('Administrador','Analista','Tecnico','CISO','Auditor')", name="ck_usuarios_rol"
        ),
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def usuario_corto(self) -> str:
        return self.email.split("@")[0]


class Activo(db.Model):
    __tablename__ = "activos"
    id_activo = db.Column(db.Integer, primary_key=True)
    nombre_host = db.Column(db.String(100), nullable=False)
    direccion_ip = db.Column(db.String(45), nullable=False, unique=True, index=True)
    sistema_operativo = db.Column(db.String(100), nullable=False)
    criticidad = db.Column(db.String(10), nullable=False)
    fecha_registro = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    tickets = db.relationship("TicketRemediacion", back_populates="activo")

    __table_args__ = (
        db.CheckConstraint("criticidad IN ('Baja','Media','Alta','Critica')", name="ck_activos_criticidad"),
    )

    @property
    def codigo(self) -> str:
        return f"A{self.id_activo:03d}"


class Vulnerabilidad(db.Model):
    __tablename__ = "vulnerabilidades"
    id_vulnerabilidad = db.Column(db.Integer, primary_key=True)
    codigo_cve = db.Column(db.String(20), nullable=False, unique=True, index=True)
    titulo = db.Column(db.String(200), nullable=False)
    descripcion = db.Column(db.Text)
    puntaje_cvss = db.Column(db.Numeric(3, 1), nullable=False)
    nivel_severidad = db.Column(db.String(10), nullable=False)

    tickets = db.relationship("TicketRemediacion", back_populates="vulnerabilidad")

    __table_args__ = (
        db.CheckConstraint("puntaje_cvss >= 0.0 AND puntaje_cvss <= 10.0", name="ck_vuln_cvss"),
        db.CheckConstraint(
            "nivel_severidad IN ('Ninguna','Baja','Media','Alta','Critica')", name="ck_vuln_severidad"
        ),
    )


class TicketRemediacion(db.Model):
    __tablename__ = "tickets_remediacion"
    id_ticket = db.Column(db.Integer, primary_key=True)
    id_activo = db.Column(db.Integer, db.ForeignKey("activos.id_activo", ondelete="RESTRICT"), nullable=False, index=True)
    id_vulnerabilidad = db.Column(
        db.Integer, db.ForeignKey("vulnerabilidades.id_vulnerabilidad", ondelete="RESTRICT"), nullable=False, index=True
    )
    id_tecnico_asignado = db.Column(db.Integer, db.ForeignKey("usuarios.id_usuario", ondelete="SET NULL"), index=True)
    estado = db.Column(db.String(20), nullable=False, default="Abierta", index=True)
    fecha_creacion = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    fecha_limite = db.Column(db.Date)
    fecha_cierre = db.Column(db.DateTime)  # se llena al pasar a Verificada / Riesgo Aceptado (para MTTR)

    activo = db.relationship("Activo", back_populates="tickets")
    vulnerabilidad = db.relationship("Vulnerabilidad", back_populates="tickets")
    tecnico = db.relationship("Usuario")
    auditorias = db.relationship(
        "AuditoriaTicket", back_populates="ticket", order_by="AuditoriaTicket.fecha_registro.desc()"
    )

    __table_args__ = (
        db.CheckConstraint(
            "estado IN ('Abierta','En Analisis','En Remediacion','Mitigada','Verificada','Riesgo Aceptado')",
            name="ck_tickets_estado",
        ),
    )


class AuditoriaTicket(db.Model):
    __tablename__ = "auditoria_tickets"
    id_auditoria = db.Column(db.Integer, primary_key=True)
    id_ticket = db.Column(db.Integer, db.ForeignKey("tickets_remediacion.id_ticket", ondelete="CASCADE"), nullable=False, index=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey("usuarios.id_usuario"), nullable=False)
    estado_anterior = db.Column(db.String(20))
    estado_nuevo = db.Column(db.String(20), nullable=False)
    notas = db.Column(db.Text)
    fecha_registro = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    ticket = db.relationship("TicketRemediacion", back_populates="auditorias")
    usuario = db.relationship("Usuario")


class Bitacora(db.Model):
    """Bitácora general de eventos (RNF-04): login, altas, ediciones, exportaciones, etc.

    Complementa a auditoria_tickets (que guarda solo cambios de estado de tickets)
    y alimenta la tabla del Módulo de Auditoría y Reportes.
    """

    __tablename__ = "bitacora_eventos"
    id_evento = db.Column(db.Integer, primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey("usuarios.id_usuario", ondelete="SET NULL"), index=True)
    usuario_txt = db.Column(db.String(120), nullable=False)
    accion = db.Column(db.String(80), nullable=False)
    detalle = db.Column(db.String(255))
    ip_origen = db.Column(db.String(45))
    fecha_registro = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    usuario = db.relationship("Usuario")
