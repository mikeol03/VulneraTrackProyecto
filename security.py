"""Autenticación, control de acceso por rol (RBAC) y protección CSRF."""
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import abort, current_app, flash, g, redirect, request, session, url_for

from models import Usuario, db

# Matriz de permisos RBAC (RF-01). Cada permiso lista los roles que lo tienen.
PERMISOS = {
    "dashboard.ver": ["Administrador", "Analista", "Tecnico", "CISO", "Auditor"],
    "activos.ver": ["Administrador", "Analista", "Tecnico", "CISO", "Auditor"],
    "activos.editar": ["Administrador", "Analista"],
    "activos.eliminar": ["Administrador"],
    "hallazgos.registrar": ["Administrador", "Analista"],
    "tickets.ver": ["Administrador", "Analista", "Tecnico", "CISO", "Auditor"],
    "tickets.gestionar": ["Administrador", "Analista"],  # crear, asignar técnico, fecha límite
    "tickets.cambiar_estado": ["Administrador", "Analista", "Tecnico", "CISO"],
    "reportes.ver": ["Administrador", "Analista", "CISO", "Auditor"],
    "usuarios.gestionar": ["Administrador"],
}

_intentos_fallidos = {}  # email -> {"n": int, "hasta": datetime}


def puede(permiso: str, usuario=None) -> bool:
    usuario = usuario or g.get("usuario")
    return bool(usuario and usuario.rol in PERMISOS.get(permiso, []))


def cargar_usuario():
    g.usuario = None
    uid = session.get("user_id")
    if uid:
        g.usuario = db.session.get(Usuario, uid)
        if g.usuario is None:
            session.clear()


def login_required(vista):
    @wraps(vista)
    def envoltura(*args, **kwargs):
        if g.get("usuario") is None:
            flash("Inicie sesión para continuar.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return vista(*args, **kwargs)

    return envoltura


def permiso_requerido(permiso: str):
    def decorador(vista):
        @wraps(vista)
        @login_required
        def envoltura(*args, **kwargs):
            if not puede(permiso):
                from services import registrar_evento

                registrar_evento("Acceso denegado", f"{request.method} {request.path} (requiere {permiso})")
                abort(403)
            return vista(*args, **kwargs)

        return envoltura

    return decorador


# --- Bloqueo por intentos fallidos -----------------------------------------
def esta_bloqueado(email: str):
    info = _intentos_fallidos.get(email)
    if info and info.get("hasta") and info["hasta"] > datetime.utcnow():
        return info["hasta"]
    return None


def registrar_fallo(email: str):
    info = _intentos_fallidos.setdefault(email, {"n": 0, "hasta": None})
    info["n"] += 1
    if info["n"] >= current_app.config["MAX_LOGIN_ATTEMPTS"]:
        info["hasta"] = datetime.utcnow() + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])
        info["n"] = 0


def limpiar_fallos(email: str):
    _intentos_fallidos.pop(email, None)


# --- CSRF ------------------------------------------------------------------
def csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


def verificar_csrf():
    if request.method in ("POST", "PUT", "DELETE"):
        if current_app.config.get("TESTING") and not current_app.config.get("WTF_CSRF_ENABLED", True):
            return
        enviado = request.form.get("_csrf") or request.headers.get("X-CSRF-Token")
        if not enviado or enviado != session.get("_csrf"):
            abort(400, description="Token CSRF inválido o ausente. Recargue la página e intente de nuevo.")
