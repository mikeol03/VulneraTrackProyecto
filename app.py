"""Punto de entrada de VulneraTrack (Flask).

Ejecutar:
    python seed.py      # crea la BD y carga datos de prueba
    python app.py       # inicia el servidor en http://127.0.0.1:5000
"""
from flask import Flask, render_template

from config import Config
from models import db
from security import cargar_usuario, csrf_token, puede, verificar_csrf

ETIQUETAS = {
    "Critica": "Crítica",
    "En Analisis": "En Análisis",
    "En Remediacion": "En Remediación",
    "Tecnico": "Técnico",
}


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    db.init_app(app)

    # SQLite no valida llaves foráneas por defecto: se activa para comportarse como MySQL.
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    @event.listens_for(Engine, "connect")
    def _fk_sqlite(dbapi_conn, _):
        if dbapi_conn.__class__.__module__.startswith("sqlite3"):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    from routes.auth import bp as auth_bp
    from routes.dashboard import bp as dashboard_bp
    from routes.activos import bp as activos_bp
    from routes.hallazgos import bp as hallazgos_bp
    from routes.tickets import bp as tickets_bp
    from routes.reportes import bp as reportes_bp
    from routes.usuarios import bp as usuarios_bp

    for bp in (auth_bp, dashboard_bp, activos_bp, hallazgos_bp, tickets_bp, reportes_bp, usuarios_bp):
        app.register_blueprint(bp)

    @app.before_request
    def _antes():
        cargar_usuario()
        verificar_csrf()

    @app.after_request
    def _cabeceras_seguridad(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        return resp

    app.jinja_env.globals.update(csrf_token=csrf_token, puede=puede)
    app.jinja_env.filters["etq"] = lambda v: ETIQUETAS.get(v, v) if v else ""
    app.jinja_env.filters["css"] = lambda v: (v or "").lower().replace(" ", "-")

    @app.errorhandler(403)
    def _403(e):
        return render_template("error.html", codigo=403, mensaje="No tiene permisos para acceder a esta función."), 403

    @app.errorhandler(404)
    def _404(e):
        return render_template("error.html", codigo=404, mensaje="El recurso solicitado no existe."), 404

    @app.errorhandler(400)
    def _400(e):
        return render_template("error.html", codigo=400, mensaje=getattr(e, "description", "Solicitud inválida.")), 400

    @app.errorhandler(413)
    def _413(e):
        return render_template("error.html", codigo=413, mensaje="El archivo excede el tamaño máximo de 2 MB."), 413

    return app


app = create_app()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="127.0.0.1", port=5000)
