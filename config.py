"""Configuración de VulneraTrack.

Por defecto usa SQLite (archivo local vulneratrack.db) para pruebas rápidas.
Para usar MySQL defina la variable de entorno DATABASE_URL, por ejemplo:
    DATABASE_URL=mysql+pymysql://vt_user:vt_pass@localhost:3306/vulneratrack
"""
import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "cambie-esta-clave-en-produccion-vt-2026")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "vulneratrack.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB por archivo de ingesta
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Bloqueo temporal tras intentos fallidos de login (RNF-01)
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_MINUTES = 5
    # SLA por severidad (días) para la fecha límite sugerida de los tickets (RF-06)
    SLA_DIAS = {"Critica": 3, "Alta": 7, "Media": 30, "Baja": 90}


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
