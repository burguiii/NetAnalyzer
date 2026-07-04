"""
Configuracion central del Monitor de Red.

Puedes editar estos valores sin tocar el resto del codigo.
Los comentarios explican para que sirve cada uno.
"""

import os
from pathlib import Path

# --- Rutas (no hace falta tocarlas normalmente) ---
BASE_DIR = Path(__file__).resolve().parent.parent   # carpeta raiz del proyecto
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "static"
DB_PATH = DATA_DIR / "monitor.db"

# --- Dashboard web ---
# Puerto del dashboard. Por defecto 5000; puede sobreescribirse con la
# variable de entorno PORT (util para herramientas que asignan el puerto).
DASHBOARD_PORT = int(os.environ.get("PORT", "5000"))

# --- Muestreo de conexiones ---
POLL_INTERVAL_SECONDS = 3      # cada cuantos segundos se leen las conexiones

# --- Captura de paquetes (scapy + Npcap) ---
# Deja esto en False hasta que tengas Npcap instalado y confirmado.
ENABLE_PACKET_CAPTURE = False

# --- Reputacion de IP (AbuseIPDB) ---
# La clave NO se guarda aqui (para poder subir este archivo a Git sin filtrarla).
# Se busca, en este orden:
#   1) la variable de entorno ABUSEIPDB_API_KEY
#   2) el archivo app/config_secret.py (ignorado por Git)
# Si no hay clave, la app funciona igual pero sin puntuacion de reputacion.
def _load_abuseipdb_key() -> str:
    env = os.environ.get("ABUSEIPDB_API_KEY")
    if env:
        return env.strip()
    try:
        from . import config_secret
        return getattr(config_secret, "ABUSEIPDB_API_KEY", "").strip()
    except ImportError:
        return ""

ABUSEIPDB_API_KEY = _load_abuseipdb_key()

# --- Umbrales de las reglas de deteccion ---
PORT_SCAN_THRESHOLD = 10             # nº de puertos distintos para considerar escaneo
PORT_SCAN_WINDOW_SECONDS = 5         # ventana de tiempo para el escaneo

NEW_CONN_BURST_THRESHOLD = 20        # nº de conexiones nuevas de un proceso
NEW_CONN_BURST_WINDOW_SECONDS = 10   # ventana de tiempo para el pico de conexiones

ABUSE_SCORE_THRESHOLD = 50           # score de AbuseIPDB para marcar mala reputacion

# Puertos poco comunes asociados a malware conocido (ampliable)
SUSPICIOUS_PORTS = [4444, 1337, 31337, 6667, 6668, 6669, 5555]

# Carpetas consideradas "sospechosas" si un proceso se ejecuta desde ahi
SUSPICIOUS_PATH_HINTS = ["\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\"]
