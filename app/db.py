"""
Acceso a la base de datos SQLite.

Todas las funciones abren y cierran su propia conexion para ser
seguras al usarse desde varios hilos (el hilo de muestreo y el web).
"""

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime

from . import config

# Un solo lock para las escrituras (SQLite no gusta de escrituras concurrentes)
_write_lock = threading.Lock()


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@contextmanager
def _connect():
    """Devuelve una conexion con filas accesibles por nombre de columna."""
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Crea las tablas si no existen. Se llama una vez al arrancar."""
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                pid INTEGER,
                process_name TEXT,
                process_path TEXT,
                local_ip TEXT,
                local_port INTEGER,
                remote_ip TEXT,
                remote_port INTEGER,
                protocol TEXT,
                status TEXT
            );

            CREATE TABLE IF NOT EXISTS ip_info (
                ip TEXT PRIMARY KEY,
                country TEXT,
                country_code TEXT,
                city TEXT,
                isp TEXT,
                hostname TEXT,
                lat REAL,
                lon REAL,
                abuse_score INTEGER,
                last_checked TEXT
            );

            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                window_start TEXT,
                window_end TEXT,
                local_ip TEXT,
                remote_ip TEXT,
                remote_port INTEGER,
                bytes_sent INTEGER,
                bytes_received INTEGER
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                remote_ip TEXT,
                process_name TEXT,
                description TEXT,
                advice TEXT,
                direction TEXT,
                resuelta INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS trusted_ips (
                ip TEXT PRIMARY KEY,
                note TEXT,
                rules TEXT,          -- '*' = confiar en todo; o lista de reglas
                                     --        silenciadas separadas por '||'
                added_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_conn_remote ON connections(remote_ip);
            CREATE INDEX IF NOT EXISTS idx_conn_time ON connections(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_resuelta ON alerts(resuelta);
            """
        )
        # Migraciones suaves para BDs creadas con versiones anteriores.
        _add_column_if_missing(conn, "ip_info", "hostname", "TEXT")
        _add_column_if_missing(conn, "ip_info", "lat", "REAL")
        _add_column_if_missing(conn, "ip_info", "lon", "REAL")
        _add_column_if_missing(conn, "alerts", "advice", "TEXT")
        _add_column_if_missing(conn, "alerts", "direction", "TEXT")


def _add_column_if_missing(conn, table, column, coltype):
    cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")


# ----------------------------------------------------------------------
# Conexiones
# ----------------------------------------------------------------------
def insert_connections(rows: list[dict]):
    """Inserta un lote de conexiones nuevas detectadas en este ciclo."""
    if not rows:
        return
    ts = _now()
    with _write_lock, _connect() as conn:
        conn.executemany(
            """INSERT INTO connections
               (timestamp, pid, process_name, process_path, local_ip,
                local_port, remote_ip, remote_port, protocol, status)
               VALUES (:timestamp, :pid, :process_name, :process_path,
                       :local_ip, :local_port, :remote_ip, :remote_port,
                       :protocol, :status)""",
            [{**r, "timestamp": r.get("timestamp", ts)} for r in rows],
        )


def get_recent_connections(limit: int = 500) -> list[dict]:
    with _connect() as conn:
        cur = conn.execute(
            "SELECT * FROM connections ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]


def search_history(ip: str = "", process: str = "",
                   desde: str = "", hasta: str = "",
                   limit: int = 500) -> list[dict]:
    """Busqueda filtrable del historico de conexiones."""
    clauses, params = [], []
    if ip:
        clauses.append("(remote_ip LIKE ? OR local_ip LIKE ?)")
        params += [f"%{ip}%", f"%{ip}%"]
    if process:
        clauses.append("process_name LIKE ?")
        params.append(f"%{process}%")
    if desde:
        clauses.append("timestamp >= ?")
        params.append(desde)
    if hasta:
        clauses.append("timestamp <= ?")
        params.append(hasta)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    with _connect() as conn:
        cur = conn.execute(
            f"SELECT * FROM connections {where} ORDER BY id DESC LIMIT ?", params
        )
        return [dict(r) for r in cur.fetchall()]


# ----------------------------------------------------------------------
# Info de IP (geolocalizacion / reputacion) con cache
# ----------------------------------------------------------------------
def get_ip_info(ip: str) -> dict | None:
    with _connect() as conn:
        cur = conn.execute("SELECT * FROM ip_info WHERE ip = ?", (ip,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_all_ip_info() -> dict:
    """Devuelve {ip: info} para enriquecer la tabla de conexiones rapido."""
    with _connect() as conn:
        cur = conn.execute("SELECT * FROM ip_info")
        return {r["ip"]: dict(r) for r in cur.fetchall()}


def upsert_ip_info(ip: str, country="", country_code="", city="",
                   isp="", hostname="", lat=None, lon=None, abuse_score=None):
    with _write_lock, _connect() as conn:
        conn.execute(
            """INSERT INTO ip_info (ip, country, country_code, city, isp,
                                    hostname, lat, lon, abuse_score, last_checked)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(ip) DO UPDATE SET
                 country=excluded.country,
                 country_code=excluded.country_code,
                 city=excluded.city,
                 isp=excluded.isp,
                 hostname=excluded.hostname,
                 lat=excluded.lat,
                 lon=excluded.lon,
                 abuse_score=COALESCE(excluded.abuse_score, ip_info.abuse_score),
                 last_checked=excluded.last_checked""",
            (ip, country, country_code, city, isp, hostname, lat, lon,
             abuse_score, _now()),
        )


# ----------------------------------------------------------------------
# Alertas
# ----------------------------------------------------------------------
def insert_alert(rule: str, severity: str, remote_ip: str = "",
                 process_name: str = "", description: str = "",
                 advice: str = "", direction: str = ""):
    with _write_lock, _connect() as conn:
        conn.execute(
            """INSERT INTO alerts
               (timestamp, rule, severity, remote_ip, process_name,
                description, advice, direction)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (_now(), rule, severity, remote_ip, process_name,
             description, advice, direction),
        )


def get_alerts(only_pending: bool = False, limit: int = 300) -> list[dict]:
    where = "WHERE resuelta = 0" if only_pending else ""
    order = "ORDER BY (severity='Alta') DESC, id DESC"
    with _connect() as conn:
        cur = conn.execute(
            f"SELECT * FROM alerts {where} {order} LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]


def resolve_alert(alert_id: int):
    with _write_lock, _connect() as conn:
        conn.execute("UPDATE alerts SET resuelta = 1 WHERE id = ?", (alert_id,))


def count_pending_alerts() -> int:
    with _connect() as conn:
        cur = conn.execute("SELECT COUNT(*) FROM alerts WHERE resuelta = 0")
        return cur.fetchone()[0]


def resolve_alerts_for(ip: str, rule: str | None = None):
    """Marca como revisadas las alertas pendientes de una IP (opcionalmente
    solo las de una regla concreta). Se usa al marcar una IP de confianza."""
    with _write_lock, _connect() as conn:
        if rule and rule != "*":
            conn.execute(
                "UPDATE alerts SET resuelta = 1 WHERE remote_ip = ? AND rule = ?",
                (ip, rule),
            )
        else:
            conn.execute(
                "UPDATE alerts SET resuelta = 1 WHERE remote_ip = ?", (ip,)
            )


# ----------------------------------------------------------------------
# Lista de confianza (allowlist) de IPs
# ----------------------------------------------------------------------
_RULE_SEP = "||"


def add_trusted_ip(ip: str, note: str = "", rule: str = "*"):
    """
    Marca una IP como de confianza.
      - rule="*"      -> confiar en TODO lo de esa IP (silencia cualquier alerta).
      - rule="<regla>"-> confiar solo en esa regla; si la IP hace algo DISTINTO
                          (otra regla) seguira avisando.
    Si la IP ya existe, acumula la nueva regla (salvo que ya sea '*').
    """
    with _write_lock, _connect() as conn:
        cur = conn.execute("SELECT rules FROM trusted_ips WHERE ip = ?", (ip,))
        row = cur.fetchone()
        if row is None:
            rules = "*" if rule == "*" else rule
            conn.execute(
                "INSERT INTO trusted_ips (ip, note, rules, added_at) VALUES (?,?,?,?)",
                (ip, note, rules, _now()),
            )
        else:
            existing = row["rules"] or ""
            if existing == "*" or rule == "*":
                new_rules = "*"
            else:
                parts = set(filter(None, existing.split(_RULE_SEP)))
                parts.add(rule)
                new_rules = _RULE_SEP.join(sorted(parts))
            conn.execute(
                "UPDATE trusted_ips SET rules = ?, note = COALESCE(NULLIF(?,''), note) WHERE ip = ?",
                (new_rules, note, ip),
            )


def remove_trusted_ip(ip: str):
    with _write_lock, _connect() as conn:
        conn.execute("DELETE FROM trusted_ips WHERE ip = ?", (ip,))


def get_trusted_ips() -> list[dict]:
    with _connect() as conn:
        cur = conn.execute("SELECT * FROM trusted_ips ORDER BY added_at DESC")
        return [dict(r) for r in cur.fetchall()]


def get_trusted_map() -> dict:
    """Devuelve {ip: rules} para consultas rapidas."""
    with _connect() as conn:
        cur = conn.execute("SELECT ip, rules FROM trusted_ips")
        return {r["ip"]: (r["rules"] or "*") for r in cur.fetchall()}


def is_ip_trusted(ip: str, rule: str) -> bool:
    """¿Está silenciada esta (IP, regla)?"""
    if not ip:
        return False
    with _connect() as conn:
        cur = conn.execute("SELECT rules FROM trusted_ips WHERE ip = ?", (ip,))
        row = cur.fetchone()
        if not row:
            return False
        rules = row["rules"] or "*"
        if rules == "*":
            return True
        return rule in set(rules.split(_RULE_SEP))


# ----------------------------------------------------------------------
# Trafico (usado por packet_capture opcional)
# ----------------------------------------------------------------------
def insert_traffic(window_start, window_end, local_ip, remote_ip,
                   remote_port, bytes_sent, bytes_received):
    with _write_lock, _connect() as conn:
        conn.execute(
            """INSERT INTO traffic_stats
               (window_start, window_end, local_ip, remote_ip, remote_port,
                bytes_sent, bytes_received)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (window_start, window_end, local_ip, remote_ip, remote_port,
             bytes_sent, bytes_received),
        )
