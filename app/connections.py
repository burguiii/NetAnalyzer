"""
Lectura de conexiones de red activas del PC usando psutil.

Corre en un hilo aparte con un loop de muestreo. Cada ciclo:
  1. Lee todas las conexiones inet.
  2. Las mapea a su proceso (nombre + ruta del ejecutable).
  3. Persiste en la BD solo las conexiones NUEVAS (para no duplicar).
  4. Alimenta al modulo de deteccion.
"""

import socket
import threading
import time

import psutil

from . import config, db, detection, enrichment, explain

# Estado compartido: ultima foto de conexiones activas (para la API en vivo)
_latest_snapshot: list[dict] = []
_snapshot_lock = threading.Lock()

# Recordamos que conexiones ya vimos para insertar solo las nuevas
_seen_keys: set = set()

_STATUS_LABELS = {
    "ESTABLISHED": "Establecida",
    "LISTEN": "Escuchando",
    "SYN_SENT": "Conectando",
    "SYN_RECV": "Conectando",
    "TIME_WAIT": "Cerrando",
    "CLOSE_WAIT": "Cerrando",
    "NONE": "-",
}


def _proto_name(conn) -> str:
    if conn.type == socket.SOCK_STREAM:
        return "TCP"
    if conn.type == socket.SOCK_DGRAM:
        return "UDP"
    return str(conn.type)


def _process_info(pid) -> tuple[str, str]:
    """Devuelve (nombre, ruta) del proceso, tolerando errores de permisos."""
    if not pid:
        return ("Sistema", "")
    try:
        p = psutil.Process(pid)
        try:
            path = p.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            path = ""
        return (p.name(), path)
    except psutil.NoSuchProcess:
        return ("(finalizado)", "")
    except psutil.AccessDenied:
        return ("(acceso denegado)", "")
    except Exception:
        return ("(desconocido)", "")


def read_active_connections() -> list[dict]:
    """Lee una foto de todas las conexiones activas ahora mismo."""
    rows = []
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        # Sin admin no se ven todos los procesos; devolvemos lo que haya
        return _latest_snapshot
    except Exception:
        return _latest_snapshot

    for c in conns:
        laddr = c.laddr
        raddr = c.raddr
        local_ip = laddr.ip if laddr else ""
        local_port = laddr.port if laddr else 0
        remote_ip = raddr.ip if raddr else ""
        remote_port = raddr.port if raddr else 0
        name, path = _process_info(c.pid)
        status = _STATUS_LABELS.get(c.status, c.status or "-")

        rows.append({
            "pid": c.pid or 0,
            "process_name": name,
            "process_path": path,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "protocol": _proto_name(c),
            "status": status,
            "raw_status": c.status or "",
        })
    return rows


def get_snapshot() -> list[dict]:
    """Foto actual enriquecida con geo/reputacion + explicacion humana."""
    with _snapshot_lock:
        snapshot = list(_latest_snapshot)
    ip_cache = db.get_all_ip_info()

    # Puertos en los que nuestro PC esta "escuchando" (para saber la direccion)
    listening_ports = {
        r["local_port"] for r in snapshot if r.get("raw_status") == "LISTEN"
    }
    trusted = db.get_trusted_map()   # {ip: rules}

    for row in snapshot:
        info = ip_cache.get(row["remote_ip"])
        if info:
            row["country"] = info.get("country") or ""
            row["country_code"] = (info.get("country_code") or "").lower()
            row["city"] = info.get("city") or ""
            row["isp"] = info.get("isp") or ""
            row["hostname"] = info.get("hostname") or ""
            row["lat"] = info.get("lat")
            row["lon"] = info.get("lon")
            row["abuse_score"] = info.get("abuse_score")
        else:
            row["country"] = ""
            row["country_code"] = ""
            row["city"] = ""
            row["isp"] = ""
            row["hostname"] = ""
            row["lat"] = None
            row["lon"] = None
            row["abuse_score"] = None

        # Traduccion a lenguaje humano (que es, quien, direccion, veredicto...)
        e = explain.describe(row, info, listening_ports)

        # Marcar si la IP es de confianza (allowlist)
        if row["remote_ip"] in trusted:
            e["trusted"] = True
            if trusted[row["remote_ip"]] == "*":
                # Confianza total: la pintamos verde salvo que sea peligrosa real
                if e["verdict"] not in ("bad",):
                    e["verdict"] = "ok"
        else:
            e["trusted"] = False
        row["explain"] = e
    return snapshot


def _poll_loop():
    """Loop principal de muestreo (corre en un hilo demonio)."""
    global _seen_keys
    while True:
        try:
            rows = read_active_connections()

            with _snapshot_lock:
                _latest_snapshot.clear()
                _latest_snapshot.extend(rows)

            # Detectar conexiones nuevas (clave = proceso+remoto+puerto)
            new_rows = []
            current_keys = set()
            for r in rows:
                if not r["remote_ip"]:
                    continue  # ignoramos sockets en escucha sin remoto
                key = (r["pid"], r["remote_ip"], r["remote_port"])
                current_keys.add(key)
                if key not in _seen_keys:
                    new_rows.append(r)

            _seen_keys = current_keys

            if new_rows:
                db.insert_connections(new_rows)
                # Enriquecer IPs nuevas (geo/reputacion) en segundo plano
                for r in new_rows:
                    enrichment.enqueue(r["remote_ip"])

            # Pasar la foto completa al detector de anomalias
            detection.analyze(rows)

        except Exception as e:
            print(f"[connections] error en el ciclo de muestreo: {e}")

        time.sleep(config.POLL_INTERVAL_SECONDS)


def start():
    """Arranca el hilo de muestreo."""
    t = threading.Thread(target=_poll_loop, name="conn-poller", daemon=True)
    t.start()
    print(f"[connections] muestreo cada {config.POLL_INTERVAL_SECONDS}s iniciado")
    return t
