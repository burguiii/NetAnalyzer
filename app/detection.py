"""
Reglas de deteccion de patrones sospechosos.

Funciona en modo SOLO ALERTA: nunca bloquea automaticamente. Cuando una
regla se dispara, guarda una alerta en la BD. El bloqueo es una accion
manual del usuario desde el dashboard.

Se le llama con analyze(conexiones) en cada ciclo de muestreo.
Mantiene estado en memoria para las reglas basadas en ventanas de tiempo.
"""

import ipaddress
import time
from collections import defaultdict, deque

from . import config, db, explain


def _is_loopback(ip: str) -> bool:
    """El trafico a 127.x / ::1 es ruido interno del sistema, no lo analizamos."""
    if not ip:
        return True
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return True

# --- Estado en memoria para reglas por ventana de tiempo ---
# Para escaneo entrante: por IP remota -> deque de (timestamp, puerto_local)
_incoming_ports = defaultdict(deque)
# Para picos de conexiones: por proceso -> deque de timestamps de conexiones nuevas
_conn_bursts = defaultdict(deque)
# Recordar conexiones ya vistas (para contar solo las nuevas en el pico)
_known_conns: set = set()
# En el primer ciclo, TODAS las conexiones existentes parecerian "nuevas".
# Con esta bandera sembramos el estado la primera vez sin generar alertas.
_first_run = True
# Evitar spam de la misma alerta: (regla, clave) -> ultimo timestamp emitido
_recent_alerts = {}
_ALERT_COOLDOWN = 60  # segundos entre alertas identicas


def _should_emit(rule: str, key: str) -> bool:
    now = time.time()
    k = (rule, key)
    last = _recent_alerts.get(k, 0)
    if now - last < _ALERT_COOLDOWN:
        return False
    _recent_alerts[k] = now
    return True


def _emit(rule, severity, remote_ip="", process="", desc="", direction=""):
    # Si el usuario marcó esta IP como de confianza PARA ESTA REGLA, no avisamos.
    # (Si la misma IP dispara OTRA regla distinta, sí avisará: eso es
    #  comportamiento nuevo no previsto.)
    if remote_ip and db.is_ip_trusted(remote_ip, rule):
        return
    key = remote_ip or process or rule
    if _should_emit(rule, key):
        advice = explain.alert_advice(rule, remote_ip, process)
        db.insert_alert(rule, severity, remote_ip, process, desc,
                        advice=advice, direction=direction)
        print(f"[ALERTA/{severity}] {rule} -> {desc}")


def _prune(dq: deque, window: float):
    now = time.time()
    while dq and now - dq[0][0] > window:
        dq.popleft()


def analyze(connections: list[dict]):
    global _first_run
    now = time.time()

    # Ignoramos el trafico loopback (127.x): es comunicacion interna del PC
    # consigo mismo (navegadores, herramientas de desarrollo, etc.) y generaria
    # falsos positivos constantes en las reglas de escaneo y picos.
    connections = [c for c in connections if not _is_loopback(c.get("remote_ip"))]

    # Primera pasada: registramos las conexiones ya existentes como "conocidas"
    # para no confundir el estado inicial del PC con actividad sospechosa.
    if _first_run:
        _first_run = False
        for c in connections:
            if c.get("remote_ip"):
                _known_conns.add((c.get("pid"), c["remote_ip"], c.get("remote_port")))
        return

    # ---- Regla: escaneo de puertos entrante ----
    # Conexiones entrantes (alguien se conecta a un puerto de escucha nuestro)
    # detectamos SYN_RECV / conexiones con remoto hacia muchos puertos locales.
    for c in connections:
        remote = c.get("remote_ip")
        if not remote:
            continue
        raw = c.get("raw_status", "")
        # Entrante = el puerto local es "servidor". Heuristica: SYN_RECV o
        # multiples puertos locales distintos tocados por la misma IP remota.
        if raw in ("SYN_RECV", "ESTABLISHED", "CLOSE_WAIT"):
            dq = _incoming_ports[remote]
            dq.append((now, c.get("local_port")))
            _prune(dq, config.PORT_SCAN_WINDOW_SECONDS)
            distinct_ports = {p for _, p in dq}
            if len(distinct_ports) >= config.PORT_SCAN_THRESHOLD:
                _emit(
                    "Escaneo de puertos entrante", "Alta", remote_ip=remote,
                    desc=(f"La IP {remote} toco {len(distinct_ports)} puertos "
                          f"distintos en {config.PORT_SCAN_WINDOW_SECONDS}s."),
                    direction="Entrante",
                )

    # ---- Regla: conexion a IP con mala reputacion ----
    for c in connections:
        remote = c.get("remote_ip")
        if not remote:
            continue
        info = db.get_ip_info(remote)
        if info and info.get("abuse_score") is not None:
            if info["abuse_score"] >= config.ABUSE_SCORE_THRESHOLD:
                _emit(
                    "Conexion a IP con mala reputacion", "Alta",
                    remote_ip=remote, process=c.get("process_name", ""),
                    desc=(f"{c.get('process_name')} conecto con {remote} "
                          f"(AbuseIPDB score {info['abuse_score']})."),
                    direction="Saliente",
                )

    # ---- Regla: puerto remoto inusual (malware conocido) ----
    for c in connections:
        rport = c.get("remote_port")
        remote = c.get("remote_ip")
        if remote and rport in config.SUSPICIOUS_PORTS:
            _emit(
                "Puerto remoto inusual", "Media", remote_ip=remote,
                process=c.get("process_name", ""),
                desc=(f"{c.get('process_name')} conecto a {remote}:{rport}, "
                      f"puerto asociado a malware conocido."),
                direction="Saliente",
            )

    # ---- Regla: proceso desde carpeta sospechosa con conexion saliente ----
    for c in connections:
        remote = c.get("remote_ip")
        path = (c.get("process_path") or "").lower()
        if remote and path and any(h in path for h in config.SUSPICIOUS_PATH_HINTS):
            _emit(
                "Proceso en ubicacion sospechosa", "Media", remote_ip=remote,
                process=c.get("process_name", ""),
                desc=(f"{c.get('process_name')} se ejecuta desde una carpeta "
                      f"temporal/descargas y abrio conexion a {remote}."),
                direction="Saliente",
            )

    # ---- Regla: muchas conexiones nuevas simultaneas (posible C2/botnet) ----
    current = set()
    for c in connections:
        remote = c.get("remote_ip")
        if not remote:
            continue
        key = (c.get("pid"), remote, c.get("remote_port"))
        current.add(key)
        if key not in _known_conns:
            dq = _conn_bursts[c.get("process_name", "?")]
            dq.append((now, key))
            _prune(dq, config.NEW_CONN_BURST_WINDOW_SECONDS)
            if len(dq) >= config.NEW_CONN_BURST_THRESHOLD:
                _emit(
                    "Pico de conexiones nuevas", "Media",
                    process=c.get("process_name", ""),
                    desc=(f"{c.get('process_name')} abrio {len(dq)} conexiones "
                          f"nuevas en {config.NEW_CONN_BURST_WINDOW_SECONDS}s."),
                    direction="Saliente",
                )
    _known_conns.clear()
    _known_conns.update(current)
