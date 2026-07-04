"""
Enriquecimiento de IPs remotas: geolocalizacion + reputacion.

- Geolocalizacion: ip-api.com (gratis, sin API key para uso basico).
- Reputacion: AbuseIPDB (requiere API key gratuita en config.ABUSEIPDB_API_KEY).

Todo se cachea en la tabla ip_info para no re-consultar la misma IP.
Las consultas corren en un hilo trabajador con una cola, para no bloquear
el muestreo de conexiones. Las IPs privadas/locales se ignoran.
"""

import ipaddress
import queue
import socket
import threading
import time

import requests

from . import config, db

_pending: "queue.Queue[str]" = queue.Queue()
_inflight: set = set()
_inflight_lock = threading.Lock()


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.is_private or addr.is_loopback or
                addr.is_link_local or addr.is_multicast or addr.is_reserved)
    except ValueError:
        return True  # si no es una IP valida, la tratamos como no enriquecible


def enqueue(ip: str):
    """Pide enriquecer una IP (sin bloquear). Evita duplicados y privadas."""
    if not ip or _is_private(ip):
        return
    if db.get_ip_info(ip):
        return  # ya cacheada
    with _inflight_lock:
        if ip in _inflight:
            return
        _inflight.add(ip)
    _pending.put(ip)


def _geolocate(ip: str) -> dict:
    """Consulta ip-api.com. Devuelve dict vacio si falla."""
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,countryCode,city,isp",
            timeout=6,
        )
        data = r.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country", ""),
                "country_code": data.get("countryCode", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
            }
    except Exception:
        pass
    return {}


def _reverse_dns(ip: str) -> str:
    """Nombre de dominio de la IP (DNS inverso). '' si no resuelve."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _reputation(ip: str) -> int | None:
    """Consulta AbuseIPDB si hay API key. Devuelve score 0-100 o None."""
    if not config.ABUSEIPDB_API_KEY:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=6,
        )
        data = r.json()
        return data.get("data", {}).get("abuseConfidenceScore")
    except Exception:
        return None


def _worker():
    while True:
        ip = _pending.get()
        try:
            geo = _geolocate(ip)
            hostname = _reverse_dns(ip)
            score = _reputation(ip)
            db.upsert_ip_info(
                ip,
                country=geo.get("country", ""),
                country_code=geo.get("country_code", ""),
                city=geo.get("city", ""),
                isp=geo.get("isp", ""),
                hostname=hostname,
                abuse_score=score,
            )
            # ip-api gratis permite ~45 req/min -> pausa suave entre consultas
            time.sleep(1.5)
        except Exception as e:
            print(f"[enrichment] error enriqueciendo {ip}: {e}")
        finally:
            with _inflight_lock:
                _inflight.discard(ip)
            _pending.task_done()


def start():
    t = threading.Thread(target=_worker, name="ip-enricher", daemon=True)
    t.start()
    if config.ABUSEIPDB_API_KEY:
        print("[enrichment] geolocalizacion + reputacion (AbuseIPDB) activas")
    else:
        print("[enrichment] geolocalizacion activa (sin API key de reputacion)")
    return t
