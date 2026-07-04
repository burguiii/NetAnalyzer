"""
API REST (Flask) que consume el dashboard, y servidor de los archivos estaticos.
"""

import threading

import requests
from flask import Flask, jsonify, request, send_from_directory

from . import config, connections, db, explain, firewall

# Cache de la ubicacion de "casa" (tu IP publica) para el mapa
_home_cache = {"data": None, "lock": threading.Lock()}

app = Flask(
    __name__,
    static_folder=str(config.STATIC_DIR),
    static_url_path="",
)


# ----------------------------------------------------------------------
# Frontend
# ----------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(config.STATIC_DIR, "index.html")


# ----------------------------------------------------------------------
# API
# ----------------------------------------------------------------------
@app.route("/api/connections")
def api_connections():
    """Conexiones activas ahora mismo (enriquecidas con geo/reputacion)."""
    rows = connections.get_snapshot()
    # Solo las que tienen remoto son interesantes en la vista en vivo
    active = [r for r in rows if r.get("remote_ip")]
    return jsonify({
        "total": len(active),
        "connections": active,
        "pending_alerts": db.count_pending_alerts(),
    })


@app.route("/api/alerts")
def api_alerts():
    only_pending = request.args.get("resuelta", "").lower() == "false"
    alerts = db.get_alerts(only_pending=only_pending)
    # Enriquecer con "quién es" para que el usuario sepa de dónde viene
    for a in alerts:
        ip = a.get("remote_ip")
        info = db.get_ip_info(ip) if ip else None
        if info:
            a["who"] = explain.who_is(info.get("hostname", ""), info.get("isp", ""),
                                      info.get("country", ""), info.get("city", ""))
            a["country_code"] = (info.get("country_code") or "").lower()
        else:
            a["who"] = ""
            a["country_code"] = ""
    return jsonify({"alerts": alerts})


@app.route("/api/trust", methods=["POST"])
def api_trust():
    body = request.json or {}
    ip = body.get("ip", "")
    rule = body.get("rule", "*") or "*"   # "*" = confiar en todo
    note = body.get("note", "")
    if not ip:
        return jsonify({"ok": False, "message": "Falta la IP."}), 400
    db.add_trusted_ip(ip, note=note, rule=rule)
    db.resolve_alerts_for(ip, rule)       # apaga las alertas ya existentes
    scope = "todo el tráfico" if rule == "*" else f"«{rule}»"
    return jsonify({"ok": True, "message": f"IP {ip} marcada de confianza para {scope}."})


@app.route("/api/untrust", methods=["POST"])
def api_untrust():
    ip = (request.json or {}).get("ip", "")
    db.remove_trusted_ip(ip)
    return jsonify({"ok": True, "message": f"IP {ip} ya no es de confianza."})


@app.route("/api/trusted")
def api_trusted():
    rows = db.get_trusted_ips()
    # Enriquecer cada IP de confianza con lo que sabemos de ella
    for t in rows:
        info = db.get_ip_info(t["ip"])
        if info:
            t["who"] = explain.who_is(info.get("hostname", ""), info.get("isp", ""),
                                      info.get("country", ""), info.get("city", ""))
            t["country_code"] = (info.get("country_code") or "").lower()
            t["country"] = info.get("country", "")
            t["city"] = info.get("city", "")
            t["hostname"] = info.get("hostname", "")
            t["isp"] = info.get("isp", "")
            t["abuse_score"] = info.get("abuse_score")
        else:
            t["who"] = ""
            t["country_code"] = ""
            t["country"] = ""
            t["city"] = ""
            t["hostname"] = ""
            t["isp"] = ""
            t["abuse_score"] = None
    return jsonify({"trusted": rows})


@app.route("/api/alerts/<int:alert_id>/resolver", methods=["POST"])
def api_resolve(alert_id):
    db.resolve_alert(alert_id)
    return jsonify({"ok": True})


@app.route("/api/history")
def api_history():
    rows = db.search_history(
        ip=request.args.get("ip", ""),
        process=request.args.get("proceso", ""),
        desde=request.args.get("desde", ""),
        hasta=request.args.get("hasta", ""),
    )
    return jsonify({"total": len(rows), "connections": rows})


@app.route("/api/block", methods=["POST"])
def api_block():
    ip = (request.json or {}).get("ip", "")
    ok, msg = firewall.block_ip(ip)
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    ip = (request.json or {}).get("ip", "")
    ok, msg = firewall.unblock_ip(ip)
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@app.route("/api/blocked")
def api_blocked():
    return jsonify({"blocked": firewall.list_blocked()})


@app.route("/api/home")
def api_home():
    """Ubicacion aproximada de tu PC (por tu IP publica) para centrar el mapa."""
    with _home_cache["lock"]:
        if _home_cache["data"] is not None:
            return jsonify(_home_cache["data"])
    data = {"lat": 40.4, "lon": -3.7, "city": "", "country": "Tu ubicación"}
    try:
        r = requests.get(
            "http://ip-api.com/json/?fields=status,country,city,lat,lon",
            timeout=6,
        )
        j = r.json()
        if j.get("status") == "success":
            data = {"lat": j.get("lat"), "lon": j.get("lon"),
                    "city": j.get("city", ""), "country": j.get("country", "")}
    except Exception:
        pass
    with _home_cache["lock"]:
        _home_cache["data"] = data
    return jsonify(data)


@app.route("/api/status")
def api_status():
    """Info general para la cabecera del dashboard."""
    return jsonify({
        "packet_capture": config.ENABLE_PACKET_CAPTURE,
        "reputation_enabled": bool(config.ABUSEIPDB_API_KEY),
        "poll_interval": config.POLL_INTERVAL_SECONDS,
        "pending_alerts": db.count_pending_alerts(),
    })


def run():
    app.run(
        host="127.0.0.1",
        port=config.DASHBOARD_PORT,
        debug=False,
        use_reloader=False,
        threaded=True,
    )
