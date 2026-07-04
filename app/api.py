"""
API REST (Flask) que consume el dashboard, y servidor de los archivos estaticos.
"""

from flask import Flask, jsonify, request, send_from_directory

from . import config, connections, db, firewall

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
    return jsonify({"alerts": db.get_alerts(only_pending=only_pending)})


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
