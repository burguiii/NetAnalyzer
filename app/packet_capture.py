"""
Captura de paquetes (OPCIONAL) con scapy — requiere Npcap instalado.

Deshabilitado por defecto (config.ENABLE_PACKET_CAPTURE = False). Cuando se
activa, cuenta bytes por (IP origen, IP destino, puerto) en ventanas de
tiempo y vuelca agregados a la tabla traffic_stats. NO guarda cada paquete.

Si scapy o Npcap no estan disponibles, se desactiva solo sin romper la app.
"""

import threading
import time
from collections import defaultdict
from datetime import datetime

from . import config, db

WINDOW_SECONDS = 10  # cada cuanto se vuelcan agregados a la BD


def _capture_loop():
    try:
        from scapy.all import sniff, IP, TCP, UDP
    except Exception as e:
        print(f"[packet_capture] scapy/Npcap no disponible, captura desactivada: {e}")
        return

    counters = defaultdict(lambda: {"sent": 0, "recv": 0})
    window_start = datetime.now()
    lock = threading.Lock()

    # Determinar IPs locales para saber que es "enviado" vs "recibido"
    import psutil
    local_ips = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family.name in ("AF_INET", "AF_INET6"):
                local_ips.add(a.address)

    def handle(pkt):
        if IP not in pkt:
            return
        src, dst = pkt[IP].src, pkt[IP].dst
        size = len(pkt)
        rport = 0
        if TCP in pkt:
            rport = pkt[TCP].dport
        elif UDP in pkt:
            rport = pkt[UDP].dport
        with lock:
            if src in local_ips:      # saliente
                counters[(src, dst, rport)]["sent"] += size
            elif dst in local_ips:    # entrante
                counters[(dst, src, rport)]["recv"] += size

    def flusher():
        nonlocal window_start
        while True:
            time.sleep(WINDOW_SECONDS)
            with lock:
                snapshot = dict(counters)
                counters.clear()
                ws, we = window_start, datetime.now()
                window_start = we
            for (local_ip, remote_ip, rport), v in snapshot.items():
                db.insert_traffic(
                    ws.strftime("%Y-%m-%d %H:%M:%S"),
                    we.strftime("%Y-%m-%d %H:%M:%S"),
                    local_ip, remote_ip, rport, v["sent"], v["recv"],
                )

    threading.Thread(target=flusher, name="traffic-flusher", daemon=True).start()
    print("[packet_capture] captura de paquetes iniciada (scapy)")
    # Filtro BPF: solo IP, excluye broadcast/multicast tipico
    sniff(prn=handle, store=False, filter="ip and not broadcast and not multicast")


def start():
    if not config.ENABLE_PACKET_CAPTURE:
        print("[packet_capture] desactivado (ENABLE_PACKET_CAPTURE = False)")
        return None
    t = threading.Thread(target=_capture_loop, name="packet-capture", daemon=True)
    t.start()
    return t
